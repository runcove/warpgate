use poem::http::{HeaderName, Method, StatusCode, header};
use poem::web::Data;
use poem::{Endpoint, FromRequest, IntoResponse, Middleware, Request, Response};
use tracing::warn;
use url::{Origin, Url};
use warpgate_common_http::auth::UnauthenticatedRequestContext;
use warpgate_common_http::{PlainHttpListener, is_cluster_peer_request};

use super::loopback_host::request_host;
use super::management_scope::is_login_flow_route;
use super::mfa_enforcement::warpgate_surface_path;
use crate::common::{is_cross_origin_request, is_warpgate_session_cookie_name};

static SEC_FETCH_SITE: HeaderName = HeaderName::from_static("sec-fetch-site");

/// What the origin check looks at in a request.
#[derive(Debug)]
pub(crate) struct OriginCheckRequest<'a> {
    pub method: Method,
    pub path: &'a str,
    pub websocket_upgrade: bool,
    pub cluster_peer: bool,
    pub origin: Option<&'a str>,
    pub sec_fetch_site: Option<&'a str>,
}

impl OriginCheckRequest<'_> {
    /// Whether the request needs an accepted origin at all: a state-changing
    /// method or a websocket upgrade, other than the IdP's form_post to the
    /// SSO return route (bound to the login by its OAuth `state`) and a
    /// cluster peer's forwarded request.
    pub fn is_checked(&self) -> bool {
        let safe = matches!(self.method, Method::GET | Method::HEAD | Method::OPTIONS);
        if self.cluster_peer || (safe && !self.websocket_upgrade) {
            return false;
        }
        let sso_form_post = self.method == Method::POST
            && warpgate_surface_path(self.path) == Some("/api/sso/return");
        !sso_form_post
    }

    /// Whether a checked request may proceed on a plain-HTTP loopback
    /// listener, where other local services share the browser's cookies:
    /// `Origin` must be exactly the listener's own origin (`own`: scheme, host
    /// and port). Without `Origin`, Fetch Metadata must say `same-origin` or
    /// `none` (typed by the user); `same-site`, `cross-site` or no header at
    /// all are refused.
    pub fn is_same_origin_on_loopback(&self, own: Option<&Origin>) -> bool {
        match self.origin {
            Some(origin) => {
                let Some(own) = own else {
                    return false;
                };
                Url::parse(origin)
                    .map(|url| url.origin())
                    .is_ok_and(|origin| origin.is_tuple() && &origin == own)
            }
            None => matches!(self.sec_fetch_site, Some("same-origin" | "none")),
        }
    }
}

/// The origin a plain-HTTP loopback listener serves this request on: `http`
/// and the raw `Host` header, which `LoopbackHostMiddleware` has already
/// held to a loopback name and the listening port.
fn loopback_own_origin(req: &Request) -> Option<Origin> {
    let host = request_host(req)?;
    Url::parse(&format!("http://{host}"))
        .ok()
        .map(|url| url.origin())
}

/// Whether any `Cookie` header names one of Warpgate's session cookies, read
/// as the session layer reads names (trimmed, percent-decoded). Leniently:
/// an empty, invalid or valueless session cookie still counts, and so does a
/// header that is not valid UTF-8.
fn carries_session_cookie(req: &Request) -> bool {
    req.headers().get_all(header::COOKIE).iter().any(|value| {
        String::from_utf8_lossy(value.as_bytes())
            .split(';')
            .any(|pair| {
                let name = pair.split_once('=').map_or(pair, |(name, _)| name);
                is_warpgate_session_cookie_name(name)
            })
    })
}

/// On a plain-HTTP loopback listener, whether a checked request may proceed:
/// one that carries no session cookie cannot act on the user's session (a
/// token client, a ticket link), so only requests with a session cookie are
/// held to [`OriginCheckRequest::is_same_origin_on_loopback`].
fn loopback_request_allowed(req: &Request, check: &OriginCheckRequest<'_>) -> bool {
    !carries_session_cookie(req)
        || check.is_same_origin_on_loopback(loopback_own_origin(req).as_ref())
}

/// Off loopback, whether a checked request may proceed: one to a login-flow
/// route must not come from another origin ([`is_cross_origin_request`]);
/// anything else is left to upstream, which ignores the session on it.
fn login_flow_request_allowed(
    req: &Request,
    check: &OriginCheckRequest<'_>,
    request_host: Option<&str>,
) -> bool {
    !is_login_flow_route(&check.method, check.path) || !is_cross_origin_request(req, request_host)
}

fn is_plain_http_loopback(req: &Request) -> bool {
    req.data::<PlainHttpListener>()
        .is_some_and(|listener| listener.0)
}

fn origin_check_request(req: &Request, cluster_peer: bool) -> OriginCheckRequest<'_> {
    OriginCheckRequest {
        method: req.method().clone(),
        path: req.original_uri().path(),
        websocket_upgrade: req
            .header(header::UPGRADE)
            .is_some_and(|value| value.eq_ignore_ascii_case("websocket")),
        cluster_peer,
        origin: req.header(header::ORIGIN),
        sec_fetch_site: req.header(&SEC_FETCH_SITE),
    }
}

/// Refuses with 403 a state-changing request (or websocket upgrade) to a
/// login-flow route that comes from another origin, by upstream's test
/// ([`is_cross_origin_request`]: the `Origin`, else `Referer`, host must be
/// the request's own, and `Sec-Fetch-Site` must not be `cross-site` or
/// `same-site`).
///
/// Upstream only ignores the session on such a request
/// (`inject_request_authorization`), which refuses every route that needs a
/// login; the login flow acts without one, so a page elsewhere could still
/// log the browser in or out. Requests without browser headers are not
/// affected.
///
/// On a plain-HTTP loopback listener the stricter
/// [`OriginCheckRequest::is_same_origin_on_loopback`] rule applies instead,
/// to every route, for requests that carry a Warpgate session cookie.
#[derive(Clone)]
pub struct OriginCheckMiddleware;

impl<E: Endpoint> Middleware<E> for OriginCheckMiddleware {
    type Output = OriginCheckEndpoint<E>;

    fn transform(&self, inner: E) -> Self::Output {
        OriginCheckEndpoint { inner }
    }
}

pub struct OriginCheckEndpoint<E: Endpoint> {
    inner: E,
}

impl<E: Endpoint> Endpoint for OriginCheckEndpoint<E> {
    type Output = Response;

    async fn call(&self, req: Request) -> poem::Result<Self::Output> {
        let check = origin_check_request(&req, is_cluster_peer_request(&req));
        if check.is_checked() {
            let loopback = is_plain_http_loopback(&req);
            let allowed = if loopback {
                loopback_request_allowed(&req, &check)
            } else {
                let ctx =
                    Data::<&UnauthenticatedRequestContext>::from_request_without_body(&req).await?;
                login_flow_request_allowed(&req, &check, ctx.trusted_hostname(&req).as_deref())
            };
            if !allowed {
                warn!(
                    method = %check.method,
                    path = check.path,
                    origin = ?check.origin,
                    sec_fetch_site = ?check.sec_fetch_site,
                    loopback,
                    "Refused a management request from another origin"
                );
                return Err(poem::Error::from_status(StatusCode::FORBIDDEN));
            }
        }
        Ok(self.inner.call(req).await?.into_response())
    }
}

/// On a plain-HTTP loopback listener, refuses with 403 a state-changing
/// request (or websocket upgrade) proxied to a target that carries a Warpgate
/// session cookie unless it comes from Warpgate's own origin, by the same
/// rule as Warpgate's own routes
/// ([`OriginCheckRequest::is_same_origin_on_loopback`]). Other listeners are
/// not affected.
#[derive(Clone)]
pub struct TargetOriginCheckMiddleware;

impl<E: Endpoint> Middleware<E> for TargetOriginCheckMiddleware {
    type Output = TargetOriginCheckEndpoint<E>;

    fn transform(&self, inner: E) -> Self::Output {
        TargetOriginCheckEndpoint { inner }
    }
}

pub struct TargetOriginCheckEndpoint<E: Endpoint> {
    inner: E,
}

impl<E: Endpoint> Endpoint for TargetOriginCheckEndpoint<E> {
    type Output = Response;

    async fn call(&self, req: Request) -> poem::Result<Self::Output> {
        if is_plain_http_loopback(&req) {
            let check = origin_check_request(&req, is_cluster_peer_request(&req));
            if check.is_checked() && !loopback_request_allowed(&req, &check) {
                warn!(
                    method = %check.method,
                    path = check.path,
                    origin = ?check.origin,
                    sec_fetch_site = ?check.sec_fetch_site,
                    "Refused a request to a target from another origin"
                );
                return Err(poem::Error::from_status(StatusCode::FORBIDDEN));
            }
        }
        Ok(self.inner.call(req).await?.into_response())
    }
}

#[cfg(test)]
mod tests {
    use poem::endpoint::make_sync;
    use poem::test::{TestClient, TestRequestBuilder};
    use poem::{EndpointExt, Route};

    use super::*;

    const MAIN: &str = "https://warpgate.example.test";
    const MAIN_HOST: &str = "warpgate.example.test";
    const TARGET: &str = "https://vm.warpgate.example.test:8443";
    const TARGET_HOST: &str = "vm.warpgate.example.test";
    const FOREIGN: &str = "https://elsewhere.example";

    const ADMIN_API: &str = "/@warpgate/admin/api/targets";
    const USER_API: &str = "/@warpgate/api/profile/api-tokens";
    const LOGIN: &str = "/@warpgate/api/auth/login";
    const LOGOUT: &str = "/@warpgate/api/auth/logout";
    const SSO_RETURN: &str = "/@warpgate/api/sso/return";

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    const fn post<'a>(path: &'a str, origin: Option<&'a str>) -> OriginCheckRequest<'a> {
        OriginCheckRequest {
            method: Method::POST,
            path,
            websocket_upgrade: false,
            cluster_peer: false,
            origin,
            sec_fetch_site: None,
        }
    }

    /// A request built as the server builds it (poem's `TestClient` leaves
    /// `original_uri` at `/`, and the check reads `original_uri`).
    fn request(method: Method, path: &str, headers: &[(&str, &str)]) -> Request {
        let mut builder = poem::http::Request::builder().method(method).uri(path);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let (parts, ()) = builder.body(()).unwrap().into_parts();
        Request::from_parts(
            poem::RequestParts::from((
                parts,
                poem::web::LocalAddr::default(),
                poem::web::RemoteAddr::default(),
                poem::http::uri::Scheme::HTTPS,
            )),
            poem::Body::empty(),
        )
    }

    /// Whether the check off loopback lets `req` to `host` through.
    fn allows(req: &Request, host: &str) -> bool {
        let check = origin_check_request(req, is_cluster_peer_request(req));
        !check.is_checked() || login_flow_request_allowed(req, &check, Some(host))
    }

    fn post_from(path: &str, origin: &str) -> Request {
        request(Method::POST, path, &[("origin", origin)])
    }

    #[test]
    fn login_flow_refuses_another_origin() {
        let cancel = |origin| {
            request(
                Method::DELETE,
                "/@warpgate/api/auth/state",
                &[("origin", origin)],
            )
        };
        for path in [
            LOGIN,
            "/@warpgate/api/auth/otp",
            LOGOUT,
            "/_warpgate/api/auth/login",
        ] {
            assert!(!allows(&post_from(path, FOREIGN), MAIN_HOST), "{path}");
            // A target's page under the main host is another origin too ...
            assert!(!allows(&post_from(path, TARGET), MAIN_HOST), "{path}");
            // ... and so is the main host's page, on a target's host.
            assert!(!allows(&post_from(path, MAIN), TARGET_HOST), "{path}");
        }
        assert!(!allows(&cancel(FOREIGN), MAIN_HOST));
    }

    #[test]
    fn login_flow_allows_its_own_origin() {
        for (origin, host) in [
            (MAIN, MAIN_HOST),
            ("https://warpgate.example.test:443", MAIN_HOST),
            (TARGET, TARGET_HOST),
            ("https://localhost:8888", "localhost"),
        ] {
            for path in [LOGIN, LOGOUT] {
                assert!(allows(&post_from(path, origin), host), "{origin} {path}");
            }
        }
    }

    #[test]
    fn login_flow_refuses_null_and_unparseable_origins() {
        for origin in ["null", "", "not a url", "data:text/plain,x"] {
            assert!(!allows(&post_from(LOGIN, origin), MAIN_HOST), "{origin:?}");
        }
    }

    #[test]
    fn login_flow_reads_referer_and_fetch_metadata_without_origin() {
        let referer = request(
            Method::POST,
            LOGIN,
            &[("referer", "https://elsewhere.example/page")],
        );
        assert!(!allows(&referer, MAIN_HOST));
        for site in ["cross-site", "same-site"] {
            let req = request(Method::POST, LOGIN, &[("sec-fetch-site", site)]);
            assert!(!allows(&req, MAIN_HOST), "{site}");
        }
        for site in ["same-origin", "none"] {
            let req = request(Method::POST, LOGIN, &[("sec-fetch-site", site)]);
            assert!(allows(&req, MAIN_HOST), "{site}");
        }
    }

    #[test]
    fn allows_request_without_browser_headers() {
        for path in [ADMIN_API, USER_API, LOGIN] {
            assert!(
                allows(&request(Method::POST, path, &[]), MAIN_HOST),
                "{path}"
            );
        }
    }

    /// Routes that need a login are left to upstream, which ignores the
    /// session on a cross-origin request to them.
    #[test]
    fn leaves_other_routes_to_upstream() {
        for path in [ADMIN_API, USER_API, "/@warpgate/api/auth/state/x/approve"] {
            assert!(allows(&post_from(path, FOREIGN), MAIN_HOST), "{path}");
        }
        let stream = request(
            Method::GET,
            "/@warpgate/api/web-ssh/sessions/x/stream",
            &[("upgrade", "websocket"), ("origin", FOREIGN)],
        );
        assert!(allows(&stream, MAIN_HOST));
    }

    #[test]
    fn ignores_safe_methods() {
        for method in [Method::GET, Method::HEAD, Method::OPTIONS] {
            let check = OriginCheckRequest {
                method: method.clone(),
                ..post(LOGIN, Some(FOREIGN))
            };
            assert!(!check.is_checked(), "{method}");
        }
        // A websocket upgrade is checked whatever its method.
        let upgrade = request(
            Method::GET,
            "/@warpgate/api/info",
            &[("upgrade", "websocket"), ("origin", FOREIGN)],
        );
        assert!(!allows(&upgrade, MAIN_HOST));
    }

    #[test]
    fn exempts_sso_return_post() {
        let idp = "https://idp.example";
        for path in [SSO_RETURN, "/_warpgate/api/sso/return"] {
            assert!(allows(&post_from(path, idp), MAIN_HOST), "{path}");
        }
        // Only that route.
        assert!(!allows(&post_from(LOGOUT, idp), MAIN_HOST));
    }

    #[test]
    fn exempts_cluster_peer() {
        let mut req = post_from(LOGIN, FOREIGN);
        req.extensions_mut()
            .insert(warpgate_common_http::ClusterPeer {
                node_id: warpgate_common::NodeId(uuid::Uuid::new_v4()),
            });
        assert!(allows(&req, MAIN_HOST));
    }

    /// The middleware, end to end, under the `/@warpgate` mount.
    #[tokio::test]
    async fn middleware_refuses_a_cross_origin_login() {
        let services = crate::test_db::services(crate::test_db::memory_db().await).await;
        let ctx = UnauthenticatedRequestContext::new(services).await;
        let app = Route::new()
            .nest(
                "/@warpgate",
                make_sync(|_| "served").with(OriginCheckMiddleware),
            )
            .data(ctx);

        for (path, origin, expected) in [
            (LOGIN, Some(MAIN), StatusCode::OK),
            (LOGIN, Some(FOREIGN), StatusCode::FORBIDDEN),
            (LOGIN, None, StatusCode::OK),
            (ADMIN_API, Some(FOREIGN), StatusCode::OK),
        ] {
            let mut headers = vec![("host", MAIN_HOST)];
            if let Some(origin) = origin {
                headers.push(("origin", origin));
            }
            let req = request(Method::POST, path, &headers);
            assert_eq!(
                app.get_response(req).await.status(),
                expected,
                "{path} {origin:?}"
            );
        }
    }

    // Loopback mode: Warpgate on http://127.0.0.1:8888 (port P), another local
    // service on port 9999 (port Q).
    const LOOPBACK_HOST: &str = "127.0.0.1:8888";
    const LOOPBACK_OWN: &str = "http://127.0.0.1:8888";
    const LOOPBACK_OTHER_PORT: &str = "http://127.0.0.1:9999";

    const SESSION_COOKIE: &str = "warpgate-loopback-session=abc";

    fn loopback_own() -> Origin {
        url(LOOPBACK_OWN).origin()
    }

    #[test]
    fn loopback_allows_only_its_own_origin() {
        let own = loopback_own();
        for origin in [
            LOOPBACK_OWN,
            "http://127.0.0.1:8888/",
            "HTTP://127.0.0.1:8888",
        ] {
            let check = post("/vms/new", Some(origin));
            assert!(check.is_same_origin_on_loopback(Some(&own)), "{origin}");
        }
        for origin in [
            LOOPBACK_OTHER_PORT,
            "http://localhost:8888",
            "https://127.0.0.1:8888",
            "http://127.0.0.1",
            "http://127.0.0.2:8888",
            "null",
            "",
            FOREIGN,
        ] {
            let check = post("/vms/new", Some(origin));
            assert!(!check.is_same_origin_on_loopback(Some(&own)), "{origin:?}");
        }
        // Without a known own origin, no Origin header can match.
        assert!(!post("/vms/new", Some(LOOPBACK_OWN)).is_same_origin_on_loopback(None));
    }

    #[test]
    fn loopback_without_origin_needs_same_origin_fetch_metadata() {
        let own = loopback_own();
        let without_origin = |site| OriginCheckRequest {
            sec_fetch_site: site,
            ..post("/vms/new", None)
        };
        for site in ["same-origin", "none"] {
            assert!(
                without_origin(Some(site)).is_same_origin_on_loopback(Some(&own)),
                "{site}"
            );
        }
        for site in [Some("same-site"), Some("cross-site"), Some("bogus"), None] {
            assert!(
                !without_origin(site).is_same_origin_on_loopback(Some(&own)),
                "{site:?}"
            );
        }
    }

    /// The headers the web UI behind Warpgate sends, as a browser does.
    #[derive(Clone, Copy)]
    enum Sender {
        /// From Warpgate's own origin, as the web UI sends it.
        OwnOrigin,
        /// From another local port.
        OtherPort,
        /// No `Origin`, `Sec-Fetch-Site: same-site`.
        SameSiteWithoutOrigin,
        /// Neither header.
        NoBrowserHeaders,
    }

    fn browser_headers<'a, E: Endpoint>(
        req: TestRequestBuilder<'a, E>,
        sender: Sender,
        fetch_mode: &str,
    ) -> TestRequestBuilder<'a, E> {
        let req = req
            .header("host", LOOPBACK_HOST)
            .header("cookie", SESSION_COOKIE);
        match sender {
            Sender::OwnOrigin => req
                .header("origin", LOOPBACK_OWN)
                .header("sec-fetch-site", "same-origin")
                .header("sec-fetch-mode", fetch_mode)
                .header("sec-fetch-dest", "empty"),
            Sender::OtherPort => req
                .header("origin", LOOPBACK_OTHER_PORT)
                .header("sec-fetch-site", "same-site")
                .header("sec-fetch-mode", fetch_mode)
                .header("sec-fetch-dest", "empty"),
            Sender::SameSiteWithoutOrigin => req
                .header("sec-fetch-site", "same-site")
                .header("sec-fetch-mode", fetch_mode)
                .header("sec-fetch-dest", "empty"),
            Sender::NoBrowserHeaders => req,
        }
    }

    fn htmx_headers<'a, E: Endpoint>(
        req: TestRequestBuilder<'a, E>,
        target: Option<&str>,
    ) -> TestRequestBuilder<'a, E> {
        let req = req
            .header("hx-request", "true")
            .header("hx-current-url", "http://127.0.0.1:8888/");
        match target {
            Some(target) => req.header("hx-target", target.to_owned()),
            None => req,
        }
    }

    /// The requests the web UI behind Warpgate makes through the proxied
    /// route, each sent as `sender` would; returns their statuses.
    async fn web_ui_requests<E: Endpoint>(cli: &TestClient<E>, sender: Sender) -> Vec<StatusCode> {
        let form = "name=somevm&image=ubuntu";
        let create = htmx_headers(
            browser_headers(cli.post("/vms/new"), sender, "cors"),
            Some("modal-container"),
        )
        .header("content-type", "application/x-www-form-urlencoded")
        .body(form);
        let pause = htmx_headers(
            browser_headers(cli.post("/vms/somevm/pause"), sender, "cors"),
            None,
        );
        let start = browser_headers(cli.post("/vms/somevm/start"), sender, "cors");
        let terminal = browser_headers(cli.get("/terminal/somevm/ws"), sender, "websocket")
            .header("upgrade", "websocket")
            .header("connection", "Upgrade");
        let delete = htmx_headers(
            browser_headers(cli.delete("/vms/somevm"), sender, "cors"),
            Some("modal-container"),
        )
        .header("content-type", "application/x-www-form-urlencoded")
        .body(form);

        let mut statuses = Vec::new();
        statuses.push(create.send().await.0.status());
        statuses.push(pause.send().await.0.status());
        statuses.push(start.send().await.0.status());
        statuses.push(terminal.send().await.0.status());
        statuses.push(delete.send().await.0.status());
        statuses
    }

    fn proxied_route(loopback: bool) -> impl Endpoint {
        Route::new()
            .nest_no_strip(
                "/",
                make_sync(|_| "proxied").with(TargetOriginCheckMiddleware),
            )
            .data(PlainHttpListener(loopback))
    }

    #[tokio::test]
    async fn loopback_target_route_serves_the_web_ui_from_its_own_origin() {
        let cli = TestClient::new(proxied_route(true));
        assert_eq!(
            web_ui_requests(&cli, Sender::OwnOrigin).await,
            [StatusCode::OK; 5]
        );
        // Reading is not checked, from anywhere.
        let read = browser_headers(cli.get("/vms"), Sender::OtherPort, "cors");
        read.send().await.assert_status_is_ok();
    }

    #[tokio::test]
    async fn loopback_target_route_refuses_the_web_ui_requests_from_elsewhere() {
        let cli = TestClient::new(proxied_route(true));
        for sender in [
            Sender::OtherPort,
            Sender::SameSiteWithoutOrigin,
            Sender::NoBrowserHeaders,
        ] {
            assert_eq!(
                web_ui_requests(&cli, sender).await,
                [StatusCode::FORBIDDEN; 5]
            );
        }
    }

    #[tokio::test]
    async fn target_route_is_unchecked_off_loopback() {
        let cli = TestClient::new(proxied_route(false));
        for sender in [
            Sender::OwnOrigin,
            Sender::OtherPort,
            Sender::NoBrowserHeaders,
        ] {
            assert_eq!(web_ui_requests(&cli, sender).await, [StatusCode::OK; 5]);
        }
    }

    #[test]
    fn session_cookie_is_recognised_by_its_decoded_name() {
        let carries = |cookies: &[&str]| {
            let mut req = Request::builder();
            for cookie in cookies {
                req = req.header("cookie", *cookie);
            }
            carries_session_cookie(&req.finish())
        };
        for cookies in [
            &["warpgate-loopback-session=abc"][..],
            &["warpgate-http-session=abc"],
            &["other=1; warpgate-loopback-session=abc"],
            &["other=1", "warpgate-loopback-session=abc"],
            &["warpgate-loopback-session="],
            &["warpgate-loopback-session"],
            &[" warpgate-loopback-session =not a valid value"],
            &["warpgate%2Dloopback%2Dsession=abc"],
        ] {
            assert!(carries(cookies), "{cookies:?}");
        }
        for cookies in [
            &[][..],
            &["other=1"],
            &["other=warpgate-loopback-session"],
            &["warpgate-loopback-session-x=1"],
        ] {
            assert!(!carries(cookies), "{cookies:?}");
        }
    }

    /// A target request without a session cookie cannot act on the user's
    /// session, so it passes with any headers; with one, it is refused.
    #[tokio::test]
    async fn loopback_target_route_checks_only_requests_with_a_session_cookie() {
        let cli = TestClient::new(proxied_route(true));
        for origin in [None, Some(LOOPBACK_OTHER_PORT)] {
            let mut req = cli.post("/vms/somevm/start").header("host", LOOPBACK_HOST);
            if let Some(origin) = origin {
                req = req.header("origin", origin);
            }
            req.send().await.assert_status_is_ok();
        }
        let req = cli
            .post("/vms/somevm/start")
            .header("host", LOOPBACK_HOST)
            .header("cookie", "warpgate-loopback-session=");
        req.send().await.assert_status(StatusCode::FORBIDDEN);
    }

    /// Warpgate's own admin API on a loopback listener.
    #[tokio::test]
    async fn loopback_admin_api_allows_only_its_own_origin() {
        let services = crate::test_db::services(crate::test_db::memory_db().await).await;
        {
            let mut config = services.config.lock().await;
            config.store.http.plain_http_on_loopback = true;
        }
        let ctx = UnauthenticatedRequestContext::new(services).await;
        let app = Route::new()
            .nest(
                "/@warpgate",
                make_sync(|_| "served").with(OriginCheckMiddleware),
            )
            .data(ctx)
            .data(PlainHttpListener(true));
        let cli = TestClient::new(app);

        for (sender, expected) in [
            (Sender::OwnOrigin, StatusCode::OK),
            (Sender::OtherPort, StatusCode::FORBIDDEN),
            (Sender::SameSiteWithoutOrigin, StatusCode::FORBIDDEN),
            (Sender::NoBrowserHeaders, StatusCode::FORBIDDEN),
        ] {
            let req = browser_headers(cli.post(ADMIN_API), sender, "cors");
            assert_eq!(req.send().await.0.status(), expected);
        }
        let req = browser_headers(cli.get(ADMIN_API), Sender::OtherPort, "cors");
        req.send().await.assert_status_is_ok();

        // A token client sends no cookie and no browser headers: allowed.
        let token = cli
            .post(ADMIN_API)
            .header("host", LOOPBACK_HOST)
            .header("x-warpgate-token", "token-value");
        token.send().await.assert_status_is_ok();
        // The same request with the session cookie: refused.
        let with_cookie = cli
            .post(ADMIN_API)
            .header("host", LOOPBACK_HOST)
            .header("x-warpgate-token", "token-value")
            .header("cookie", SESSION_COOKIE);
        with_cookie
            .send()
            .await
            .assert_status(StatusCode::FORBIDDEN);
    }
}
