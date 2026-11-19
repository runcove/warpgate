use poem::http::{HeaderName, Method, StatusCode, header};
use poem::web::Data;
use poem::{Endpoint, FromRequest, IntoResponse, Middleware, Request, Response};
use tracing::warn;
use url::{Origin, Url};
use warpgate_common_http::auth::UnauthenticatedRequestContext;
use warpgate_common_http::{PlainHttpListener, is_cluster_peer_request};

use super::loopback_host::request_host;
use super::management_scope::is_origin_checked_route;
use super::mfa_enforcement::warpgate_surface_path;
use crate::common::{accepted_origins, is_cross_origin_request, is_warpgate_cookie_name};

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

/// Whether any `Cookie` header names one of Warpgate's cookies, by
/// [`is_warpgate_cookie_name`] (decoded, trimmed, case-insensitive). Leniently:
/// an empty, invalid or valueless session cookie still counts, and so does a
/// header that is not valid UTF-8.
fn carries_session_cookie(req: &Request) -> bool {
    req.headers().get_all(header::COOKIE).iter().any(|value| {
        String::from_utf8_lossy(value.as_bytes())
            .split(';')
            .any(|pair| {
                let name = pair.split_once('=').map_or(pair, |(name, _)| name);
                is_warpgate_cookie_name(name)
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
    accepted: &[Origin],
) -> bool {
    !is_origin_checked_route(&check.method, check.path)
        || !is_cross_origin_request(req, request_host, accepted)
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
/// `same-site`) with our stricter addition: its full origin - scheme, host and
/// port - must be Warpgate's own ([`accepted_origins`]).
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
                let accepted = accepted_origins(&req, &*ctx.services().config.lock().await).await;
                login_flow_request_allowed(
                    &req,
                    &check,
                    ctx.trusted_hostname(&req).as_deref(),
                    &accepted,
                )
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

/// Refuses with 403 a state-changing request (or websocket upgrade) proxied
/// to a target that carries a Warpgate session cookie unless it comes from
/// the origin it is sent to, by the loopback rule
/// ([`OriginCheckRequest::is_same_origin_on_loopback`]): `Origin` must be
/// that origin, else Fetch Metadata must say `same-origin` or `none`; with
/// neither header it is refused. On a plain-HTTP loopback listener that
/// origin is the listener's own; elsewhere it is the target's own (the
/// trusted scheme and host), so a page on one target's host cannot act as
/// the user on another's. A request without a session cookie acts as no one
/// and is left alone.
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
        let check = origin_check_request(&req, is_cluster_peer_request(&req));
        if check.is_checked() && carries_session_cookie(&req) {
            let own = if is_plain_http_loopback(&req) {
                loopback_own_origin(&req)
            } else {
                target_own_origin(&req)
            };
            if !check.is_same_origin_on_loopback(own.as_ref()) {
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

/// Off loopback, the origin a target is served on for this request: the
/// trusted scheme and the trusted Host (or X-Forwarded-Host), port included.
/// A page on another target's host is another origin.
fn target_own_origin(req: &Request) -> Option<Origin> {
    let ctx = req.data::<UnauthenticatedRequestContext>()?;
    let host = ctx.trusted_host_header(req)?;
    Url::parse(&format!("{}://{host}", ctx.trusted_proto(req)))
        .ok()
        .map(|url| url.origin())
        .filter(Origin::is_tuple)
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

    /// Whether the check off loopback lets `req` through to Warpgate reached
    /// at `own` (its full origin, from which the request host is taken).
    fn allows(req: &Request, own: &str) -> bool {
        let own = url(own);
        let check = origin_check_request(req, is_cluster_peer_request(req));
        !check.is_checked()
            || login_flow_request_allowed(req, &check, own.host_str(), &[own.origin()])
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
            "/@warpgate/api/sso/logout",
            "/_warpgate/api/sso/logout",
        ] {
            assert!(!allows(&post_from(path, FOREIGN), MAIN), "{path}");
            // A target's page under the main host is another origin too ...
            assert!(!allows(&post_from(path, TARGET), MAIN), "{path}");
            // ... and so is the main host's page, on a target's host.
            assert!(!allows(&post_from(path, MAIN), TARGET), "{path}");
        }
        assert!(!allows(&cancel(FOREIGN), MAIN));
    }

    #[test]
    fn login_flow_allows_its_own_origin() {
        for (origin, host) in [
            (MAIN, MAIN),
            ("https://warpgate.example.test:443", MAIN),
            (TARGET, TARGET),
            ("https://localhost:8888", "https://localhost:8888"),
        ] {
            for path in [LOGIN, LOGOUT] {
                assert!(allows(&post_from(path, origin), host), "{origin} {path}");
            }
        }
    }

    /// Ours, stricter than upstream's host-only test: the same host with
    /// another scheme or port is another origin.
    #[test]
    fn login_flow_compares_the_full_origin() {
        for origin in [
            "http://warpgate.example.test",
            "https://warpgate.example.test:8443",
            "http://warpgate.example.test:443",
        ] {
            assert!(!allows(&post_from(LOGIN, origin), MAIN), "{origin}");
        }
        assert!(allows(&post_from(LOGIN, MAIN), MAIN));
        // The same holds for a Referer standing in for the Origin.
        let referer = |r| request(Method::POST, LOGIN, &[("referer", r)]);
        assert!(!allows(
            &referer("https://warpgate.example.test:9999/x"),
            MAIN
        ));
        assert!(allows(
            &referer("https://warpgate.example.test/@warpgate"),
            MAIN
        ));
        // And on a target's host with its own port.
        assert!(!allows(
            &post_from(LOGIN, "https://vm.warpgate.example.test"),
            TARGET
        ));
        assert!(allows(&post_from(LOGIN, TARGET), TARGET));
    }

    #[test]
    fn login_flow_refuses_null_and_unparseable_origins() {
        for origin in ["null", "", "not a url", "data:text/plain,x"] {
            assert!(!allows(&post_from(LOGIN, origin), MAIN), "{origin:?}");
        }
    }

    #[test]
    fn login_flow_reads_referer_and_fetch_metadata_without_origin() {
        let referer = request(
            Method::POST,
            LOGIN,
            &[("referer", "https://elsewhere.example/page")],
        );
        assert!(!allows(&referer, MAIN));
        for site in ["cross-site", "same-site"] {
            let req = request(Method::POST, LOGIN, &[("sec-fetch-site", site)]);
            assert!(!allows(&req, MAIN), "{site}");
        }
        for site in ["same-origin", "none"] {
            let req = request(Method::POST, LOGIN, &[("sec-fetch-site", site)]);
            assert!(allows(&req, MAIN), "{site}");
        }
    }

    #[test]
    fn allows_request_without_browser_headers() {
        for path in [ADMIN_API, USER_API, LOGIN] {
            assert!(allows(&request(Method::POST, path, &[]), MAIN), "{path}");
        }
    }

    /// Routes that need a login are left to upstream, which ignores the
    /// session on a cross-origin request to them.
    #[test]
    fn leaves_other_routes_to_upstream() {
        for path in [ADMIN_API, USER_API, "/@warpgate/api/auth/state/x/approve"] {
            assert!(allows(&post_from(path, FOREIGN), MAIN), "{path}");
        }
        let stream = request(
            Method::GET,
            "/@warpgate/api/web-ssh/sessions/x/stream",
            &[("upgrade", "websocket"), ("origin", FOREIGN)],
        );
        assert!(allows(&stream, MAIN));
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
        assert!(!allows(&upgrade, MAIN));
    }

    #[test]
    fn exempts_sso_return_post() {
        let idp = "https://idp.example";
        for path in [SSO_RETURN, "/_warpgate/api/sso/return"] {
            assert!(allows(&post_from(path, idp), MAIN), "{path}");
        }
        // Only that route.
        assert!(!allows(&post_from(LOGOUT, idp), MAIN));
    }

    #[test]
    fn exempts_cluster_peer() {
        let mut req = post_from(LOGIN, FOREIGN);
        req.extensions_mut()
            .insert(warpgate_common_http::ClusterPeer {
                node_id: warpgate_common::NodeId(uuid::Uuid::new_v4()),
            });
        assert!(allows(&req, MAIN));
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
            // Same host, another scheme or port: another origin.
            (
                LOGIN,
                Some("http://warpgate.example.test"),
                StatusCode::FORBIDDEN,
            ),
            (
                LOGIN,
                Some("https://warpgate.example.test:8443"),
                StatusCode::FORBIDDEN,
            ),
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
    fn loopback_refuses_a_deeply_nested_blob_origin() {
        // `Url::origin` recursed through nested `blob:` URLs and overflowed
        // the stack before url 2.5.9 (RUSTSEC-2026-0592).
        let nested = format!("{}{LOOPBACK_OWN}", "blob:".repeat(100_000));
        let own = loopback_own();
        let check = post("/vms/new", Some(&nested));
        assert!(!check.is_same_origin_on_loopback(Some(&own)));
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

    /// Off loopback, a state-changing request carrying a session cookie must
    /// come from the target's own origin (trusted scheme and host, port
    /// included): a page on a sibling target's host is refused, and so is a
    /// request with neither `Origin` nor `Sec-Fetch-Site`. Without a session
    /// cookie, or for a read, anything passes.
    #[tokio::test]
    async fn target_route_off_loopback_allows_only_the_targets_own_origin() {
        let services = crate::test_db::services(crate::test_db::memory_db().await).await;
        let app = Route::new()
            .nest_no_strip(
                "/",
                make_sync(|_| "proxied").with(TargetOriginCheckMiddleware),
            )
            .data(UnauthenticatedRequestContext::new(services).await)
            .data(PlainHttpListener(false));
        let cli = TestClient::new(app);
        const HOST: &str = "vm.warpgate.example.test:8443";
        const COOKIE: &str = "__Host-warpgate-http-session=abc";
        let post = |origin: Option<&str>, site: Option<&str>, cookie: bool| {
            let mut req = cli.post("/vms/somevm/start").header("host", HOST);
            if cookie {
                req = req.header("cookie", COOKIE);
            }
            if let Some(origin) = origin {
                req = req.header("origin", origin.to_owned());
            }
            if let Some(site) = site {
                req = req.header("sec-fetch-site", site.to_owned());
            }
            req
        };
        for (origin, site, cookie, expected) in [
            (Some(TARGET), Some("same-origin"), true, StatusCode::OK),
            (None, Some("same-origin"), true, StatusCode::OK),
            (None, Some("none"), true, StatusCode::OK),
            (
                Some("https://vm2.warpgate.example.test:8443"),
                Some("same-site"),
                true,
                StatusCode::FORBIDDEN,
            ),
            (Some(MAIN), Some("same-site"), true, StatusCode::FORBIDDEN),
            (
                Some("http://vm.warpgate.example.test:8443"),
                None,
                true,
                StatusCode::FORBIDDEN,
            ),
            (
                Some(FOREIGN),
                Some("cross-site"),
                true,
                StatusCode::FORBIDDEN,
            ),
            (None, Some("same-site"), true, StatusCode::FORBIDDEN),
            (None, None, true, StatusCode::FORBIDDEN),
            (Some(FOREIGN), Some("cross-site"), false, StatusCode::OK),
            (None, None, false, StatusCode::OK),
        ] {
            assert_eq!(
                post(origin, site, cookie).send().await.0.status(),
                expected,
                "{origin:?} {site:?} {cookie}"
            );
        }
        // A read is not checked, from anywhere.
        cli.get("/vms")
            .header("host", HOST)
            .header("cookie", COOKIE)
            .header("origin", FOREIGN)
            .send()
            .await
            .assert_status_is_ok();
    }

    /// Two targets on hosts of their own under one parent domain, and a
    /// browser signed in on both. Its requests to the first host carry that
    /// host's session cookie whatever page sends them (the hosts are
    /// same-site), under the browser's cookie name and through the cookie
    /// gate, as served. A page on the second host changes nothing on the
    /// first: not through the target, by any method or a websocket, and not
    /// by signing that host's session out.
    #[tokio::test]
    async fn a_page_on_one_target_host_cannot_act_on_another() {
        use crate::middleware::CookieGateMiddleware;

        const HOST: &str = "vm.warpgate.example.test:8443";
        const SIBLING: &str = "https://vm2.warpgate.example.test:8443";
        const COOKIE: &str = "__Host-warpgate-http-session=abc; theme=dark";

        let services = crate::test_db::services(crate::test_db::memory_db().await).await;
        // What reached the route: whether the session cookie came through
        // the gate, under the name it has inside.
        let seen = |req: Request| {
            let session = req
                .headers()
                .get_all(header::COOKIE)
                .iter()
                .any(|value| value.as_bytes().starts_with(b"warpgate-http-session=abc"));
            if session { "session" } else { "no session" }
        };
        let app = Route::new()
            .nest("/@warpgate", make_sync(seen).with(OriginCheckMiddleware))
            .nest_no_strip("/", make_sync(seen).with(TargetOriginCheckMiddleware))
            .with(CookieGateMiddleware::new(false, None))
            .data(PlainHttpListener(false))
            .data(UnauthenticatedRequestContext::new(services).await);

        let send = async |method: Method, path: &str, from: Option<&str>, signed_in: bool| {
            let websocket = method == Method::GET;
            let mut headers = vec![("host", HOST)];
            if signed_in {
                headers.push(("cookie", COOKIE));
            }
            if let Some(from) = from {
                let site = if from == TARGET {
                    "same-origin"
                } else {
                    "same-site"
                };
                headers.push(("origin", from));
                headers.push(("sec-fetch-site", site));
            }
            if websocket {
                headers.push(("upgrade", "websocket"));
                headers.push(("connection", "Upgrade"));
            }
            let response = app.get_response(request(method, path, &headers)).await;
            let status = response.status();
            let body = response.into_body().into_string().await.unwrap();
            (status, body)
        };

        // GET here is a websocket upgrade.
        let methods = [
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::GET,
        ];
        for method in methods {
            let path = "/vms/somevm/start";
            // The target's own page acts, as the session.
            let (status, body) = send(method.clone(), path, Some(TARGET), true).await;
            assert_eq!(
                (status, body.as_str()),
                (StatusCode::OK, "session"),
                "{method}"
            );
            // The other target's page does not, with or without `Origin`.
            for from in [Some(SIBLING), Some(MAIN)] {
                let (status, _) = send(method.clone(), path, from, true).await;
                assert_eq!(status, StatusCode::FORBIDDEN, "{method} {from:?}");
            }
            let headers = [
                ("host", HOST),
                ("cookie", COOKIE),
                ("sec-fetch-site", "same-site"),
                ("upgrade", "websocket"),
            ];
            let headers = if method == Method::GET {
                &headers[..]
            } else {
                &headers[..3]
            };
            let response = app
                .get_response(request(method.clone(), path, headers))
                .await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{method}");
            // Without the session it acts as no one, so it is not this
            // check's to refuse.
            let (status, body) = send(method.clone(), path, Some(SIBLING), false).await;
            assert_eq!(
                (status, body.as_str()),
                (StatusCode::OK, "no session"),
                "{method}"
            );
        }

        // Signing this host's session out is its own page's to do.
        let (status, _) = send(Method::POST, LOGOUT, Some(TARGET), true).await;
        assert_eq!(status, StatusCode::OK);
        for signed_in in [true, false] {
            let (status, _) = send(Method::POST, LOGOUT, Some(SIBLING), signed_in).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "signed in: {signed_in}");
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
            &["Warpgate-Loopback-Session=abc"],
            &["__Host-warpgate-http-session=abc"],
            &["%5F%5Fhost-warpgate-handoff=abc"],
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
