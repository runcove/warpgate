use poem::http::{HeaderName, Method, StatusCode, header};
use poem::web::Data;
use poem::{Endpoint, FromRequest, IntoResponse, Middleware, Request, Response};
use tracing::warn;
use url::{Origin, Url};
use warpgate_common_http::auth::UnauthenticatedRequestContext;
use warpgate_common_http::ext::construct_external_url;
use warpgate_common_http::{PlainHttpListener, is_cluster_peer_request};

use super::loopback_host::request_host;
use super::management_scope::is_login_flow_route;
use super::mfa_enforcement::warpgate_surface_path;
use crate::common::{is_localhost_host, is_warpgate_session_cookie_name};

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

/// The origins a state-changing request may come from.
#[derive(Debug)]
pub(crate) struct AcceptedOrigins {
    /// The main host's, from `external_host`. Without one configured, the
    /// request's own origin stands in for it, as it does for every external
    /// URL Warpgate builds.
    main: Option<Origin>,
    /// The request's own, accepted for login-flow routes on any host.
    own: Option<Origin>,
    /// Whether the request's own origin is accepted for every route: on
    /// localhost, which may carry the main host's session too.
    own_for_all_routes: bool,
}

impl AcceptedOrigins {
    pub fn new(main: Option<&Url>, own: Option<&Url>, own_hostname: Option<&str>) -> Self {
        let own = own.map(Url::origin);
        Self {
            main: main.map(Url::origin).or_else(|| own.clone()),
            own,
            own_for_all_routes: own_hostname.is_some_and(is_localhost_host),
        }
    }
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

    /// Whether a checked request may proceed. Without `Origin` it is a
    /// non-browser client unless Fetch Metadata says the browser sent it from
    /// another site. With `Origin` it must be the main host's, or the
    /// request's own on a login-flow route; `null` and anything unparseable
    /// are refused.
    pub fn is_allowed(&self, accepted: &AcceptedOrigins) -> bool {
        let Some(origin) = self.origin else {
            return self.sec_fetch_site != Some("cross-site");
        };
        let Ok(origin) = Url::parse(origin).map(|url| url.origin()) else {
            return false;
        };
        if !origin.is_tuple() {
            return false;
        }
        if accepted.main.as_ref() == Some(&origin) {
            return true;
        }
        accepted.own.as_ref() == Some(&origin)
            && (accepted.own_for_all_routes || is_login_flow_route(&self.method, self.path))
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

async fn accepted_origins(req: &Request) -> poem::Result<AcceptedOrigins> {
    let ctx = Data::<&UnauthenticatedRequestContext>::from_request_without_body(req).await?;
    let config = ctx.services().config.lock().await;
    let main = construct_external_url(None, &config, None).await.ok();
    let own = construct_external_url(Some(req), &config, None).await.ok();
    Ok(AcceptedOrigins::new(
        main.as_ref(),
        own.as_ref(),
        ctx.trusted_hostname(req).as_deref(),
    ))
}

/// Refuses state-changing management requests (and websocket upgrades) whose
/// `Origin` is not the main host's, or the request's own on a login-flow
/// route, with 403. Requests without browser headers are not affected.
///
/// On a plain-HTTP loopback listener the stricter
/// [`OriginCheckRequest::is_same_origin_on_loopback`] rule applies instead,
/// to requests that carry a Warpgate session cookie.
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
                check.is_allowed(&accepted_origins(&req).await?)
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

    /// Origins accepted for a request to `own`, with the main host at
    /// [`MAIN`].
    fn accepted(own: &str) -> AcceptedOrigins {
        let own = url(own);
        AcceptedOrigins::new(Some(&url(MAIN)), Some(&own), own.host_str())
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

    fn allows(check: &OriginCheckRequest<'_>, accepted: &AcceptedOrigins) -> bool {
        !check.is_checked() || check.is_allowed(accepted)
    }

    #[test]
    fn allows_main_host_origin() {
        let on_main = accepted(MAIN);
        for path in [ADMIN_API, USER_API, LOGIN, "/_warpgate/admin/api/targets"] {
            assert!(allows(&post(path, Some(MAIN)), &on_main), "{path}");
        }
        // The default port spelled out.
        let explicit = "https://warpgate.example.test:443";
        assert!(allows(&post(ADMIN_API, Some(explicit)), &on_main));
        // The main host's page calling Warpgate under another name.
        assert!(allows(&post(ADMIN_API, Some(MAIN)), &accepted(TARGET)));
    }

    #[test]
    fn refuses_foreign_origin_on_admin_api() {
        let on_main = accepted(MAIN);
        for origin in [FOREIGN, "http://warpgate.example.test", TARGET] {
            let check = post(ADMIN_API, Some(origin));
            assert!(!allows(&check, &on_main), "{origin}");
        }
    }

    #[test]
    fn refuses_foreign_origin_on_user_api() {
        let on_main = accepted(MAIN);
        for origin in [FOREIGN, TARGET] {
            let check = post(USER_API, Some(origin));
            assert!(!allows(&check, &on_main), "{origin}");
        }
    }

    #[test]
    fn allows_own_origin_for_login_flow_on_target_host() {
        let on_target = accepted(TARGET);
        for path in [LOGIN, "/@warpgate/api/auth/otp", LOGOUT] {
            assert!(allows(&post(path, Some(TARGET)), &on_target), "{path}");
        }
        let cancel = OriginCheckRequest {
            method: Method::DELETE,
            path: "/@warpgate/api/auth/state",
            ..post(LOGIN, Some(TARGET))
        };
        assert!(allows(&cancel, &on_target));
        // Not another host's origin, even on a login route.
        assert!(!allows(&post(LOGIN, Some(FOREIGN)), &on_target));
    }

    #[test]
    fn refuses_own_origin_for_non_login_route_on_target_host() {
        let on_target = accepted(TARGET);
        for path in [ADMIN_API, USER_API, "/@warpgate/api/auth/state/x/approve"] {
            assert!(!allows(&post(path, Some(TARGET)), &on_target), "{path}");
        }
    }

    #[test]
    fn allows_own_origin_on_localhost() {
        let own = "https://localhost:8888";
        assert!(allows(&post(ADMIN_API, Some(own)), &accepted(own)));
        assert!(!allows(&post(ADMIN_API, Some(FOREIGN)), &accepted(own)));
    }

    #[test]
    fn falls_back_to_own_origin_without_external_host() {
        let own = url("https://node.example.test:8888");
        let accepted = AcceptedOrigins::new(None, Some(&own), own.host_str());
        let origin = "https://node.example.test:8888";
        assert!(allows(&post(ADMIN_API, Some(origin)), &accepted));
        assert!(!allows(&post(ADMIN_API, Some(FOREIGN)), &accepted));
    }

    #[test]
    fn allows_request_without_browser_headers() {
        for path in [ADMIN_API, USER_API, LOGIN] {
            assert!(allows(&post(path, None), &accepted(MAIN)), "{path}");
            assert!(allows(&post(path, None), &accepted(TARGET)), "{path}");
        }
        for site in ["same-origin", "same-site", "none"] {
            let check = OriginCheckRequest {
                sec_fetch_site: Some(site),
                ..post(ADMIN_API, None)
            };
            assert!(allows(&check, &accepted(MAIN)), "{site}");
        }
    }

    #[test]
    fn refuses_null_origin() {
        for origin in ["null", "", "not a url", "data:text/plain,x"] {
            let check = post(LOGIN, Some(origin));
            assert!(!allows(&check, &accepted(MAIN)), "{origin:?}");
        }
    }

    #[test]
    fn refuses_cross_site_fetch_metadata_without_origin() {
        let check = OriginCheckRequest {
            sec_fetch_site: Some("cross-site"),
            ..post(ADMIN_API, None)
        };
        assert!(!allows(&check, &accepted(MAIN)));
    }

    #[test]
    fn ignores_safe_methods() {
        for method in [Method::GET, Method::HEAD, Method::OPTIONS] {
            let check = OriginCheckRequest {
                method: method.clone(),
                ..post(ADMIN_API, Some(FOREIGN))
            };
            assert!(!check.is_checked(), "{method}");
        }
        for method in [Method::PUT, Method::PATCH, Method::DELETE] {
            let check = OriginCheckRequest {
                method: method.clone(),
                ..post(ADMIN_API, Some(FOREIGN))
            };
            assert!(!allows(&check, &accepted(MAIN)), "{method}");
        }
    }

    #[test]
    fn checks_websocket_upgrades() {
        let stream = "/@warpgate/api/web-ssh/sessions/x/stream";
        let upgrade = |origin| OriginCheckRequest {
            method: Method::GET,
            websocket_upgrade: true,
            ..post(stream, origin)
        };
        assert!(!allows(&upgrade(Some(FOREIGN)), &accepted(MAIN)));
        assert!(allows(&upgrade(Some(MAIN)), &accepted(MAIN)));
        assert!(allows(&upgrade(None), &accepted(MAIN)));
    }

    #[test]
    fn exempts_sso_return_post() {
        let idp = Some("https://idp.example");
        for path in [SSO_RETURN, "/_warpgate/api/sso/return"] {
            assert!(allows(&post(path, idp), &accepted(MAIN)), "{path}");
        }
        // Only that route and method.
        let logout = "/@warpgate/api/sso/logout";
        assert!(!allows(&post(logout, idp), &accepted(MAIN)));
        let delete = OriginCheckRequest {
            method: Method::DELETE,
            ..post(SSO_RETURN, idp)
        };
        assert!(!allows(&delete, &accepted(MAIN)));
    }

    #[test]
    fn exempts_cluster_peer() {
        let check = OriginCheckRequest {
            cluster_peer: true,
            ..post(ADMIN_API, Some(FOREIGN))
        };
        assert!(allows(&check, &accepted(MAIN)));
    }

    /// The middleware over a configured main host, end to end.
    #[tokio::test]
    async fn middleware_refuses_foreign_origin() {
        let services = crate::test_db::services(crate::test_db::memory_db().await).await;
        {
            let mut config = services.config.lock().await;
            config.store.external_host = Some("warpgate.example.test".into());
            config.store.http.external_port = Some(443);
        }
        let ctx = UnauthenticatedRequestContext::new(services).await;
        let app = Route::new()
            .nest(
                "/@warpgate",
                make_sync(|_| "served").with(OriginCheckMiddleware),
            )
            .data(ctx);
        let cli = TestClient::new(app);
        let host = "warpgate.example.test";

        for (origin, expected) in [
            (Some(MAIN), StatusCode::OK),
            (Some(FOREIGN), StatusCode::FORBIDDEN),
            (None, StatusCode::OK),
        ] {
            let mut req = cli.post(ADMIN_API).header("host", host);
            if let Some(origin) = origin {
                req = req.header("origin", origin);
            }
            assert_eq!(req.send().await.0.status(), expected, "{origin:?}");
        }
        let req = cli.get(ADMIN_API).header("host", host);
        req.header("origin", FOREIGN)
            .send()
            .await
            .assert_status_is_ok();
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
