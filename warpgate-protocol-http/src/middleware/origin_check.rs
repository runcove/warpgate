use poem::http::{HeaderName, Method, StatusCode, header};
use poem::web::Data;
use poem::{Endpoint, FromRequest, IntoResponse, Middleware, Request, Response};
use tracing::warn;
use url::{Origin, Url};
use warpgate_common_http::auth::UnauthenticatedRequestContext;
use warpgate_common_http::ext::construct_external_url;
use warpgate_common_http::is_cluster_peer_request;

use super::management_scope::is_login_flow_route;
use super::mfa_enforcement::warpgate_surface_path;
use crate::common::is_localhost_host;

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
        let ctx = Data::<&UnauthenticatedRequestContext>::from_request_without_body(&req).await?;
        let check = OriginCheckRequest {
            method: req.method().clone(),
            path: req.original_uri().path(),
            websocket_upgrade: req
                .header(header::UPGRADE)
                .is_some_and(|value| value.eq_ignore_ascii_case("websocket")),
            cluster_peer: is_cluster_peer_request(&req, &ctx.services().cluster.cluster_token),
            origin: req.header(header::ORIGIN),
            sec_fetch_site: req.header(&SEC_FETCH_SITE),
        };
        if check.is_checked() && !check.is_allowed(&accepted_origins(&req).await?) {
            warn!(
                method = %check.method,
                path = check.path,
                origin = ?check.origin,
                sec_fetch_site = ?check.sec_fetch_site,
                "Refused a management request from another origin"
            );
            return Err(poem::Error::from_status(StatusCode::FORBIDDEN));
        }
        Ok(self.inner.call(req).await?.into_response())
    }
}

#[cfg(test)]
mod tests {
    use poem::endpoint::make_sync;
    use poem::test::TestClient;
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
        req.header("origin", FOREIGN).send().await.assert_status_is_ok();
    }
}
