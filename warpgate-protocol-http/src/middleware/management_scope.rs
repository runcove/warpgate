use poem::error::NotFoundError;
use poem::http::{Method, StatusCode};
use poem::web::Data;
use poem::{Endpoint, FromRequest, IntoResponse, Middleware, Request, Response};
use tracing::warn;
use warpgate_common::WarpgateError;
use warpgate_common_http::auth::UnauthenticatedRequestContext;
use warpgate_common_http::is_cluster_peer_request;

use super::mfa_enforcement::warpgate_surface_path;
use crate::catchall::{bound_to_host, get_target_by_request_host};

/// Whether `method` and `path` are part of signing in or out: the routes
/// under `/@warpgate` and `/_warpgate` on which a host bound to an HTTP target
/// still honours a session or token ([`credentials_refused_on_bound_host`]). That covers the gateway shell and its assets (the login page
/// is a route inside the shell), the login steps, the browser's own login
/// state, SSO start, return and logout, `info` for the login page and the
/// embedded session bar, and the custom logo the login page shows. Everything
/// else, including the admin API, the rest of the user API and forced MFA
/// enrolment, is only usable on other hosts.
///
/// Paths are matched exactly; a dot or empty segment, or an escape in an
/// asset path, is never part of the login flow.
pub(crate) fn is_login_flow_route(method: &Method, path: &str) -> bool {
    let Some(path) = warpgate_surface_path(path) else {
        return false;
    };
    if path.is_empty() || path == "/" {
        return method == Method::GET;
    }
    if path
        .split('/')
        .skip(1)
        .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return false;
    }
    if path.starts_with("/assets/") {
        return method == Method::GET && !path.contains('%');
    }
    if let Some(name) = path
        .strip_prefix("/api/sso/providers/")
        .and_then(|rest| rest.strip_suffix("/start"))
    {
        return method == Method::GET && !name.contains('/');
    }
    match path {
        "/api/info"
        | "/api/logo"
        | "/api/sso/providers"
        | "/api/sso/auto-start"
        | "/api/sso/logout" => method == Method::GET,
        "/api/auth/login" | "/api/auth/otp" | "/api/auth/logout" => method == Method::POST,
        // The browser's own login only; `/api/auth/state/:id` and its
        // approve and reject routes act on someone else's.
        "/api/auth/state" => method == Method::GET || method == Method::DELETE,
        // GET for the query response mode, POST for form_post.
        "/api/sso/return" => method == Method::GET || method == Method::POST,
        _ => false,
    }
}

/// Whether the request's host is bound to an HTTP target, resolved as the
/// catchall resolves it: the trusted Host (or X-Forwarded-Host), port
/// included, looked up with `get_target_by_request_host` and compared with
/// [`bound_to_host`].
async fn target_binding(
    ctx: &UnauthenticatedRequestContext,
    req: &Request,
) -> Result<bool, WarpgateError> {
    let Some(host) = ctx.trusted_host_header(req) else {
        return Ok(false);
    };
    let target = get_target_by_request_host(&ctx.services().config_provider, &host).await?;
    Ok(target.is_some_and(|target| bound_to_host(&target, &host)))
}

/// Whether a route of Warpgate's own on this request's host is out of scope:
/// the host is bound to an HTTP target and the route is not part of the login
/// flow ([`is_login_flow_route`]). A cluster peer's forwarded request was
/// scoped on the node the client reached.
async fn out_of_scope(
    ctx: &UnauthenticatedRequestContext,
    req: &Request,
) -> Result<bool, WarpgateError> {
    let path = req.original_uri().path();
    if is_cluster_peer_request(req)
        || warpgate_surface_path(path).is_none()
        || is_login_flow_route(req.method(), path)
    {
        return Ok(false);
    }
    target_binding(ctx, req).await
}

/// Whether the session or token a request to Warpgate's own routes carries
/// must not count, because its host is bound to an HTTP target and the route
/// is not part of the login flow ([`is_login_flow_route`]).
///
/// This is upstream's session restriction on hosts other than the control
/// plane (`inject_request_authorization`), extended: a bound host serves the
/// target's own pages, which share its origin, so there it applies with or
/// without `external_host`, and to API tokens as well as the session. A
/// cluster peer's forwarded request was scoped on the node the client
/// reached.
pub async fn credentials_refused_on_bound_host(
    ctx: &UnauthenticatedRequestContext,
    req: &Request,
) -> bool {
    out_of_scope(ctx, req).await.unwrap_or_else(|error| {
        // Decides whether credentials count, so it must not fail open.
        warn!(%error, "Could not resolve the request host to a target; treating it as bound");
        true
    })
}

/// Hides Warpgate's own management surface on hosts bound to an HTTP target:
/// every route under `/@warpgate` and `/_warpgate` that is not part of the
/// login flow ([`is_login_flow_route`]) answers 404 there, whatever the
/// request's credentials, as if it were not mounted. If the host cannot be
/// resolved, those routes answer 503 rather than being served.
///
/// Stricter than upstream, which on such a host (when it is not the control
/// plane) only ignores the session and still serves the routes, 401 where a
/// login is needed: here the per-VM host shows none of the admin or user API,
/// not even that it exists.
#[derive(Clone)]
pub struct ManagementScopeMiddleware;

impl<E: Endpoint> Middleware<E> for ManagementScopeMiddleware {
    type Output = ManagementScopeEndpoint<E>;

    fn transform(&self, inner: E) -> Self::Output {
        ManagementScopeEndpoint { inner }
    }
}

pub struct ManagementScopeEndpoint<E: Endpoint> {
    inner: E,
}

impl<E: Endpoint> Endpoint for ManagementScopeEndpoint<E> {
    type Output = Response;

    async fn call(&self, req: Request) -> poem::Result<Self::Output> {
        let ctx = Data::<&UnauthenticatedRequestContext>::from_request_without_body(&req).await?;
        match out_of_scope(&ctx, &req).await {
            Ok(false) => {}
            Ok(true) => return Err(NotFoundError.into()),
            Err(error) => {
                warn!(%error, "Could not resolve the request host to a target; refusing a management route");
                return Err(poem::Error::from_status(StatusCode::SERVICE_UNAVAILABLE));
            }
        }
        Ok(self.inner.call(req).await?.into_response())
    }
}

#[cfg(test)]
mod tests {
    use poem::endpoint::make_sync;
    use poem::{EndpointExt, Route};
    use sea_orm::ActiveValue::Set;
    use sea_orm::{ConnectionTrait, DatabaseConnection, EntityTrait};
    use uuid::Uuid;
    use warpgate_common::NodeId;
    use warpgate_common_http::ClusterPeer;
    use warpgate_db_entities::Target;

    use super::*;
    use crate::catchall::served_on_host;

    const TARGET_HOST: &str = "vm.example.test:8443";
    const MAIN_HOST: &str = "warpgate.example.test";
    const OTHER_HOST: &str = "node.example.test:8888";

    #[test]
    fn login_flow_route_allowlist() {
        for prefix in ["/@warpgate", "/_warpgate"] {
            for (method, path, allowed) in [
                // Shell and assets
                (Method::GET, "", true),
                (Method::GET, "/", true),
                (Method::GET, "/assets/index-abc123.js", true),
                (Method::POST, "/assets/index-abc123.js", false),
                // Login flow
                (Method::GET, "/api/info", true),
                // The custom logo on the login page
                (Method::GET, "/api/logo", true),
                (Method::POST, "/api/auth/login", true),
                (Method::POST, "/api/auth/otp", true),
                (Method::POST, "/api/auth/logout", true),
                (Method::GET, "/api/auth/state", true),
                (Method::DELETE, "/api/auth/state", true),
                (Method::GET, "/api/sso/providers", true),
                (Method::GET, "/api/sso/providers/corp-idp/start", true),
                (Method::GET, "/api/sso/auto-start", true),
                (Method::GET, "/api/sso/return", true),
                (Method::POST, "/api/sso/return", true),
                (Method::GET, "/api/sso/logout", true),
                // Wrong methods on login routes
                (Method::POST, "/api/info", false),
                (Method::POST, "/api/logo", false),
                (Method::DELETE, "/api/logo", false),
                (Method::GET, "/api/auth/login", false),
                (Method::PUT, "/api/auth/state", false),
                (Method::POST, "/api/sso/providers/corp-idp/start", false),
                // Forced MFA enrolment is served on the main host only
                (Method::POST, "/api/profile/credentials/otp", false),
                // The rest of the user API
                (Method::POST, "/api/dismiss-tutorial", false),
                (Method::GET, "/api/auth/web-auth-requests", false),
                (Method::GET, "/api/auth/web-auth-requests/stream", false),
                (Method::GET, "/api/sso/kubernetes-configs", false),
                (Method::GET, "/api/targets", false),
                (Method::GET, "/api/profile/credentials", false),
                (Method::POST, "/api/profile/credentials/password", false),
                (Method::POST, "/api/profile/credentials/public-keys", false),
                (Method::DELETE, "/api/profile/credentials/otp/x", false),
                (Method::POST, "/api/profile/credentials/certificates", false),
                (Method::GET, "/api/profile/api-tokens", false),
                (Method::POST, "/api/profile/api-tokens", false),
                (Method::GET, "/api/ticket-request-targets", false),
                (Method::POST, "/api/ticket-requests", false),
                (Method::POST, "/api/ticket-requests/x/activate", false),
                (Method::GET, "/api/my-tickets", false),
                (Method::POST, "/api/web-ssh/sessions", false),
                (Method::GET, "/api/web-ssh/sessions/x/stream", false),
                (Method::POST, "/api/web-desktop/sessions", false),
                (Method::GET, "/api/web-desktop/sessions/x/stream", false),
                (Method::GET, "/api/playground", false),
                (Method::GET, "/api/openapi.json", false),
                // Admin shell and API
                (Method::GET, "/admin", false),
                (Method::GET, "/admin/api/users", false),
                (Method::POST, "/admin/api/targets", false),
                (Method::GET, "/admin/api/playground", false),
                // Path shapes that are never the login flow
                (Method::GET, "/api/info/", false),
                (Method::GET, "/api/logo/", false),
                (Method::GET, "/api//info", false),
                (Method::GET, "/assets/../admin/api/users", false),
                (Method::GET, "/assets/./index.js", false),
                (Method::GET, "/assets/%2e%2e/admin/api/users", false),
                (Method::GET, "/api/sso/providers//start", false),
                (Method::GET, "/api/sso/providers/a/b/start", false),
            ] {
                let path = format!("{prefix}{path}");
                assert_eq!(
                    is_login_flow_route(&method, &path),
                    allowed,
                    "{method} {path}"
                );
            }
        }
        // Proxied target paths are not management routes at all.
        assert!(!is_login_flow_route(&Method::GET, "/api/info"));
    }

    #[test]
    fn auth_state_by_id_is_not_login_flow() {
        let state = "/@warpgate/api/auth/state/123e4567-e89b-12d3-a456-426614174000";
        for (method, suffix) in [
            (Method::GET, ""),
            (Method::POST, "/approve"),
            (Method::POST, "/reject"),
        ] {
            let path = format!("{state}{suffix}");
            assert!(!is_login_flow_route(&method, &path), "{method} {path}");
        }
    }

    async fn bind_target(db: &DatabaseConnection, external_host: &str) {
        let id = Uuid::new_v4();
        Target::Entity::insert(Target::ActiveModel {
            id: Set(id),
            name: Set(format!("target-{id}")),
            description: Set(String::new()),
            kind: Set(Target::TargetKind::Http),
            options: Set(serde_json::json!({
                "http": { "url": "http://127.0.0.1:1", "external_host": external_host }
            })),
            rate_limit_bytes_per_second: Set(None),
            group_id: Set(None),
            ticket_max_duration_seconds: Set(None),
            ticket_requests_disabled: Set(false),
            ticket_require_approval: Set(false),
            ticket_max_uses: Set(None),
            require_approval: Set(false),
        })
        .exec(db)
        .await
        .unwrap();
    }

    /// A request context over a database with one HTTP target bound to
    /// [`TARGET_HOST`].
    async fn context(
        trust_x_forwarded: bool,
    ) -> (UnauthenticatedRequestContext, DatabaseConnection) {
        let db = crate::test_db::memory_db().await;
        bind_target(&db, TARGET_HOST).await;
        let services = crate::test_db::services(db.clone()).await;
        services
            .config
            .lock()
            .await
            .store
            .http
            .trust_x_forwarded_headers = trust_x_forwarded;
        (UnauthenticatedRequestContext::new(services).await, db)
    }

    const ADMIN_API: [(Method, &str); 3] = [
        (Method::GET, "/@warpgate/admin/api/users"),
        (Method::POST, "/@warpgate/admin/api/targets"),
        (Method::GET, "/@warpgate/admin"),
    ];

    const USER_API: [(Method, &str); 6] = [
        (Method::GET, "/@warpgate/api/targets"),
        (Method::POST, "/@warpgate/api/profile/api-tokens"),
        (Method::POST, "/@warpgate/api/profile/credentials/otp"),
        (Method::POST, "/@warpgate/api/ticket-requests"),
        (Method::GET, "/@warpgate/api/web-ssh/sessions/x/stream"),
        (Method::POST, "/@warpgate/api/auth/state/x/approve"),
    ];

    const LOGIN_FLOW: [(Method, &str); 8] = [
        (Method::GET, "/@warpgate"),
        (Method::GET, "/@warpgate/assets/index.js"),
        (Method::GET, "/@warpgate/api/info"),
        (Method::POST, "/@warpgate/api/auth/login"),
        (Method::POST, "/@warpgate/api/auth/logout"),
        (Method::GET, "/@warpgate/api/sso/providers/corp-idp/start"),
        (Method::GET, "/@warpgate/api/sso/auto-start"),
        (Method::POST, "/@warpgate/api/sso/return"),
    ];

    /// Builds a request as the server does (poem's `TestClient` leaves
    /// `original_uri` at `/` whatever the URI, and the rule reads
    /// `original_uri`) and asks whether its credentials are refused.
    async fn refused(
        ctx: &UnauthenticatedRequestContext,
        method: &Method,
        path: &str,
        headers: &[(&str, &str)],
    ) -> bool {
        let req = scoped_request(method, path, headers);
        credentials_refused_on_bound_host(ctx, &req).await
    }

    /// A request built as the server builds it (poem's `TestClient` leaves
    /// `original_uri` at `/` whatever the URI, and the scope reads
    /// `original_uri`).
    fn scoped_request(method: &Method, path: &str, headers: &[(&str, &str)]) -> Request {
        let mut builder = poem::http::Request::builder()
            .method(method.clone())
            .uri(path);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let (parts, ()) = builder.body(()).unwrap().into_parts();
        let req = Request::from_parts(
            poem::RequestParts::from((
                parts,
                poem::web::LocalAddr::default(),
                poem::web::RemoteAddr::default(),
                poem::http::uri::Scheme::HTTP,
            )),
            poem::Body::empty(),
        );
        // Positive control: the path under test is the one the rule reads.
        assert_eq!(req.original_uri().path(), path);
        req
    }

    #[tokio::test]
    async fn target_host_refuses_credentials_on_admin_and_user_api() {
        let (ctx, _db) = context(false).await;
        for (method, path) in ADMIN_API.into_iter().chain(USER_API) {
            assert!(
                refused(&ctx, &method, path, &[("host", TARGET_HOST)]).await,
                "{method} {path}"
            );
        }
    }

    #[tokio::test]
    async fn target_host_accepts_credentials_on_login_flow() {
        let (ctx, _db) = context(false).await;
        for (method, path) in LOGIN_FLOW {
            assert!(
                !refused(&ctx, &method, path, &[("host", TARGET_HOST)]).await,
                "{method} {path}"
            );
        }
    }

    #[tokio::test]
    async fn other_hosts_accept_credentials_on_every_route() {
        let (ctx, _db) = context(false).await;
        for host in [MAIN_HOST, OTHER_HOST, "localhost:8888", "127.0.0.1"] {
            for (method, path) in ADMIN_API.into_iter().chain(USER_API).chain(LOGIN_FLOW) {
                assert!(
                    !refused(&ctx, &method, path, &[("host", host)]).await,
                    "{method} {path} on {host}"
                );
            }
        }
    }

    #[tokio::test]
    async fn proxied_paths_are_not_warpgate_routes() {
        let (ctx, _db) = context(false).await;
        assert!(!refused(&ctx, &Method::POST, "/api/users", &[("host", TARGET_HOST)]).await);
    }

    /// A cluster peer, identified by the acceptor's mTLS check (the
    /// `ClusterPeer` extension), forwards a request the node the client
    /// reached has already scoped; a plain request on the same host is scoped.
    #[tokio::test]
    async fn cluster_peer_is_not_scoped() {
        let (ctx, _db) = context(false).await;
        let request = |from_peer: bool| {
            // Built as the server builds it: the scope reads `original_uri`.
            let mut req = scoped_request(
                &Method::GET,
                "/@warpgate/admin/api/users",
                &[("host", TARGET_HOST)],
            );
            if from_peer {
                req.extensions_mut().insert(ClusterPeer {
                    node_id: NodeId(Uuid::new_v4()),
                });
            }
            req
        };
        assert!(!credentials_refused_on_bound_host(&ctx, &request(true)).await);
        assert!(credentials_refused_on_bound_host(&ctx, &request(false)).await);
    }

    #[tokio::test]
    async fn target_lookup_error_fails_closed() {
        let (ctx, db) = context(false).await;
        db.execute_unprepared("DROP TABLE targets").await.unwrap();
        let admin = "/@warpgate/admin/api/users";
        let login = "/@warpgate/api/auth/login";
        for host in [TARGET_HOST, MAIN_HOST] {
            assert!(
                refused(&ctx, &Method::GET, admin, &[("host", host)]).await,
                "{host}"
            );
            // The login flow does not depend on the lookup.
            assert!(
                !refused(&ctx, &Method::POST, login, &[("host", host)]).await,
                "{host}"
            );
        }
    }

    #[tokio::test]
    async fn binding_matches_catchall_host_resolution() {
        let admin = "/@warpgate/admin/api/users";
        let forwarded_to_target = [("host", MAIN_HOST), ("x-forwarded-host", TARGET_HOST)];
        let forwarded_to_main = [("host", TARGET_HOST), ("x-forwarded-host", MAIN_HOST)];

        // The port is part of the binding, as in the catchall.
        let (ctx, _db) = context(false).await;
        for (host, expected) in [
            ("vm.example.test", false),
            ("vm.example.test:9443", false),
            (TARGET_HOST, true),
        ] {
            assert_eq!(
                refused(&ctx, &Method::GET, admin, &[("host", host)]).await,
                expected,
                "{host}"
            );
        }
        // X-Forwarded-Host is ignored unless it is trusted ...
        assert!(!refused(&ctx, &Method::GET, admin, &forwarded_to_target).await);

        // ... and takes precedence over Host when it is.
        let (ctx, _db) = context(true).await;
        assert!(refused(&ctx, &Method::GET, admin, &forwarded_to_target).await);
        assert!(!refused(&ctx, &Method::GET, admin, &forwarded_to_main).await);
    }

    #[tokio::test]
    async fn binding_agrees_with_served_on_host() {
        // A host is bound exactly where the catchall serves the bound target.
        let (ctx, _db) = context(false).await;
        let admin = "/@warpgate/admin/api/users";
        for host in [
            TARGET_HOST,
            "vm.example.test",
            "vm.example.test:9443",
            "VM.example.test:8443",
            "vm.example.test:8443.",
        ] {
            assert_eq!(
                refused(&ctx, &Method::GET, admin, &[("host", host)]).await,
                served_on_host(Some(TARGET_HOST), Some(host)),
                "{host}"
            );
        }
    }

    #[tokio::test]
    async fn underscore_prefix_is_scoped_too() {
        let (ctx, _db) = context(false).await;
        for (method, path, expected) in [
            (Method::GET, "/_warpgate/admin/api/users", true),
            (Method::GET, "/_warpgate/api/targets", true),
            (Method::GET, "/_warpgate/api/info", false),
            (Method::POST, "/_warpgate/api/auth/login", false),
        ] {
            assert_eq!(
                refused(&ctx, &method, path, &[("host", TARGET_HOST)]).await,
                expected,
                "{method} {path}"
            );
        }
    }

    /// The middleware over both mounts: out-of-scope routes are 404 on the
    /// bound host whatever the credentials, the login flow is served, other
    /// hosts are untouched, and a failed lookup is 503.
    #[tokio::test]
    async fn middleware_hides_the_management_surface_on_a_bound_host() {
        let (ctx, db) = context(false).await;
        let mount = || make_sync(|_| "served").with(ManagementScopeMiddleware);
        let app = Route::new()
            .nest("/@warpgate", mount())
            .nest("/_warpgate", mount())
            .data(ctx);
        let status = |method: Method, path: &'static str, host: &'static str| {
            let req = scoped_request(&method, path, &[("host", host), ("x-warpgate-token", "t")]);
            let app = &app;
            async move { app.get_response(req).await.status() }
        };

        for (method, path) in ADMIN_API.into_iter().chain(USER_API) {
            assert_eq!(
                status(method.clone(), path, TARGET_HOST).await,
                StatusCode::NOT_FOUND,
                "{method} {path}"
            );
            assert_eq!(
                status(method.clone(), path, MAIN_HOST).await,
                StatusCode::OK,
                "{method} {path}"
            );
        }
        for (method, path) in LOGIN_FLOW {
            assert_eq!(
                status(method.clone(), path, TARGET_HOST).await,
                StatusCode::OK,
                "{method} {path}"
            );
        }
        // The custom logo is part of the login page.
        assert_eq!(
            status(Method::GET, "/@warpgate/api/logo", TARGET_HOST).await,
            StatusCode::OK
        );

        db.execute_unprepared("DROP TABLE targets").await.unwrap();
        assert_eq!(
            status(Method::GET, "/@warpgate/admin/api/users", TARGET_HOST).await,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            status(Method::POST, "/@warpgate/api/auth/login", TARGET_HOST).await,
            StatusCode::OK
        );
    }
}
