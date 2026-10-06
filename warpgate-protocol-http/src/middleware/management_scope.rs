use poem::error::NotFoundError;
use poem::http::{Method, StatusCode};
use poem::web::Data;
use poem::{Endpoint, FromRequest, IntoResponse, Middleware, Request, Response};
use tracing::warn;
use warpgate_common_http::auth::UnauthenticatedRequestContext;
use warpgate_common_http::is_cluster_peer_request;
use warpgate_core::ConfigProvider;

use super::mfa_enforcement::warpgate_surface_path;
use crate::catchall::bound_to_host;

/// Whether `method` and `path` are part of signing in or out: the routes a
/// host bound to an HTTP target still serves under `/@warpgate` and
/// `/_warpgate`. That covers the gateway shell and its assets (the login page
/// is a route inside the shell), the login steps, the browser's own login
/// state, SSO start, return and logout, and `info` for the login page and the
/// embedded session bar. Everything else, including the admin API, the rest
/// of the user API and forced MFA enrolment, is only served on other hosts.
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
        "/api/info" | "/api/sso/providers" | "/api/sso/auto-start" | "/api/sso/logout" => {
            method == Method::GET
        }
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
/// included, looked up with `get_target_by_hostname` and compared with
/// [`bound_to_host`]. A cluster peer's forwarded request was scoped on the
/// node the client reached.
async fn is_target_bound(req: &Request) -> poem::Result<bool> {
    let ctx = Data::<&UnauthenticatedRequestContext>::from_request_without_body(req).await?;
    if is_cluster_peer_request(req, &ctx.services().cluster.cluster_token) {
        return Ok(false);
    }
    let Some(host) = ctx.trusted_host_header(req) else {
        return Ok(false);
    };
    let target = ctx
        .services()
        .config_provider
        .get_target_by_hostname(&host)
        .await?;
    Ok(target.is_some_and(|target| bound_to_host(&target, &host)))
}

/// Serves only the login flow ([`is_login_flow_route`]) on hosts bound to an
/// HTTP target; every other management route answers 404 there, as if it
/// were not mounted. If the host cannot be resolved, those routes answer 503
/// rather than being served.
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
        if !is_login_flow_route(req.method(), req.original_uri().path()) {
            match is_target_bound(&req).await {
                Ok(false) => {}
                Ok(true) => return Err(NotFoundError.into()),
                Err(error) => {
                    warn!(%error, "Could not resolve the request host to a target; refusing a management route");
                    return Err(poem::Error::from_status(StatusCode::SERVICE_UNAVAILABLE));
                }
            }
        }
        Ok(self.inner.call(req).await?.into_response())
    }
}

#[cfg(test)]
mod tests {
    use poem::endpoint::make_sync;
    use poem::test::TestClient;
    use poem::{EndpointExt, Route};
    use sea_orm::ActiveValue::Set;
    use sea_orm::{ConnectionTrait, DatabaseConnection, EntityTrait};
    use uuid::Uuid;
    use warpgate_common::http_headers::X_WARPGATE_CLUSTER_TOKEN;
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

    /// Both management mounts behind the scope, over a database with one HTTP
    /// target bound to [`TARGET_HOST`].
    async fn client(trust_x_forwarded: bool) -> (TestClient<impl Endpoint>, DatabaseConnection) {
        let db = crate::test_db::memory_db().await;
        bind_target(&db, TARGET_HOST).await;
        let services = crate::test_db::services(db.clone()).await;
        services.config.lock().await.store.http.trust_x_forwarded_headers = trust_x_forwarded;
        let ctx = UnauthenticatedRequestContext::new(services).await;
        let mount = || make_sync(|_| "served").with(ManagementScopeMiddleware);
        let app = Route::new()
            .nest("/@warpgate", mount())
            .nest("/_warpgate", mount())
            .data(ctx);
        (TestClient::new(app), db)
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

    async fn status(
        cli: &TestClient<impl Endpoint>,
        method: &Method,
        path: &str,
        headers: &[(&str, &str)],
    ) -> StatusCode {
        let mut req = cli.request(method.clone(), path);
        for (name, value) in headers {
            req = req.header(*name, *value);
        }
        req.send().await.0.status()
    }

    #[tokio::test]
    async fn target_host_refuses_admin_api() {
        let (cli, _db) = client(false).await;
        for (method, path) in ADMIN_API {
            assert_eq!(
                status(&cli, &method, path, &[("host", TARGET_HOST)]).await,
                StatusCode::NOT_FOUND,
                "{method} {path}"
            );
        }
    }

    #[tokio::test]
    async fn target_host_refuses_user_api() {
        let (cli, _db) = client(false).await;
        for (method, path) in USER_API {
            assert_eq!(
                status(&cli, &method, path, &[("host", TARGET_HOST)]).await,
                StatusCode::NOT_FOUND,
                "{method} {path}"
            );
        }
    }

    #[tokio::test]
    async fn target_host_serves_login_flow() {
        let (cli, _db) = client(false).await;
        for (method, path) in LOGIN_FLOW {
            assert_eq!(
                status(&cli, &method, path, &[("host", TARGET_HOST)]).await,
                StatusCode::OK,
                "{method} {path}"
            );
        }
    }

    #[tokio::test]
    async fn main_host_serves_every_route() {
        let (cli, _db) = client(false).await;
        for (method, path) in ADMIN_API.into_iter().chain(USER_API).chain(LOGIN_FLOW) {
            assert_eq!(
                status(&cli, &method, path, &[("host", MAIN_HOST)]).await,
                StatusCode::OK,
                "{method} {path}"
            );
        }
    }

    #[tokio::test]
    async fn other_host_serves_every_route() {
        let (cli, _db) = client(false).await;
        for host in [OTHER_HOST, "localhost:8888", "127.0.0.1"] {
            for (method, path) in ADMIN_API.into_iter().chain(USER_API) {
                assert_eq!(
                    status(&cli, &method, path, &[("host", host)]).await,
                    StatusCode::OK,
                    "{method} {path} on {host}"
                );
            }
        }
    }

    #[tokio::test]
    async fn cluster_peer_is_not_scoped() {
        let db = crate::test_db::memory_db().await;
        bind_target(&db, TARGET_HOST).await;
        let services = crate::test_db::services(db).await;
        let token = services.cluster.cluster_token.expose_secret().clone();
        let ctx = UnauthenticatedRequestContext::new(services).await;
        let app = Route::new()
            .nest(
                "/@warpgate",
                make_sync(|_| "served").with(ManagementScopeMiddleware),
            )
            .data(ctx);
        let cli = TestClient::new(app);
        let peer = [
            ("host", TARGET_HOST),
            (X_WARPGATE_CLUSTER_TOKEN.as_str(), token.as_str()),
        ];
        let admin = "/@warpgate/admin/api/users";
        assert_eq!(
            status(&cli, &Method::GET, admin, &peer).await,
            StatusCode::OK
        );
        let wrong = [
            ("host", TARGET_HOST),
            (X_WARPGATE_CLUSTER_TOKEN.as_str(), "wrong"),
        ];
        assert_eq!(
            status(&cli, &Method::GET, admin, &wrong).await,
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn target_lookup_error_fails_closed() {
        let (cli, db) = client(false).await;
        db.execute_unprepared("DROP TABLE targets").await.unwrap();
        let admin = "/@warpgate/admin/api/users";
        let login = "/@warpgate/api/auth/login";
        for host in [TARGET_HOST, MAIN_HOST] {
            assert_eq!(
                status(&cli, &Method::GET, admin, &[("host", host)]).await,
                StatusCode::SERVICE_UNAVAILABLE,
                "{host}"
            );
            // The login flow does not depend on the lookup.
            assert_eq!(
                status(&cli, &Method::POST, login, &[("host", host)]).await,
                StatusCode::OK,
                "{host}"
            );
        }
    }

    #[tokio::test]
    async fn scope_matches_catchall_host_resolution() {
        let admin = "/@warpgate/admin/api/users";
        let forwarded_to_target = [("host", MAIN_HOST), ("x-forwarded-host", TARGET_HOST)];
        let forwarded_to_main = [("host", TARGET_HOST), ("x-forwarded-host", MAIN_HOST)];

        // The port is part of the binding, as in the catchall.
        let (cli, _db) = client(false).await;
        for (host, expected) in [
            ("vm.example.test", StatusCode::OK),
            ("vm.example.test:9443", StatusCode::OK),
            (TARGET_HOST, StatusCode::NOT_FOUND),
        ] {
            let headers = [("host", host)];
            assert_eq!(
                status(&cli, &Method::GET, admin, &headers).await,
                expected,
                "{host}"
            );
        }
        // X-Forwarded-Host is ignored unless it is trusted ...
        assert_eq!(
            status(&cli, &Method::GET, admin, &forwarded_to_target).await,
            StatusCode::OK
        );

        // ... and takes precedence over Host when it is.
        let (cli, _db) = client(true).await;
        assert_eq!(
            status(&cli, &Method::GET, admin, &forwarded_to_target).await,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            status(&cli, &Method::GET, admin, &forwarded_to_main).await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn binding_agrees_with_served_on_host() {
        // A host is bound exactly where the catchall serves the bound target.
        let (cli, _db) = client(false).await;
        let admin = "/@warpgate/admin/api/users";
        for host in [
            TARGET_HOST,
            "vm.example.test",
            "vm.example.test:9443",
            "VM.example.test:8443",
            "vm.example.test:8443.",
        ] {
            let expected = if served_on_host(Some(TARGET_HOST), Some(host)) {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::OK
            };
            let headers = [("host", host)];
            assert_eq!(
                status(&cli, &Method::GET, admin, &headers).await,
                expected,
                "{host}"
            );
        }
    }

    #[tokio::test]
    async fn underscore_prefix_is_scoped_too() {
        let (cli, _db) = client(false).await;
        let (ok, not_found) = (StatusCode::OK, StatusCode::NOT_FOUND);
        for (method, path, expected) in [
            (Method::GET, "/_warpgate/admin/api/users", not_found),
            (Method::GET, "/_warpgate/api/targets", not_found),
            (Method::GET, "/_warpgate/api/info", ok),
            (Method::POST, "/_warpgate/api/auth/login", ok),
        ] {
            assert_eq!(
                status(&cli, &method, path, &[("host", TARGET_HOST)]).await,
                expected,
                "{method} {path}"
            );
        }
    }
}
