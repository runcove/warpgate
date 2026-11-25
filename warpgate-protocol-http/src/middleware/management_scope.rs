use poem::error::NotFoundError;
use poem::http::{Method, StatusCode};
use poem::web::Data;
use poem::{Endpoint, FromRequest, IntoResponse, Middleware, Request, Response};
use tracing::warn;
use warpgate_common::{Target, WarpgateError};
use warpgate_common_http::auth::UnauthenticatedRequestContext;
use warpgate_common_http::is_cluster_peer_request;

use super::mfa_enforcement::warpgate_surface_path;
use crate::catchall::{bound_to_host, get_target_by_request_host};

/// Whether `method` and `path` are part of signing in or out: the gateway
/// shell and its assets (the login page is a route inside the shell), the
/// login steps, the browser's own login state, SSO start, return and logout,
/// `info` for the login page, and the custom logo the login page shows.
///
/// This set has two users, each through its own function so either can
/// change without the other: [`is_origin_checked_route`] (the origin check)
/// and [`is_served_on_bound_host`] (what a host bound to an HTTP target
/// serves).
///
/// Paths are matched exactly; a dot or empty segment, or an escape in an
/// asset path, is never part of the login flow.
fn is_login_flow_route(method: &Method, path: &str) -> bool {
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
        "/api/info" | "/api/logo" | "/api/sso/providers" | "/api/sso/auto-start" => {
            method == Method::GET
        }
        "/api/auth/login" | "/api/auth/otp" | "/api/auth/logout" | "/api/sso/logout" => {
            method == Method::POST
        }
        // The browser's own login only; `/api/auth/state/:id` and its
        // approve and reject routes act on someone else's.
        "/api/auth/state" => method == Method::GET || method == Method::DELETE,
        // GET for the query response mode, POST for form_post.
        "/api/sso/return" => method == Method::GET || method == Method::POST,
        _ => false,
    }
}

/// Whether a state-changing request to this route must come from Warpgate's
/// own origin (`OriginCheckMiddleware`): the whole login flow, sign-out
/// included ([`is_login_flow_route`]). Kept apart from
/// [`is_served_on_bound_host`] so that narrowing what bound hosts serve never
/// drops the origin check on a sign-in or sign-out route.
pub fn is_origin_checked_route(method: &Method, path: &str) -> bool {
    is_login_flow_route(method, path)
}

/// Whether a host bound to an HTTP target still serves this route of
/// Warpgate's own and honours a session or token on it
/// ([`credentials_refused_on_bound_host`]). That host serves the target's
/// own pages, which share its origin, so it serves only what neither reads
/// nor changes the sign-in: the gateway's assets (GET); the handoff's begin
/// route (`crate::handoff::BEGIN_PATH`), which starts a handoff and changes
/// no session, and its redeem route (`crate::handoff::REDEEM_PATH`), which
/// is how a browser gets a session on this host (both GET); and sign-out,
/// which there ends only this host's session. Everything else (the login
/// page, the login steps, `info`, the SSO return, the user API and the admin
/// API) is only usable on other hosts; a visitor without a session is sent
/// through a handoff (`common::login_redirect`, or the begin route on a
/// public target's host). The sign-in itself happens on the control-plane
/// host, so an identity provider never returns a browser to a bound host:
/// there the SSO return answers as any unknown route does.
pub fn is_served_on_bound_host(method: &Method, path: &str) -> bool {
    if method == Method::GET
        && matches!(
            warpgate_surface_path(path),
            Some(crate::handoff::BEGIN_PATH | crate::handoff::REDEEM_PATH)
        )
    {
        return true;
    }
    is_login_flow_route(method, path)
        && warpgate_surface_path(path)
            .is_some_and(|path| path.starts_with("/assets/") || path == "/api/auth/logout")
}

/// The HTTP target bound to the request's host, if any, resolved as
/// [`target_binding`] resolves it. A cluster peer's forwarded request is
/// never treated as on a bound host.
pub async fn target_bound_to_request_host(
    ctx: &UnauthenticatedRequestContext,
    req: &Request,
) -> Result<Option<Target>, WarpgateError> {
    if is_cluster_peer_request(req) {
        return Ok(None);
    }
    let Some(host) = ctx.trusted_host_header(req) else {
        return Ok(None);
    };
    let target = get_target_by_request_host(ctx.services(), &host).await?;
    Ok(target.filter(|target| bound_to_host(target, &host)))
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
    let target = get_target_by_request_host(ctx.services(), &host).await?;
    Ok(target.is_some_and(|target| bound_to_host(&target, &host)))
}

/// Whether a route of Warpgate's own on this request's host is out of scope:
/// the host is bound to an HTTP target and the route is not one it serves
/// ([`is_served_on_bound_host`]). A cluster peer's forwarded request was
/// scoped on the node the client reached.
async fn out_of_scope(
    ctx: &UnauthenticatedRequestContext,
    req: &Request,
) -> Result<bool, WarpgateError> {
    let path = req.original_uri().path();
    if is_cluster_peer_request(req)
        || warpgate_surface_path(path).is_none()
        || is_served_on_bound_host(req.method(), path)
    {
        return Ok(false);
    }
    target_binding(ctx, req).await
}

/// Whether the session or token a request to Warpgate's own routes carries
/// must not count, because its host is bound to an HTTP target and the route
/// is not one it serves ([`is_served_on_bound_host`]).
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
/// every route under `/@warpgate` and `/_warpgate` that such a host does not
/// serve ([`is_served_on_bound_host`]) answers 404 there, whatever the
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
                (Method::POST, "/api/sso/logout", true),
                (Method::GET, "/api/sso/logout", false),
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
                // The origin check still covers the whole login flow.
                assert_eq!(
                    is_origin_checked_route(&method, &path),
                    allowed,
                    "{method} {path}"
                );
            }
        }
        // Proxied target paths are not management routes at all.
        assert!(!is_login_flow_route(&Method::GET, "/api/info"));
    }

    /// A bound host serves the gateway's assets, the handoff's begin and
    /// redeem routes and host-local sign-out, and nothing that reads or
    /// changes the sign-in; not the SSO return either.
    #[test]
    fn bound_host_serves_only_assets_handoff_and_logout() {
        for prefix in ["/@warpgate", "/_warpgate"] {
            for (method, path, served) in [
                // The handoff's begin and redeem routes, GET only; never
                // its start
                (Method::GET, "/handoff/begin", true),
                (Method::POST, "/handoff/begin", false),
                (Method::GET, "/handoff/begin/", false),
                (Method::GET, "/handoff", true),
                (Method::POST, "/handoff", false),
                (Method::GET, "/handoff/", false),
                (Method::GET, "/handoff/start", false),
                // Host-local sign-out, POST only
                (Method::POST, "/api/auth/logout", true),
                (Method::GET, "/api/auth/logout", false),
                (Method::GET, "/assets/index-abc123.js", true),
                (Method::GET, "/assets/embed/index.css", true),
                // No sign-in starts here, so no SSO return comes back here
                (Method::GET, "/api/sso/return", false),
                (Method::POST, "/api/sso/return", false),
                // The login page and everything it calls
                (Method::GET, "", false),
                (Method::GET, "/", false),
                (Method::GET, "/api/info", false),
                (Method::GET, "/api/logo", false),
                (Method::POST, "/api/auth/login", false),
                (Method::POST, "/api/auth/otp", false),
                (Method::GET, "/api/auth/state", false),
                (Method::DELETE, "/api/auth/state", false),
                (Method::GET, "/api/sso/providers", false),
                (Method::GET, "/api/sso/providers/corp-idp/start", false),
                (Method::GET, "/api/sso/auto-start", false),
                (Method::POST, "/api/sso/logout", false),
                // Path shapes and methods the login flow refuses stay refused
                (Method::POST, "/assets/index-abc123.js", false),
                (Method::GET, "/assets/../api/info", false),
                (Method::GET, "/assets/%2e%2e/api/info", false),
                (Method::GET, "/assets", false),
                (Method::GET, "/api/sso/return/", false),
                (Method::PUT, "/api/sso/return", false),
                (Method::GET, "/admin/api/users", false),
            ] {
                let path = format!("{prefix}{path}");
                assert_eq!(
                    is_served_on_bound_host(&method, &path),
                    served,
                    "{method} {path}"
                );
            }
        }
        // A target's own paths are not Warpgate's at all.
        assert!(!is_served_on_bound_host(&Method::GET, "/assets/app.js"));
        assert!(!is_served_on_bound_host(&Method::GET, "/api/sso/return"));
        assert!(!is_served_on_bound_host(&Method::GET, "/handoff"));
        assert!(!is_served_on_bound_host(&Method::GET, "/handoff/begin"));
    }

    /// Both sign-out routes are origin-checked, only as POST (a GET can be
    /// triggered by any page). A bound host serves the host-local sign-out
    /// only, never SSO sign-out.
    #[test]
    fn sign_out_is_post_only_and_origin_checked() {
        for prefix in ["/@warpgate", "/_warpgate"] {
            for route in ["/api/auth/logout", "/api/sso/logout"] {
                let path = format!("{prefix}{route}");
                assert!(is_origin_checked_route(&Method::POST, &path), "{path}");
                assert_eq!(
                    is_served_on_bound_host(&Method::POST, &path),
                    route == "/api/auth/logout",
                    "{path}"
                );
                assert!(!is_origin_checked_route(&Method::GET, &path), "{path}");
                assert!(!is_served_on_bound_host(&Method::GET, &path), "{path}");
            }
        }
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

    /// What a bound host serves.
    const BOUND_HOST_SERVED: [(Method, &str); 6] = [
        (Method::GET, "/@warpgate/handoff/begin"),
        (Method::GET, "/@warpgate/handoff"),
        (Method::GET, "/_warpgate/handoff"),
        (Method::POST, "/@warpgate/api/auth/logout"),
        (Method::GET, "/@warpgate/assets/index.js"),
        (Method::GET, "/_warpgate/assets/index.js"),
    ];

    /// The rest of the login flow: served on every other host, on none bound
    /// to a target.
    const SIGN_IN: [(Method, &str); 13] = [
        (Method::GET, "/@warpgate/handoff/start"),
        (Method::GET, "/@warpgate/api/sso/return"),
        (Method::POST, "/@warpgate/api/sso/return"),
        (Method::GET, "/@warpgate"),
        (Method::GET, "/@warpgate/api/info"),
        (Method::GET, "/_warpgate/api/info"),
        (Method::POST, "/@warpgate/api/auth/login"),
        (Method::POST, "/@warpgate/api/auth/otp"),
        (Method::GET, "/@warpgate/api/auth/state"),
        (Method::GET, "/@warpgate/api/sso/providers"),
        (Method::GET, "/@warpgate/api/sso/providers/corp-idp/start"),
        (Method::GET, "/@warpgate/api/sso/auto-start"),
        (Method::POST, "/@warpgate/api/sso/logout"),
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
        assert_eq!(req.original_uri().to_string(), path);
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
    async fn target_host_accepts_credentials_on_assets_handoff_and_logout_only() {
        let (ctx, _db) = context(false).await;
        for (method, path) in BOUND_HOST_SERVED {
            assert!(
                !refused(&ctx, &method, path, &[("host", TARGET_HOST)]).await,
                "{method} {path}"
            );
        }
        // A page on the bound host cannot read who is signed in, sign the
        // browser out, or sign it in as someone else.
        for (method, path) in SIGN_IN {
            assert!(
                refused(&ctx, &method, path, &[("host", TARGET_HOST)]).await,
                "{method} {path}"
            );
        }
    }

    #[tokio::test]
    async fn other_hosts_accept_credentials_on_every_route() {
        let (ctx, _db) = context(false).await;
        for host in [MAIN_HOST, OTHER_HOST, "localhost:8888", "127.0.0.1"] {
            for (method, path) in ADMIN_API
                .into_iter()
                .chain(USER_API)
                .chain(BOUND_HOST_SERVED)
                .chain(SIGN_IN)
            {
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
        let asset = "/@warpgate/assets/index.js";
        for host in [TARGET_HOST, MAIN_HOST] {
            for (method, path) in [(Method::GET, admin), (Method::POST, login)] {
                assert!(
                    refused(&ctx, &method, path, &[("host", host)]).await,
                    "{method} {path} on {host}"
                );
            }
            // What every host serves does not depend on the lookup.
            assert!(
                !refused(&ctx, &Method::GET, asset, &[("host", host)]).await,
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
    async fn bound_target_is_resolved_from_the_trusted_host() {
        let (ctx, _db) = context(false).await;
        let bound = |headers: &'static [(&'static str, &'static str)], peer: bool| {
            let mut req = scoped_request(&Method::GET, "/app", headers);
            if peer {
                req.extensions_mut().insert(ClusterPeer {
                    node_id: NodeId(Uuid::new_v4()),
                });
            }
            let ctx = &ctx;
            async move {
                target_bound_to_request_host(ctx, &req)
                    .await
                    .unwrap()
                    .is_some()
            }
        };
        assert!(bound(&[("host", TARGET_HOST)], false).await);
        assert!(!bound(&[("host", TARGET_HOST)], true).await);
        assert!(!bound(&[("host", MAIN_HOST)], false).await);
        assert!(!bound(&[("host", "vm.example.test")], false).await);
        assert!(
            !bound(
                &[("host", MAIN_HOST), ("x-forwarded-host", TARGET_HOST)],
                false
            )
            .await
        );
    }

    const NAVIGATION: [(&str, &str); 2] = [
        ("accept", "text/html,application/xhtml+xml,*/*;q=0.8"),
        ("sec-fetch-mode", "navigate"),
    ];

    /// The login redirect for an unauthenticated request, as `page_auth`
    /// sends it: its status and `Location`.
    async fn login_redirect_for(
        ctx: &UnauthenticatedRequestContext,
        path: &str,
        headers: &[(&str, &str)],
    ) -> (StatusCode, Option<String>) {
        login_redirect_limited(ctx, path, headers, None).await
    }

    /// [`login_redirect_for`] under the handoff rate limit `limit`, if given.
    async fn login_redirect_limited(
        ctx: &UnauthenticatedRequestContext,
        path: &str,
        headers: &[(&str, &str)],
        limit: Option<std::sync::Arc<crate::handoff::RateLimit>>,
    ) -> (StatusCode, Option<String>) {
        let mut builder = poem::http::Request::builder().uri(path);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let (parts, ()) = builder.body(()).unwrap().into_parts();
        let mut req = Request::from_parts(
            poem::RequestParts::from((
                parts,
                poem::web::LocalAddr::default(),
                poem::web::RemoteAddr::default(),
                poem::http::uri::Scheme::HTTP,
            )),
            poem::Body::empty(),
        );
        // Positive control: the address under test, query and all, is the
        // one the redirect reads.
        assert_eq!(req.original_uri().to_string(), path);
        req.extensions_mut().insert(ctx.clone());
        if let Some(limit) = limit {
            req.extensions_mut().insert(limit);
        }
        let response = crate::common::login_redirect(&req).await;
        let location = response
            .headers()
            .get(poem::http::header::LOCATION)
            .map(|value| value.to_str().unwrap().to_owned());
        (response.status(), location)
    }

    /// A visitor without a session on a bound host starts a handoff: a 303
    /// to the handoff start on the control-plane host named in the
    /// configuration, with a challenge and the nonce cookie; the request's
    /// Host chooses neither origin. Other hosts keep their own login page.
    #[tokio::test]
    async fn bound_host_sends_sign_in_to_the_control_plane() {
        let (ctx, _db) = context(true).await;
        {
            let mut config = ctx.services().config.lock().await;
            config.store.external_host = Some("warpgate.example.test".into());
            config.store.http.external_port = Some(8443);
        }
        let start = "https://warpgate.example.test:8443/@warpgate/handoff/start?challenge=";
        let on_target = [("host", TARGET_HOST), NAVIGATION[0], NAVIGATION[1]];
        let (status, location) = login_redirect_for(&ctx, "/app?a=1", &on_target).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let location = location.unwrap();
        assert!(location.starts_with(start), "{location}");
        assert!(location.len() > start.len(), "{location}");
        // The page to return to stays on the server, not in the address.
        assert!(!location.contains("app"), "{location}");

        // The bound host reached through a trusted X-Forwarded-Host is bound
        // all the same, and the redirect names the configured hosts only.
        let forwarded = [
            ("host", "other.example"),
            ("x-forwarded-host", TARGET_HOST),
            NAVIGATION[0],
            NAVIGATION[1],
        ];
        let (_, location) = login_redirect_for(&ctx, "/app", &forwarded).await;
        let location = location.unwrap();
        assert!(location.starts_with(start), "{location}");
        assert!(!location.contains("other"), "{location}");

        // A fetch gets the 401 without a redirect.
        let (status, location) = login_redirect_for(&ctx, "/app", &[("host", TARGET_HOST)]).await;
        assert_eq!((status, location), (StatusCode::UNAUTHORIZED, None));

        // Plain HTTP (the nonce cookie is a `__Host-` cookie): no handoff.
        let plain = [
            ("host", TARGET_HOST),
            ("x-forwarded-proto", "http"),
            NAVIGATION[0],
            NAVIGATION[1],
        ];
        let (status, location) = login_redirect_for(&ctx, "/app", &plain).await;
        assert_eq!((status, location), (StatusCode::UNAUTHORIZED, None));

        // Other hosts keep their own login page.
        let on_main = [("host", MAIN_HOST), NAVIGATION[0], NAVIGATION[1]];
        let (status, location) = login_redirect_for(&ctx, "/app", &on_main).await;
        assert_eq!(status, StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(location.as_deref(), Some("/@warpgate#/login?next=%2Fapp"));
    }

    /// Addresses of Warpgate's own pages sent from a bound host carry the
    /// configured control-plane origin; from other hosts they stay
    /// site-relative. (A bound host does not serve the SSO return, whose
    /// failure redirect uses this, so for it this is defence in depth.)
    #[tokio::test]
    async fn gateway_pages_origin_is_the_control_plane_on_a_bound_host() {
        let (ctx, _db) = context(false).await;
        {
            let mut config = ctx.services().config.lock().await;
            config.store.external_host = Some("warpgate.example.test".into());
            config.store.http.external_port = Some(8443);
        }
        let origin = |host: &'static str| {
            let mut req =
                scoped_request(&Method::GET, "/@warpgate/api/sso/return", &[("host", host)]);
            req.extensions_mut().insert(ctx.clone());
            async move { crate::common::gateway_pages_origin(&req).await }
        };
        assert_eq!(
            origin(TARGET_HOST).await,
            "https://warpgate.example.test:8443"
        );
        assert_eq!(origin(MAIN_HOST).await, "");
    }

    /// With `http.external_host` naming the control plane apart from the
    /// global `external_host` (which may itself be a bound site), the
    /// handoff starts on `http.external_host`.
    #[tokio::test]
    async fn bound_host_sign_in_goes_to_http_external_host() {
        let (ctx, _db) = context(false).await;
        {
            let mut config = ctx.services().config.lock().await;
            config.store.external_host = Some("vm.example.test".into());
            config.store.http.external_host = Some("admin.example.test".into());
            config.store.http.external_port = Some(8443);
        }
        let on_target = [("host", TARGET_HOST), NAVIGATION[0], NAVIGATION[1]];
        let (status, location) = login_redirect_for(&ctx, "/", &on_target).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let location = location.unwrap();
        assert!(
            location
                .starts_with("https://admin.example.test:8443/@warpgate/handoff/start?challenge="),
            "{location}"
        );
    }

    /// Past the source address's rate limit, a bound host opens no handoff
    /// and refuses with a plain 429.
    #[tokio::test]
    async fn bound_host_sign_in_past_the_rate_limit_is_refused() {
        let (ctx, db) = context(false).await;
        {
            let mut config = ctx.services().config.lock().await;
            config.store.external_host = Some("warpgate.example.test".into());
        }
        let limit = std::sync::Arc::new(crate::handoff::RateLimit::per_minute(
            std::num::NonZeroU32::new(1).unwrap(),
        ));
        let on_target = [("host", TARGET_HOST), NAVIGATION[0], NAVIGATION[1]];
        let (status, _) = login_redirect_limited(&ctx, "/", &on_target, Some(limit.clone())).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let (status, location) = login_redirect_limited(&ctx, "/", &on_target, Some(limit)).await;
        assert_eq!((status, location), (StatusCode::TOO_MANY_REQUESTS, None));
        assert_eq!(
            warpgate_db_entities::HttpHandoff::count(&db).await.unwrap(),
            1
        );
    }

    /// Without a configured control-plane host, or when the binding cannot
    /// be looked up, a bound host sends the visitor to no login page.
    #[tokio::test]
    async fn bound_host_without_a_control_plane_redirects_nowhere() {
        let on_target = [("host", TARGET_HOST), NAVIGATION[0], NAVIGATION[1]];
        let (ctx, db) = context(false).await;
        assert_eq!(
            login_redirect_for(&ctx, "/app", &on_target).await,
            (StatusCode::UNAUTHORIZED, None)
        );

        ctx.services().config.lock().await.store.external_host =
            Some("warpgate.example.test".into());
        db.execute_unprepared("DROP TABLE targets").await.unwrap();
        assert_eq!(
            login_redirect_for(&ctx, "/app", &on_target).await,
            (StatusCode::UNAUTHORIZED, None)
        );
    }

    /// Whether `inject_request_authorization` lets `session` count for this
    /// request.
    async fn counts(
        ctx: &UnauthenticatedRequestContext,
        session: &poem::session::Session,
        method: &Method,
        path: &str,
        host: &str,
    ) -> bool {
        use warpgate_common_http::auth::AuthenticatedRequestContext;
        let app = make_sync(|req: Request| {
            if req.data::<AuthenticatedRequestContext>().is_some() {
                "auth"
            } else {
                "anon"
            }
        })
        .around(crate::common::inject_request_authorization);
        let mut req = scoped_request(method, path, &[("host", host)]);
        req.extensions_mut().insert(ctx.clone());
        req.extensions_mut().insert(session.clone());
        app.call(req).await.unwrap() == "auth"
    }

    /// A target-host session counts only on its own target's host, for the
    /// proxied paths and the host-local sign-out; a control-plane sign-in
    /// counts on no bound host. A failed host lookup counts neither.
    #[tokio::test]
    async fn bound_and_control_plane_sessions_count_only_where_they_belong() {
        use warpgate_common_http::SessionAuthorization;

        use crate::common::{BoundSessionAuthorization, SessionExt};

        let (ctx, db) = context(false).await;
        let target = get_target_by_request_host(ctx.services(), TARGET_HOST)
            .await
            .unwrap()
            .unwrap();
        let bound = |target_id: Uuid, hostname: &str| {
            let session = poem::session::Session::default();
            session.set_bound_auth(BoundSessionAuthorization {
                user_id: Uuid::new_v4(),
                username: "alice".into(),
                target_id,
                hostname: hostname.into(),
            });
            session
        };
        let own = bound(target.id, TARGET_HOST);
        let get = Method::GET;
        let post = Method::POST;
        for (session, method, path, host, expected) in [
            (&own, &get, "/app", TARGET_HOST, true),
            (&own, &post, "/app/form", TARGET_HOST, true),
            (&own, &post, "/@warpgate/api/auth/logout", TARGET_HOST, true),
            (&own, &get, "/@warpgate/api/info", TARGET_HOST, false),
            (&own, &get, "/@warpgate/api/targets", TARGET_HOST, false),
            (&own, &get, "/app", MAIN_HOST, false),
            (&own, &get, "/app", OTHER_HOST, false),
            (&own, &post, "/@warpgate/api/auth/logout", MAIN_HOST, false),
        ] {
            assert_eq!(
                counts(&ctx, session, method, path, host).await,
                expected,
                "{method} {path} on {host}"
            );
        }
        // Another target's session, or one for another hostname, counts
        // nowhere here.
        for session in [
            bound(Uuid::new_v4(), TARGET_HOST),
            bound(target.id, "other.example.test"),
        ] {
            assert!(!counts(&ctx, &session, &get, "/app", TARGET_HOST).await);
        }

        let signed_in = poem::session::Session::default();
        signed_in.set_auth(SessionAuthorization::User {
            user_id: Uuid::new_v4(),
            username: "alice".into(),
        });
        assert!(counts(&ctx, &signed_in, &get, "/app", MAIN_HOST).await);
        assert!(!counts(&ctx, &signed_in, &get, "/app", TARGET_HOST).await);
        assert!(
            !counts(
                &ctx,
                &signed_in,
                &post,
                "/@warpgate/api/auth/logout",
                TARGET_HOST
            )
            .await
        );

        // Fail closed when the host cannot be resolved.
        db.execute_unprepared("DROP TABLE targets").await.unwrap();
        assert!(!counts(&ctx, &own, &get, "/app", TARGET_HOST).await);
        assert!(!counts(&ctx, &signed_in, &get, "/app", MAIN_HOST).await);
    }

    #[tokio::test]
    async fn underscore_prefix_is_scoped_too() {
        let (ctx, _db) = context(false).await;
        for (method, path, expected) in [
            (Method::GET, "/_warpgate/admin/api/users", true),
            (Method::GET, "/_warpgate/api/targets", true),
            (Method::GET, "/_warpgate/api/info", true),
            (Method::POST, "/_warpgate/api/auth/login", true),
            (Method::POST, "/_warpgate/api/sso/logout", true),
            (Method::POST, "/_warpgate/api/auth/logout", false),
            (Method::GET, "/_warpgate/handoff", false),
            (Method::GET, "/_warpgate/assets/index.js", false),
            (Method::GET, "/_warpgate/api/sso/return", true),
        ] {
            assert_eq!(
                refused(&ctx, &method, path, &[("host", TARGET_HOST)]).await,
                expected,
                "{method} {path}"
            );
        }
    }

    /// On a bound host the SSO return does not exist: GET and POST answer
    /// exactly as an unknown route under the user API does (status, headers
    /// and body), with the real user API mounted under both prefixes. The
    /// control-plane host still routes it.
    #[tokio::test]
    async fn sso_return_on_a_bound_host_answers_as_an_unknown_route() {
        let (ctx, _db) = context(false).await;
        let mount = || {
            Route::new()
                .nest(
                    "/api",
                    poem_openapi::OpenApiService::new(crate::api::get(), "test", "0")
                        .server("/@warpgate/api"),
                )
                .with(ManagementScopeMiddleware)
        };
        let app = Route::new()
            .nest("/@warpgate", mount())
            .nest("/_warpgate", mount())
            .data(ctx)
            .with(poem::session::ServerSession::new(
                poem::session::CookieConfig::default(),
                poem::session::MemoryStorage::new(),
            ));
        let response = |method: Method, path: String, host: &'static str| {
            let req = scoped_request(&method, &path, &[("host", host)]);
            let app = &app;
            async move {
                let response = app.get_response(req).await;
                let status = response.status();
                let mut headers: Vec<(String, String)> = response
                    .headers()
                    .iter()
                    .map(|(name, value)| {
                        (name.to_string(), value.to_str().unwrap_or("").to_owned())
                    })
                    .collect();
                headers.sort();
                let body = response.into_body().into_vec().await.unwrap();
                (status, headers, body)
            }
        };

        for prefix in ["/@warpgate", "/_warpgate"] {
            let unknown = format!("{prefix}/api/no-such-route");
            let sso_return = format!("{prefix}/api/sso/return");
            for method in [Method::GET, Method::POST] {
                let expected = response(method.clone(), unknown.clone(), TARGET_HOST).await;
                assert_eq!(expected.0, StatusCode::NOT_FOUND, "{method} {unknown}");
                for path in [sso_return.clone(), format!("{sso_return}?code=c&state=s")] {
                    assert_eq!(
                        response(method.clone(), path.clone(), TARGET_HOST).await,
                        expected,
                        "{method} {path}"
                    );
                }

                // The control-plane host routes the SSO return (it fails
                // here without a handshake, but not as a missing route) and
                // answers 404 for the unknown one.
                let (status, ..) = response(method.clone(), sso_return.clone(), MAIN_HOST).await;
                assert!(
                    status != StatusCode::NOT_FOUND && status != StatusCode::METHOD_NOT_ALLOWED,
                    "{method} {sso_return} on {MAIN_HOST}: {status}"
                );
                let (status, ..) = response(method.clone(), unknown.clone(), MAIN_HOST).await;
                assert_eq!(status, StatusCode::NOT_FOUND, "{method} {unknown}");
            }
        }
    }

    /// The middleware over both mounts: out-of-scope routes, the sign-in
    /// routes and the SSO return among them, are 404 on the bound host
    /// whatever the credentials, assets are served, other hosts are
    /// untouched, and a failed lookup is 503.
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

        for (method, path) in ADMIN_API.into_iter().chain(USER_API).chain(SIGN_IN) {
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
        for (method, path) in BOUND_HOST_SERVED {
            for host in [TARGET_HOST, MAIN_HOST] {
                assert_eq!(
                    status(method.clone(), path, host).await,
                    StatusCode::OK,
                    "{method} {path} on {host}"
                );
            }
        }
        // The login page's custom logo goes with it.
        assert_eq!(
            status(Method::GET, "/@warpgate/api/logo", TARGET_HOST).await,
            StatusCode::NOT_FOUND
        );

        db.execute_unprepared("DROP TABLE targets").await.unwrap();
        for path in ["/@warpgate/admin/api/users", "/@warpgate/api/info"] {
            assert_eq!(
                status(Method::GET, path, TARGET_HOST).await,
                StatusCode::SERVICE_UNAVAILABLE,
                "{path}"
            );
        }
        assert_eq!(
            status(Method::GET, "/@warpgate/assets/index.js", TARGET_HOST).await,
            StatusCode::OK
        );
    }
}
