use core::str;
use std::sync::Arc;

use anyhow::Context;
use http::{HeaderName, StatusCode};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use poem::error::InternalServerError;
use poem::session::{CookieConfig, Session};
use poem::web::cookie::CookieJar;
use poem::web::{Data, Redirect};
use poem::{Endpoint, EndpointExt, FromRequest, IntoResponse, Request, Response};
use sea_orm::EntityTrait;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use time::OffsetDateTime;
use tokio::sync::Mutex;
use tracing::info;
use uuid::Uuid;
use warpgate_common::auth::{AuthResult, AuthState, AuthStateUserInfo, CredentialKind};
use warpgate_common::helpers::username::username_eq_ci;
use warpgate_common::{Protocol, UserSessionId, WarpgateError};
use warpgate_common_http::auth::UnauthenticatedRequestContext;
use warpgate_common_http::ext::{construct_external_url, is_navigation_request};
use warpgate_common_http::logging::get_client_ip_addr;
use warpgate_common_http::{
    AuthenticatedRequestContext, RequestAuthorization, SessionAuthorization,
    X_WARPGATE_CLUSTER_IDENTITY, is_cluster_peer_request,
};
use warpgate_core::{ConfigProvider, vet_credential_bearer};
use warpgate_db_entities::User;
use warpgate_sso::WarpgateIdToken;

use crate::catchall::{
    PublicTargetDecision, is_warpgate_management_path, resolve_public_target_decision,
};
use crate::middleware::assert_mfa_setup_gate;
use crate::middleware::ticket::TemporaryTicketSession;
use crate::session::SessionStore;
use crate::session_storage::SharedSessionStorage;
use crate::step_up::{StepUpSessionExt, is_session_step_up_stale};

pub const PROTOCOL_NAME: Protocol = Protocol::Http;
static TARGET_SESSION_KEY: &str = "target_name";
static AUTH_SESSION_KEY: &str = "auth";
static AUTH_SSO_LOGIN_STATE: &str = "auth_sso_login_state";
pub static SESSION_COOKIE_NAME: &str = "warpgate-http-session";
pub static X_WARPGATE_TOKEN: HeaderName = HeaderName::from_static("x-warpgate-token");

/// The session cookie's shape — name and (absence of) signing — defined once:
/// the `ServerSession` middleware writes the cookie through this config, and
/// [`storage_session_id`] reads it back through the same one. `max_age` is
/// applied at the middleware wiring, where the write happens.
pub fn session_cookie_config() -> CookieConfig {
    CookieConfig::default()
        .secure(false)
        .name(SESSION_COOKIE_NAME)
}

/// The browser session's storage id from the request's cookie — poem keeps it
/// only there, never inside the session entries.
pub fn storage_session_id(jar: &CookieJar) -> Option<String> {
    session_cookie_config().get_cookie_value(jar)
}

/// Check if a host is localhost or 127.x.x.x (for development/testing scenarios)
pub fn is_localhost_host(host: &str) -> bool {
    host == "localhost" || host == "127.0.0.1" || host.starts_with("127.")
}

pub fn host_is_subdomain_of_or_equal(host: &str, base_domain: &str) -> bool {
    let base = base_domain.trim_start_matches('.');
    host == base || host.ends_with(&format!(".{base}"))
}

/// Whether a request may present a session cookie, given the configured base
/// host: the base host itself, its subdomains, or localhost (for development
/// against a non-localhost deployment). A request whose host cannot be
/// determined proves nothing and is refused — this check must not fail open.
fn session_host_is_authorized(request_host: Option<&str>, base_host: &str) -> bool {
    let Some(host) = request_host else {
        return false;
    };
    host_is_subdomain_of_or_equal(host, base_host)
        || (is_localhost_host(host) && base_host != "localhost" && base_host != "127.0.0.1")
}

#[derive(Serialize, Deserialize)]
pub struct SsoLoginState {
    pub token: WarpgateIdToken,
    pub provider: String,
    pub supports_single_logout: bool,
}

pub trait SessionExt {
    fn get_target_name(&self) -> Option<String>;
    fn set_target_name(&self, target_name: String);
    fn get_auth(&self) -> Option<SessionAuthorization>;
    fn set_auth(&self, auth: SessionAuthorization);
    /// The Warpgate session id of this browser session, once one has been
    /// registered for it. Unlike [`session_id_for_request`] this never creates
    /// one.
    fn get_session_id(&self) -> Option<UserSessionId>;

    fn get_sso_login_state(&self) -> Option<SsoLoginState>;
    fn set_sso_login_state(&self, token: SsoLoginState);
}

impl SessionExt for Session {
    fn get_target_name(&self) -> Option<String> {
        self.get(TARGET_SESSION_KEY)
    }

    fn set_target_name(&self, target_name: String) {
        self.set(TARGET_SESSION_KEY, target_name);
    }

    fn get_auth(&self) -> Option<SessionAuthorization> {
        self.get(AUTH_SESSION_KEY)
    }

    fn set_auth(&self, auth: SessionAuthorization) {
        self.set(AUTH_SESSION_KEY, auth);
    }

    fn get_session_id(&self) -> Option<UserSessionId> {
        self.get(crate::session::SESSION_ID_SESSION_KEY)
    }

    fn get_sso_login_state(&self) -> Option<SsoLoginState> {
        self.get::<String>(AUTH_SSO_LOGIN_STATE)
            .and_then(|x| serde_json::from_str(&x).ok())
    }

    fn set_sso_login_state(&self, state: SsoLoginState) {
        if let Ok(json) = serde_json::to_string(&state) {
            self.set(AUTH_SSO_LOGIN_STATE, json);
        }
    }
}

pub async fn is_user_admin(ctx: &AuthenticatedRequestContext) -> poem::Result<bool> {
    // A user is an administrator if they hold any admin permission. Resolved through the one
    // shared permission loader so this can't drift from the endpoint gate or the /info UI.
    Ok(warpgate_admin::api::admin_permission_set(ctx)
        .await
        .map_err(InternalServerError)?
        .is_admin())
}

/// Run the per-request authentication gate.
///
/// Returns `Ok(Ok(output))` when the request is authenticated (the wrapped
/// endpoint was called), or `Ok(Err(req))` when it is not — handing the
/// untouched `Request` back to the caller so it can build a redirect / 401
/// response (see `page_auth`, which needs the request to compute an SSO
/// auto-redirect on the unauthenticated path).
pub async fn _inner_auth<E: Endpoint + 'static>(
    ep: Arc<E>,
    req: Request,
) -> poem::Result<Result<E::Output, Request>> {
    let ctx = Option::<Data<&AuthenticatedRequestContext>>::from_request_without_body(&req).await?;
    let Some(ctx) = ctx else {
        return Ok(Err(req));
    };

    // Per-session SSO step-up gate. If the session is authed as a `User` (not
    // a ticket, not an API token) and the configured HTTP interval has elapsed
    // since the last SSO handshake on this session, force a re-login: log the
    // browser session out, then hand the request back so that the surrounding
    // `page_auth` / `endpoint_auth` wrapper redirects to the gateway login page
    // (or answers 401). Tickets / tokens / anonymous fall through unchanged - we
    // only pay the config-lock + session-read cost on the `User` path.
    if let RequestAuthorization::Session(session_auth @ SessionAuthorization::User { .. }) =
        &ctx.auth
    {
        // Pull the interval first; absent config -> feature off, skip the
        // session read entirely to keep the hot path cheap.
        let interval = ctx
            .services()
            .config
            .lock()
            .await
            .store
            .step_up_interval
            .as_ref()
            .and_then(|s| s.http);
        if interval.is_some() {
            let session = <&Session>::from_request_without_body(&req).await?;
            let last_sso_at = session.get_last_sso_at();
            if is_session_step_up_stale(
                Some(session_auth),
                last_sso_at,
                interval,
                OffsetDateTime::now_utc(),
            ) {
                info!(
                    username = %session_auth.username(),
                    has_stamp = last_sso_at.is_some(),
                    "HTTP step-up required: session last_sso_at is stale or missing"
                );
                // A full logout rather than dropping only the auth claim: on
                // 0.29.1 the browser session's server handle stays attributed
                // to this user, and a cookie that no longer names the user is
                // refused (401) by `SessionStore::handle_for_request` - which
                // would block the very re-login this is asking for. SSO
                // handshakes in flight live outside the Poem session, so
                // nothing the re-login needs is lost.
                let session_middleware =
                    Data::<&Arc<Mutex<SessionStore>>>::from_request_without_body(&req).await?;
                crate::api::common::logout(session, &mut *session_middleware.lock().await);
                return Ok(Err(req));
            }
        }
    }

    return ep.call(req).await.map(Ok);
}

// TODO unify both based on the accept header
pub fn endpoint_auth<E: Endpoint + 'static>(e: E) -> impl Endpoint<Output = E::Output> {
    e.around(|ep, req| async move {
        _inner_auth(ep, req)
            .await?
            .map_err(|_req| poem::Error::from_status(StatusCode::UNAUTHORIZED))
    })
}

pub fn page_auth<E: Endpoint + 'static>(e: E) -> impl Endpoint {
    e.around(|ep, req| async move {
        // Public-target bypass. If the request resolves to an HTTP target
        // with `public: true`, anonymous and session-authed clients are routed
        // through to the catchall without the normal session/role gate: a
        // logged-in visitor as themselves on their own session, anyone else
        // on a throwaway `<public>` session. Admin/user/cluster tokens get a
        // 401 (they are not proxy-scoped). `page_auth` only wraps the catchall
        // mount, so this never runs on the `/@warpgate` routes.
        match try_public_target_bypass(&req).await? {
            PublicBypassOutcome::Bypass { ctx, target_id } => {
                // Override any pre-existing AuthenticatedRequestContext with
                // a target-scoped Ticket-style auth so the catchall's Ticket
                // arm (resolve by target_id, no role check) routes the request
                // to the resolved public target. `_inner_auth`'s SSO step-up
                // logic is gated on `Session(User { .. })` and so is also
                // skipped.
                let (req, auth) = onto_public_target_session(req, target_id);
                let synthetic_ctx = ctx.to_authenticated(RequestAuthorization::Session(auth));
                return Ok(ep.data(synthetic_ctx).call(req).await?.into_response());
            }
            PublicBypassOutcome::Reject401 => {
                return Err(poem::Error::from_string(
                    "API tokens are not valid for public-target proxy access",
                    StatusCode::UNAUTHORIZED,
                ));
            }
            PublicBypassOutcome::NotApplicable => {}
        }

        match _inner_auth(ep, req).await? {
            Ok(output) => Ok(output.into_response()),
            Err(req) => {
                // Unauthenticated navigation. If the operator has opted into
                // single-provider SSO auto-redirect, jump straight to the IdP
                // authorize URL (preserving the original path) instead of
                // flashing the gateway login SPA. Otherwise fall through to the
                // existing gateway-redirect / 401 behaviour unchanged.
                if let Some(resp) = try_auto_sso_redirect(&req).await? {
                    return Ok(resp);
                }
                Ok(gateway_redirect(&req).into_response())
            }
        }
    })
}

/// Pure decision for the single-provider SSO auto-redirect. Kept side-effect
/// free so every branch can be unit-tested without a `Services` fixture.
///
/// Returns true iff the feature is enabled, exactly one SSO provider is
/// configured, the request is a top-level browser navigation, the break-glass
/// `?login=password` bypass is absent, and the target is not a Warpgate
/// management path.
pub(crate) const fn should_auto_sso_redirect(
    sso_auto_redirect_enabled: bool,
    sso_provider_count: usize,
    is_navigation: bool,
    has_password_bypass: bool,
    is_management_path: bool,
) -> bool {
    sso_auto_redirect_enabled
        && sso_provider_count == 1
        && is_navigation
        && !has_password_bypass
        && !is_management_path
}

/// Break-glass: a `?login=password` query param bypasses the auto-redirect so
/// an operator can always reach the SPA password login.
fn request_has_password_bypass(req: &Request) -> bool {
    req.uri().query().is_some_and(|q| {
        url::form_urlencoded::parse(q.as_bytes()).any(|(k, v)| k == "login" && v == "password")
    })
}

/// On the unauthenticated navigation path, consult the `sso_auto_redirect`
/// parameter + configured SSO providers and, when appropriate, initiate an SSO
/// login and return a 302 to the IdP authorize URL. Returns `Ok(None)` to let
/// the caller fall through to the normal gateway redirect / 401.
///
/// "Navigation" is upstream's [`is_navigation_request`], the same test that
/// decides whether the gateway redirect is a 302 or a 401, so the
/// auto-redirect fires on exactly the requests that would otherwise be sent
/// to the login page.
async fn try_auto_sso_redirect(req: &Request) -> poem::Result<Option<Response>> {
    let ctx = Data::<&UnauthenticatedRequestContext>::from_request_without_body(req).await?;

    let is_navigation = is_navigation_request(req);
    let has_password_bypass = request_has_password_bypass(req);
    let is_management_path = is_warpgate_management_path(req.uri().path());

    // Cheap gates first — avoid the DB read + config lock unless the request
    // could actually be redirected.
    if !is_navigation || has_password_bypass || is_management_path {
        return Ok(None);
    }

    let sso_auto_redirect_enabled = ctx
        .parameters()
        .await
        .map_err(InternalServerError)?
        .sso_auto_redirect;

    // Read the sole provider's name (if exactly one), then drop the config
    // lock before calling the SSO helper, which re-locks it internally.
    let sole_provider = {
        let config = ctx.services().config.lock().await;
        let providers = &config.store.sso_providers;
        if should_auto_sso_redirect(
            sso_auto_redirect_enabled,
            providers.len(),
            is_navigation,
            has_password_bypass,
            is_management_path,
        ) {
            providers.first().map(|p| p.name.clone())
        } else {
            None
        }
    };

    let Some(provider_name) = sole_provider else {
        return Ok(None);
    };

    let session = <&Session>::from_request_without_body(req).await?;
    let next = req.original_uri().path_and_query().map(ToString::to_string);

    match crate::api::sso_provider_detail::start_sso_and_get_auth_url(
        req,
        session,
        ctx.0,
        &provider_name,
        next,
    )
    .await?
    {
        crate::api::sso_provider_detail::StartSsoOutcome::Ok(url) => {
            Ok(Some(Redirect::temporary(url).into_response()))
        }
        // Provider vanished between the count check and the start (race), or the
        // request host is incompatible with the provider's return-URL domain.
        // Fall through to the normal login page rather than erroring.
        _ => Ok(None),
    }
}

/// Result of `try_public_target_bypass`. See [`page_auth`] for how each
/// arm is handled.
enum PublicBypassOutcome {
    /// Public target resolved; route through with a synthetic Ticket auth
    /// context (see [`onto_public_target_session`]) so the catchall sees a
    /// target-scoped session.
    Bypass {
        ctx: UnauthenticatedRequestContext,
        target_id: Uuid,
    },
    /// Public target resolved but the request carries an admin/user/cluster
    /// token — return 401.
    Reject401,
    /// No bypass applies; existing auth flow runs unchanged.
    NotApplicable,
}

/// The username an anonymous public-target request is served under.
const PUBLIC_USERNAME: &str = "<public>";

/// The identity an anonymous public-target request is served under.
/// `Uuid::nil()` and `"<public>"` are reachable through no credential path, so
/// the audit log shows the bypass rather than impersonating a real user.
fn public_session_authorization(target_id: Uuid) -> SessionAuthorization {
    SessionAuthorization::Ticket {
        user_id: Uuid::nil(),
        username: PUBLIC_USERNAME.into(),
        target_id,
        ticket_id: None,
    }
}

/// True for the throwaway session's `<public>` authorization. It only routes
/// an anonymous request to its public target and names no one, so the proxy
/// sends no identity headers for it, as it sent none for an anonymous public
/// request before 0.29.1 (an app must never see `<public>` as a user).
///
/// Recognised by construction, the nil user id no credential path produces,
/// and, failing closed, by the reserved username as well.
pub(crate) fn is_public_session_authorization(auth: &SessionAuthorization) -> bool {
    auth.user_id().is_nil() || auth.username() == PUBLIC_USERNAME
}

/// Moves a public-target request onto a throwaway session that is never
/// stored, the way `TicketMiddleware` treats header-borne tickets.
///
/// The visitor's real cookie session is left untouched, so no cookie is set
/// on a public host and nothing about the bypass outlives the request.
/// Logged-in visitors never come here (see [`onto_public_target_session`]). The
/// `SessionStore` recognises the request by its ticket key and serves every
/// public request for a target from one unstored session per node.
///
/// Never write the synthetic authorization into the real cookie session: the
/// catchall's Ticket arm would keep honouring it after `public` is turned off.
fn onto_throwaway_public_session(mut req: Request, target_id: Uuid) -> Request {
    let throwaway = Session::default();
    throwaway.set_auth(public_session_authorization(target_id));
    req.extensions_mut().insert(throwaway);
    req.set_data(TemporaryTicketSession);
    req
}

/// Picks the session and the target-scoped authorization a public-target
/// request is served under.
///
/// A visitor whose cookie session is logged in as a user keeps that session:
/// the proxied request carries their username, and the target session opens
/// under their own user session. The authorization is a `Ticket` for the
/// target in their name, so the catchall's Ticket arm skips the role check
/// and the target session is stamped with the same user the session already
/// holds. Nothing is written to their session.
///
/// Anyone else (anonymous, or a cookie holding a ticket) is moved onto the
/// throwaway `<public>` session.
fn onto_public_target_session(req: Request, target_id: Uuid) -> (Request, SessionAuthorization) {
    let visitor = req
        .extensions()
        .get::<Session>()
        .and_then(SessionExt::get_auth);
    if let Some(SessionAuthorization::User { user_id, username }) = visitor {
        return (
            req,
            SessionAuthorization::Ticket {
                user_id,
                username,
                target_id,
                ticket_id: None,
            },
        );
    }
    (
        onto_throwaway_public_session(req, target_id),
        public_session_authorization(target_id),
    )
}

/// Inspect the request and decide whether the public-target bypass should
/// fire. On `Bypass`, hands back the target row's id so `page_auth` can build
/// a `Ticket`-style `AuthenticatedRequestContext` pinned to it and the
/// catchall's Ticket arm proxies the request without role checks.
async fn try_public_target_bypass(req: &Request) -> poem::Result<PublicBypassOutcome> {
    // Defence-in-depth: never bypass auth on Warpgate's own management
    // surfaces. `/@warpgate*` and `/_warpgate*` are nested ahead of the
    // catchall so `page_auth` should not see them, but the guard keeps the
    // guarantee from depending on routing order.
    if is_warpgate_management_path(req.uri().path()) {
        return Ok(PublicBypassOutcome::NotApplicable);
    }

    let unauth_ctx = Data::<&UnauthenticatedRequestContext>::from_request_without_body(req).await?;
    let host = unauth_ctx.trusted_host_header(req);

    // If `inject_request_authorization` already attached an
    // `AuthenticatedRequestContext`, use its `auth` so the decision helper
    // sees the real authorization state (tokens get rejected at the bypass
    // instead of silently proxying).
    let auth_ctx = Option::<Data<&AuthenticatedRequestContext>>::from_request_without_body(req)
        .await
        .ok()
        .flatten();
    let auth_ref = auth_ctx.as_deref().map(|c| &c.auth);

    let (resolved, decision) =
        resolve_public_target_decision(unauth_ctx.services(), host.as_deref(), auth_ref).await?;

    match decision {
        PublicTargetDecision::Bypass => {
            // FAIL CLOSED. `resolve_public_target_decision` only ever returns
            // `Bypass` alongside `Some(target)`, so this arm is unreachable
            // today -- but it is reachable in the TYPE, and on the path that
            // decides whether to SKIP AUTHENTICATION, refusing the bypass
            // costs a public visitor one ordinary login prompt, where a panic
            // would be a denial of service.
            let Some((target, _opts)) = resolved else {
                tracing::warn!(
                    "public-target bypass resolved to Bypass with no target; \
                     refusing the bypass and falling through to normal auth"
                );
                return Ok(PublicBypassOutcome::NotApplicable);
            };
            Ok(PublicBypassOutcome::Bypass {
                ctx: unauth_ctx.0.clone(),
                target_id: target.id,
            })
        }
        PublicTargetDecision::Reject401 => Ok(PublicBypassOutcome::Reject401),
        PublicTargetDecision::NotApplicable => Ok(PublicBypassOutcome::NotApplicable),
    }
}

pub fn redirect_navigations(
    req: &Request,
    location: String,
    fallback_status: StatusCode,
) -> Response {
    if !is_navigation_request(req) {
        return Response::builder().status(fallback_status).finish();
    }

    Redirect::temporary(location).into_response()
}

pub fn gateway_redirect(req: &Request) -> Response {
    let path = req
        .original_uri()
        .path_and_query()
        .map_or_else(String::new, ToString::to_string);

    redirect_navigations(
        req,
        format!(
            "/@warpgate#/login?next={}",
            utf8_percent_encode(&path, NON_ALPHANUMERIC),
        ),
        StatusCode::UNAUTHORIZED,
    )
}

pub async fn get_or_create_auth_state_for_request(
    req: &Request,
    username: &str,
    ctx: &UnauthenticatedRequestContext,
    rate_limit_credential_type: Option<&str>,
) -> Result<Arc<Mutex<AuthState>>, WarpgateError> {
    let client_ip = get_client_ip_addr(req, ctx.services()).await;

    if let Some(state) = get_auth_state_for_request(req, ctx).await? {
        let reusable = {
            let state = state.lock().await;
            // A terminally rejected attempt can never accept another
            // credential, so a retry must start a fresh one.
            username_eq_ci(&state.user_info().username, username)
                && !matches!(state.verify(), AuthResult::Rejected)
        };
        if reusable {
            return Ok(state);
        }
    }

    // Pass the browser session id so the auth state is keyed by it: a web
    // approval landing on another node resolves the owner from the session's
    // `node_id` in the DB (see `api::auth::auth_state_owner`).
    let session_id = session_id_for_request(req, ctx).await?;

    let state = ctx
        .services()
        .create_auth_state(
            &session_id,
            username,
            crate::common::PROTOCOL_NAME,
            "",
            &[
                CredentialKind::Password,
                CredentialKind::Sso,
                CredentialKind::Totp,
            ],
            client_ip,
            rate_limit_credential_type,
        )
        .await?;

    Ok(state)
}

/// The login attempt in progress on this browser session, if any. Auth states
/// are keyed by session id, so the session itself is the lookup key and there is
/// nothing to keep in sync.
pub async fn get_auth_state_for_request(
    req: &Request,
    ctx: &UnauthenticatedRequestContext,
) -> Result<Option<Arc<Mutex<AuthState>>>, WarpgateError> {
    let session = <&Session>::from_request_without_body(req)
        .await
        .context("Session not in request")?;

    let Some(session_id) = session.get_session_id() else {
        return Ok(None);
    };

    Ok(ctx
        .services()
        .auth_state_store
        .lock()
        .await
        .get(&session_id))
}

pub async fn session_id_for_request(
    req: &Request,
    ctx: &UnauthenticatedRequestContext,
) -> Result<UserSessionId, WarpgateError> {
    let session_middleware = Data::<&Arc<Mutex<SessionStore>>>::from_request_without_body(req)
        .await
        .context("SessionStore not in request")?;

    let server_handle = session_middleware
        .lock()
        .await
        .handle_for_request(req, ctx)
        .await
        .context("creating session handle")?;

    Ok(server_handle.lock().await.user_session_id())
}

pub async fn authorize_session(
    req: &Request,
    ctx: &UnauthenticatedRequestContext,
    user_info: AuthStateUserInfo,
) -> Result<(), WarpgateError> {
    let session_middleware = Data::<&Arc<Mutex<SessionStore>>>::from_request_without_body(req)
        .await
        .context("SessionStore not in request")?;
    let session = <&Session>::from_request_without_body(req)
        .await
        .context("Session not in request")?;

    let mut server_handle = session_middleware
        .lock()
        .await
        .handle_for_request(req, ctx)
        .await
        .context("resolving session handle")?;

    // session user cannot be switched, so a second attempt should kill
    // thi session and init a new one
    let attributed = server_handle
        .lock()
        .await
        .set_user_info(user_info.clone())
        .await;
    match attributed {
        Ok(()) => {}
        Err(WarpgateError::UserSessionAlreadyAttributed) => {
            let old_id = server_handle.lock().await.user_session_id();
            {
                let mut store = session_middleware.lock().await;
                store.remove_session(session);
            }
            ctx.services()
                .state
                .lock()
                .await
                .remove_session(old_id)
                .await;
            session.clear();
            server_handle = session_middleware
                .lock()
                .await
                .handle_for_request(req, ctx)
                .await
                .context("registering replacement session")?;
            server_handle
                .lock()
                .await
                .set_user_info(user_info.clone())
                .await?;
        }
        Err(error) => return Err(error),
    }

    // when auth is completed, we must rotate the cookie *on the first hop*
    // since cookies set by a forwarded request are not passed back to the client
    if !warpgate_common_http::is_cluster_peer_request(req, &ctx.services().cluster.cluster_token) {
        // we are the first hop

        let jar = <&CookieJar>::from_request_without_body(req)
            .await
            .context("CookieJar not in request")?;
        Data::<&SharedSessionStorage>::from_request_without_body(req)
            .await
            .context("SharedSessionStorage not in request")?
            .rotate_session_id(storage_session_id(jar), session)
            .await?;
    }

    session.set_auth(SessionAuthorization::User {
        user_id: user_info.id,
        username: user_info.username,
    });
    warpgate_common_http::auth::stamp_session_auth_time(session);

    Ok(())
}

/// Authorization for a request authenticated by the cluster token. The proxying
/// node forwards the acting user's id in `x-warpgate-cluster-identity` (see
/// `cluster_proxy::proxy_or_serve`), so the request runs here as that user;
/// without the header the peer acts as a bare cluster peer. An id that no
/// longer resolves to a user fails closed (unauthenticated).
async fn cluster_request_authorization(
    ctx: &UnauthenticatedRequestContext,
    req: &Request,
) -> poem::Result<Option<RequestAuthorization>> {
    let Some(header) = req.headers().get(&X_WARPGATE_CLUSTER_IDENTITY) else {
        return Ok(Some(RequestAuthorization::ClusterToken));
    };
    let Some(user_id) = header.to_str().ok().and_then(|s| s.parse::<Uuid>().ok()) else {
        return Ok(None);
    };
    Ok(User::Entity::find_by_id(user_id)
        .one(&ctx.services().db)
        .await
        .map_err(poem::error::InternalServerError)?
        .map(|user| {
            RequestAuthorization::Session(SessionAuthorization::User {
                user_id: user.id,
                username: user.username,
            })
        }))
}

/// Resolves an API token to its user, applying the same account-status checks a
/// login goes through. `None` for an unknown token or for a user who may not
/// authenticate right now — the caller can't tell the two apart, by design.
async fn user_for_api_token(
    req: &Request,
    ctx: &UnauthenticatedRequestContext,
    token: &str,
) -> Result<Option<warpgate_common::User>, WarpgateError> {
    let services = ctx.services();
    let remote_ip = get_client_ip_addr(req, services).await;

    // Checked ahead of the lookup so a blocked caller can't use this as a
    // token-existence oracle.
    if let Some(ip) = remote_ip
        && services
            .login_protection
            .check_ip_blocked(&ip)
            .await?
            .is_some()
    {
        tracing::warn!("API token presented from a blocked IP: {ip}");
        return Ok(None);
    }

    let Some(user) = services.config_provider.validate_api_token(token).await? else {
        return Ok(None);
    };

    if !vet_credential_bearer(&services.login_protection, &user, remote_ip).await? {
        return Ok(None);
    }

    Ok(Some(user))
}

pub async fn inject_request_authorization<E: Endpoint + 'static>(
    ep: Arc<E>,
    req: Request,
) -> poem::Result<E::Output> {
    // Reinject a per-request copy so the parameter cache is request-scoped
    // rather than shared with the startup singleton.
    let ctx = Data::<&UnauthenticatedRequestContext>::from_request_without_body(&req)
        .await?
        .for_request();
    let session = <&Session>::from_request_without_body(&req).await?;
    let is_cluster_peer = is_cluster_peer_request(&req, &ctx.services().cluster.cluster_token);

    let mut session_auth = session.get_auth();
    // A forwarded request's Host is the cluster SNI name by construction, so the
    // origin check below would reject - and clear - a session that is fine.
    if session_auth.is_some() && !is_cluster_peer {
        // Host binding only means something when `external_host` pins an
        // origin. Without it the external URL is derived from Host header
        let base_host = {
            let config = ctx.services().config.lock().await;
            construct_external_url(None, &config, None)
                .await
                .ok()
                .and_then(|url| url.host_str().map(str::to_owned))
        };
        if let Some(base_host) = base_host {
            let request_host = ctx.trusted_hostname(&req);
            if !session_host_is_authorized(request_host.as_deref(), &base_host) {
                tracing::warn!(
                    "Session cookie rejected: request host {:?} is not authorized (base host: '{}'). Clearing session.",
                    request_host,
                    base_host
                );
                session.clear();
                session_auth = None;
            }
        }
    }

    let auth = if let Some(auth) = session_auth {
        Some(RequestAuthorization::Session(auth))
    } else if is_cluster_peer {
        cluster_request_authorization(&ctx, &req).await?
    } else if let Some(token_from_header) = req.headers().get(&X_WARPGATE_TOKEN) {
        let token_from_header = token_from_header
            .to_str()
            .map_err(poem::error::BadRequest)?;
        if (*ctx.services().admin_token)
            .as_ref()
            .is_some_and(|admin_token| {
                // Use constant time comparison to prevent timing attacks
                admin_token
                    .expose_secret()
                    .as_bytes()
                    .ct_eq(token_from_header.as_bytes())
                    .into()
            })
        {
            Some(RequestAuthorization::AdminToken)
        } else if let Some(user) = user_for_api_token(&req, &ctx, token_from_header).await? {
            Some(RequestAuthorization::UserToken {
                user_id: user.id,
                username: user.username,
            })
        } else {
            None
        }
    } else {
        None
    };

    if let Some(auth) = auth {
        // build context and attach it instead of raw authorization
        let actx = ctx.to_authenticated(auth);
        assert_mfa_setup_gate(&actx, &req, session).await?;
        Ok(ep.data(actx).data(ctx).call(req).await?)
    } else {
        Ok(ep.data(ctx).call(req).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        StatusCode, gateway_redirect, host_is_subdomain_of_or_equal, request_has_password_bypass,
        should_auto_sso_redirect,
    };
    use warpgate_common_http::ext::is_navigation_request;

    const BROWSER_ACCEPT: &str = "text/html,application/xhtml+xml,*/*;q=0.8";

    #[test]
    fn gateway_redirect_navigation_redirects_to_login() {
        for mode in [None, Some("navigate")] {
            let mut req = poem::Request::builder()
                .uri_str("/api/data")
                .header("accept", BROWSER_ACCEPT);
            if let Some(mode) = mode {
                req = req.header("sec-fetch-mode", mode);
            }
            let resp = gateway_redirect(&req.finish());
            assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
            let location = resp
                .headers()
                .get(http::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default();
            assert!(location.starts_with("/@warpgate#/login"));
        }
    }

    #[test]
    fn auto_sso_redirect_happy_path() {
        // Enabled, exactly one provider, a navigation, no bypass, not a
        // management path → redirect.
        assert!(should_auto_sso_redirect(true, 1, true, false, false));
    }

    #[test]
    fn auto_sso_redirect_disabled_by_default() {
        // Feature off → never redirect regardless of other inputs.
        assert!(!should_auto_sso_redirect(false, 1, true, false, false));
    }

    #[test]
    fn auto_sso_redirect_requires_exactly_one_provider() {
        // Zero providers → nothing to redirect to.
        assert!(!should_auto_sso_redirect(true, 0, true, false, false));
        // Multiple providers → user must choose, keep the SPA.
        assert!(!should_auto_sso_redirect(true, 2, true, false, false));
    }

    #[test]
    fn auto_sso_redirect_only_on_navigation() {
        // Non-navigation (fetch/XHR) must not be hijacked into a 302.
        assert!(!should_auto_sso_redirect(true, 1, false, false, false));
    }

    #[test]
    fn auto_sso_redirect_break_glass_bypass() {
        // ?login=password forces the SPA login even when otherwise eligible.
        assert!(!should_auto_sso_redirect(true, 1, true, true, false));
    }

    #[test]
    fn auto_sso_redirect_skips_management_paths() {
        // Warpgate's own admin/gateway surfaces are never auto-redirected.
        assert!(!should_auto_sso_redirect(true, 1, true, false, true));
    }

    /// The auto-redirect's notion of a navigation is upstream's, the same one
    /// `gateway_redirect` uses: a browser page load (HTML accepted, and either
    /// no `sec-fetch-mode` or `navigate`) is one; a fetch, or a client that
    /// does not ask for HTML, is not, and gets the 401 instead.
    #[test]
    fn request_is_navigation_matches_gateway_redirect_heuristic() {
        for mode in [None, Some("navigate")] {
            let mut req = poem::Request::builder()
                .uri_str("/foo")
                .header("accept", BROWSER_ACCEPT);
            if let Some(mode) = mode {
                req = req.header("sec-fetch-mode", mode);
            }
            let req = req.finish();
            assert!(is_navigation_request(&req));
            assert_eq!(
                gateway_redirect(&req).status(),
                StatusCode::TEMPORARY_REDIRECT
            );
        }
        for mode in ["cors", "same-origin", "no-cors"] {
            let req = poem::Request::builder()
                .uri_str("/foo")
                .header("accept", BROWSER_ACCEPT)
                .header("sec-fetch-mode", mode)
                .finish();
            assert!(!is_navigation_request(&req));
            assert_eq!(gateway_redirect(&req).status(), StatusCode::UNAUTHORIZED);
        }
        // No HTML accepted (curl, API clients) → not a navigation.
        let req = poem::Request::builder().uri_str("/foo").finish();
        assert!(!is_navigation_request(&req));
        assert_eq!(gateway_redirect(&req).status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn request_has_password_bypass_detects_query() {
        let req = poem::Request::builder()
            .uri_str("/foo?login=password")
            .finish();
        assert!(request_has_password_bypass(&req));
        // Alongside other params.
        let req = poem::Request::builder()
            .uri_str("/foo?next=%2Fbar&login=password")
            .finish();
        assert!(request_has_password_bypass(&req));
        // Absent / different value.
        let req = poem::Request::builder().uri_str("/foo").finish();
        assert!(!request_has_password_bypass(&req));
        let req = poem::Request::builder().uri_str("/foo?login=sso").finish();
        assert!(!request_has_password_bypass(&req));
    }

    #[test]
    fn gateway_redirect_fetch_gets_401() {
        // https://github.com/warp-tech/warpgate/issues/1989
        let cases = [
            (None, None),
            (Some("*/*"), None),
            (Some("application/json"), Some("cors")),
            (Some(BROWSER_ACCEPT), Some("cors")),
            (Some(BROWSER_ACCEPT), Some("same-origin")),
            (Some(BROWSER_ACCEPT), Some("no-cors")),
        ];
        for (accept, mode) in cases {
            let mut req = poem::Request::builder().uri_str("/api/data");
            if let Some(accept) = accept {
                req = req.header("accept", accept);
            }
            if let Some(mode) = mode {
                req = req.header("sec-fetch-mode", mode);
            }
            let resp = gateway_redirect(&req.finish());
            assert_eq!(
                resp.status(),
                StatusCode::UNAUTHORIZED,
                "{accept:?} {mode:?}"
            );
        }
    }

    #[test]
    fn session_host_check_fails_closed() {
        use super::session_host_is_authorized;

        assert!(session_host_is_authorized(
            Some("example.com"),
            "example.com"
        ));
        assert!(session_host_is_authorized(
            Some("app.example.com"),
            "example.com"
        ));
        assert!(session_host_is_authorized(Some("localhost"), "example.com"));
        assert!(!session_host_is_authorized(
            Some("evil-example.com"),
            "example.com"
        ));
        assert!(session_host_is_authorized(Some("localhost"), "localhost"));
        // The localhost exception is for developing against a real deployment,
        // not a blanket pass when the deployment itself is localhost.
        assert!(!session_host_is_authorized(Some("127.0.0.5"), "localhost"));
        // A host that cannot be determined proves nothing.
        assert!(!session_host_is_authorized(None, "example.com"));
    }

    #[test]
    fn test_host_is_subdomain_of_or_equal() {
        assert!(host_is_subdomain_of_or_equal("example.com", "example.com"));
        assert!(host_is_subdomain_of_or_equal(
            "foo.example.com",
            "example.com"
        ));
        assert!(host_is_subdomain_of_or_equal(
            "foo.example.com",
            ".example.com"
        ));
        assert!(!host_is_subdomain_of_or_equal(
            "evil-example.com",
            "example.com"
        ));
    }
}

#[cfg(test)]
mod public_session_tests {
    //! The public-target bypass: an anonymous visitor runs on a throwaway
    //! `<public>` session whose writes never reach a cookie, so a browser
    //! keeps working across requests, and goes upstream with no identity
    //! headers; a logged-in visitor is proxied as themselves, on their own
    //! session, and keeps their login.
    use poem::session::{CookieConfig, MemoryStorage, ServerSession, Session};
    use poem::test::{TestClient, TestResponse};
    use poem::web::{Data, Path};
    use poem::{Endpoint, EndpointExt, Request, Route, get, handler};
    use uuid::Uuid;
    use warpgate_common_http::SessionAuthorization;

    use super::{SessionExt, onto_public_target_session, public_session_authorization};
    use crate::middleware::ticket::ticket_session_key;
    use crate::proxy::upstream_headers_for_test;

    const TARGET: Uuid = Uuid::from_u128(7);
    const VISITS_KEY: &str = "test_visits";

    fn user_id_of(name: &str) -> Uuid {
        match name {
            "alice" => Uuid::from_u128(1),
            "bob" => Uuid::from_u128(2),
            _ => Uuid::from_u128(99),
        }
    }

    #[handler]
    fn login(Path(name): Path<String>, session: &Session) -> &'static str {
        session.set_auth(SessionAuthorization::User {
            user_id: user_id_of(&name),
            username: name,
        });
        "logged in"
    }

    #[handler]
    fn whoami(session: &Session) -> String {
        match session.get_auth() {
            Some(SessionAuthorization::User { username, .. }) => username,
            _ => "nobody".into(),
        }
    }

    /// Stands in for the catchall: it writes to the session it is handed, as
    /// the catchall does, and reports the identity headers the proxy sends
    /// upstream (`user/type`, `-` when absent), which user session the target
    /// session opens under, and how many times that session has served this
    /// target.
    #[handler]
    async fn proxied(
        req: &Request,
        session: &Session,
        ctx_auth: Data<&SessionAuthorization>,
    ) -> String {
        session.set_target_name("public-target".into());
        let visits = session.get::<u32>(VISITS_KEY).unwrap_or(0) + 1;
        session.set(VISITS_KEY, visits);

        let headers = upstream_headers_for_test(req).await;
        let header = |name: &str| {
            headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("-")
                .to_owned()
        };
        let upstream = format!(
            "{}/{}",
            header("x-warpgate-username"),
            header("x-warpgate-authentication-type")
        );

        // The catchall resolves the target by the ticket's target id, without
        // a role check.
        let SessionAuthorization::Ticket {
            user_id,
            username,
            target_id,
            ticket_id: None,
        } = ctx_auth.0
        else {
            return format!("not a target-scoped ticket: {:?}", ctx_auth.0);
        };
        if *target_id != TARGET {
            return format!("wrong target: {target_id}");
        }

        // The session store keys a temporary ticket session by its ticket,
        // anything else by the cookie; `start_target_session` then refuses a
        // target authorization whose user is not the session's user.
        let session_owner = match ticket_session_key(req, session) {
            Some((key_user, key_target, None))
                if key_user.is_nil() && key_target == TARGET && user_id.is_nil() =>
            {
                "the shared public session".to_owned()
            }
            None => match session.get_auth() {
                Some(SessionAuthorization::User {
                    user_id: session_user,
                    username: session_name,
                }) if session_user == *user_id && session_name == *username => {
                    format!("{session_name}'s own session")
                }
                other => format!("a session that is not the ticket's user: {other:?}"),
            },
            other => format!("wrong session key: {other:?}"),
        };
        format!("{upstream} on {session_owner}, visit {visits}")
    }

    fn app() -> impl Endpoint {
        Route::new()
            .at("/login/:name", get(login))
            .at("/whoami", get(whoami))
            .at(
                "/public",
                get(proxied.around(|ep, req| async move {
                    let (req, auth) = onto_public_target_session(req, TARGET);
                    ep.data(auth).call(req).await
                })),
            )
            .with(ServerSession::new(
                CookieConfig::default(),
                MemoryStorage::new(),
            ))
    }

    fn cookie_pair(resp: &TestResponse) -> Option<String> {
        resp.0
            .headers()
            .get("set-cookie")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map(ToOwned::to_owned)
    }

    async fn log_in(cli: &TestClient<impl Endpoint>, name: &str) -> String {
        let resp = cli.get(format!("/login/{name}")).send().await;
        resp.assert_status_is_ok();
        cookie_pair(&resp).expect("the login sets a cookie")
    }

    /// One visit to the public target on `cookie`, asserting it keeps that
    /// same browser session.
    async fn visit(cli: &TestClient<impl Endpoint>, cookie: &str, expected: &str) {
        let resp = cli.get("/public").header("cookie", cookie).send().await;
        resp.assert_status_is_ok();
        // The catchall's write to the visitor's own session may re-send the
        // cookie; it must still be the same session.
        if let Some(reissued) = cookie_pair(&resp) {
            assert_eq!(reissued, cookie, "the visitor's session was replaced");
        }
        resp.assert_text(expected).await;
    }

    /// Two anonymous requests to a public target both succeed and neither
    /// issues a cookie (0.28.6's synthetic ticket in the real cookie got a
    /// 401 on the second request under 0.29.1's session model), and neither
    /// carries an identity header upstream.
    #[tokio::test]
    async fn anonymous_public_requests_succeed_twice_without_a_cookie_or_identity() {
        let cli = TestClient::new(app());
        for _ in 0..2 {
            let resp = cli.get("/public").send().await;
            resp.assert_status_is_ok();
            resp.assert_header_is_not_exist("set-cookie");
            resp.assert_text("-/- on the shared public session, visit 1")
                .await;
        }
    }

    /// A logged-in visitor reaches a public target on the same cookie, twice,
    /// proxied under their own username on their own session (not the
    /// shared `<public>` one), and still has their own login afterwards.
    #[tokio::test]
    async fn a_logged_in_visitor_reaches_a_public_target_as_themselves() {
        let cli = TestClient::new(app());
        let cookie = log_in(&cli, "alice").await;

        visit(&cli, &cookie, "alice/user on alice's own session, visit 1").await;
        visit(&cli, &cookie, "alice/user on alice's own session, visit 2").await;

        cli.get("/whoami")
            .header("cookie", cookie)
            .send()
            .await
            .assert_text("alice")
            .await;
    }

    /// Two different users on the same public target, interleaved, each go
    /// upstream as themselves on their own session: nothing one user's
    /// visits leave behind is served to the other.
    #[tokio::test]
    async fn two_logged_in_visitors_each_keep_their_own_identity_and_session() {
        let cli = TestClient::new(app());
        let alice = log_in(&cli, "alice").await;
        let bob = log_in(&cli, "bob").await;
        assert_ne!(alice, bob);

        visit(&cli, &alice, "alice/user on alice's own session, visit 1").await;
        visit(&cli, &bob, "bob/user on bob's own session, visit 1").await;
        visit(&cli, &alice, "alice/user on alice's own session, visit 2").await;
        visit(&cli, &bob, "bob/user on bob's own session, visit 2").await;
    }

    async fn identity_headers(auth: &SessionAuthorization) -> (Option<String>, Option<String>) {
        let session = Session::default();
        session.set_auth(auth.clone());
        let mut req = Request::builder().finish();
        req.extensions_mut().insert(session);
        let headers = upstream_headers_for_test(&req).await;
        let header = |name: &str| {
            headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned)
        };
        (
            header("x-warpgate-username"),
            header("x-warpgate-authentication-type"),
        )
    }

    /// The public session is recognised by construction (a ticket for the
    /// nil user, whatever its name) and by its reserved name (whatever the
    /// id): neither sends an identity header upstream.
    #[tokio::test]
    async fn the_public_session_sends_no_identity_headers() {
        for auth in [
            public_session_authorization(TARGET),
            SessionAuthorization::Ticket {
                user_id: Uuid::nil(),
                username: "someone".into(),
                target_id: TARGET,
                ticket_id: None,
            },
            SessionAuthorization::Ticket {
                user_id: user_id_of("alice"),
                username: "<public>".into(),
                target_id: TARGET,
                ticket_id: None,
            },
        ] {
            assert_eq!(identity_headers(&auth).await, (None, None), "{auth:?}");
        }
    }

    fn header_values(headers: &http::HeaderMap, name: &str) -> Vec<String> {
        headers
            .get_all(name)
            .iter()
            .map(|value| value.to_str().unwrap().to_owned())
            .collect()
    }

    fn warpgate_headers(headers: &http::HeaderMap) -> Vec<String> {
        headers
            .keys()
            .map(|name| name.as_str().to_owned())
            .filter(|name| name.starts_with("x-warpgate-"))
            .collect()
    }

    /// A public-target request carrying `headers` from the caller, on a
    /// browser session holding `logged_in` (none for an anonymous visitor): what
    /// the upstream receives, after the bypass and the proxy's own headers.
    async fn upstream_for(
        logged_in: Option<SessionAuthorization>,
        headers: &[(&str, &str)],
    ) -> http::HeaderMap {
        let mut builder = Request::builder();
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let mut req = builder.finish();
        // Positive control: the caller's headers really are on the request
        // (poem's builder silently drops a header it cannot parse).
        assert_eq!(req.headers().len(), headers.len(), "{headers:?}");
        let session = Session::default();
        if let Some(auth) = logged_in {
            session.set_auth(auth);
        }
        req.extensions_mut().insert(session);

        let (req, _) = onto_public_target_session(req, TARGET);
        upstream_headers_for_test(&req).await
    }

    /// An anonymous caller who sends their own `x-warpgate-username`, in any
    /// letter case, twice, or as a list, reaches the upstream with no
    /// identity header at all.
    #[tokio::test]
    async fn an_anonymous_caller_cannot_claim_a_username_upstream() {
        for headers in [
            &[("X-Warpgate-Username", "jeremy")][..],
            &[("x-WARPGATE-username", "jeremy")],
            &[
                ("X-Warpgate-Username", "jeremy"),
                ("x-warpgate-username", "admin"),
            ],
            &[("X-Warpgate-Username", "jeremy, admin")],
        ] {
            let upstream = upstream_for(None, headers).await;
            assert_eq!(
                warpgate_headers(&upstream),
                Vec::<String>::new(),
                "{headers:?}"
            );
        }
    }

    /// The same for `x-warpgate-authentication-type`, alone and alongside a
    /// claimed username.
    #[tokio::test]
    async fn an_anonymous_caller_cannot_claim_an_authentication_type_upstream() {
        for headers in [
            &[("X-Warpgate-Authentication-Type", "user")][..],
            &[("x-WARPGATE-authentication-TYPE", "user")],
            &[
                ("X-Warpgate-Authentication-Type", "user"),
                ("x-warpgate-authentication-type", "ticket"),
            ],
            &[("X-Warpgate-Authentication-Type", "user, ticket")],
            &[
                ("X-Warpgate-Username", "jeremy"),
                ("X-Warpgate-Authentication-Type", "user"),
            ],
        ] {
            let upstream = upstream_for(None, headers).await;
            assert_eq!(
                warpgate_headers(&upstream),
                Vec::<String>::new(),
                "{headers:?}"
            );
        }
    }

    /// A logged-in visitor who sends someone else's name reaches the upstream
    /// as themselves, once: the claimed name and type are dropped, not
    /// appended next to the real ones.
    #[tokio::test]
    async fn a_logged_in_caller_cannot_claim_another_username_upstream() {
        let alice = SessionAuthorization::User {
            user_id: user_id_of("alice"),
            username: "alice".into(),
        };
        let upstream = upstream_for(
            Some(alice),
            &[
                ("X-Warpgate-Username", "bob"),
                ("x-WARPGATE-username", "jeremy"),
                ("X-Warpgate-Authentication-Type", "ticket"),
            ],
        )
        .await;
        assert_eq!(header_values(&upstream, "x-warpgate-username"), ["alice"]);
        assert_eq!(
            header_values(&upstream, "x-warpgate-authentication-type"),
            ["user"]
        );
    }

    /// A real user or a real ticket still goes upstream under its name.
    #[tokio::test]
    async fn a_real_user_or_ticket_still_sends_identity_headers() {
        let user = SessionAuthorization::User {
            user_id: user_id_of("alice"),
            username: "alice".into(),
        };
        let ticket = SessionAuthorization::Ticket {
            user_id: user_id_of("bob"),
            username: "bob".into(),
            target_id: TARGET,
            ticket_id: Some(Uuid::from_u128(3)),
        };
        assert_eq!(
            identity_headers(&user).await,
            (Some("alice".into()), Some("user".into()))
        );
        assert_eq!(
            identity_headers(&ticket).await,
            (Some("bob".into()), Some("ticket".into()))
        );
    }
}
