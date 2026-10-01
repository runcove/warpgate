use poem::session::Session;
use poem::web::websocket::WebSocket;
use poem::{Endpoint, EndpointExt, FromRequest, IntoResponse, Response};
use sea_orm::{DatabaseConnection, EntityTrait};
use tokio::sync::Mutex;
use tracing::{error, info};
use uuid::Uuid;
use warpgate_admin::api::cluster_proxy::{Owner, forward_websocket};
use warpgate_common::{Protocol, TargetOptions, UserSessionId, WarpgateError};
use warpgate_common_http::auth::{
    AuthenticatedRequestContext, FullUserAuthorization, web_reauth_required,
};
use warpgate_core::{ConfigProvider, TargetAuthorization, authorize_for_target};
use warpgate_db_entities as entities;

use crate::common::SessionExt;
use crate::session::SessionStore;

pub fn emit_unknown_authentication_failed_event(
    session_id: UserSessionId,
    remote_ip: Option<std::net::IpAddr>,
    username: &str,
    credentials: &str,
    reason: &str,
) {
    let client_ip = remote_ip.map_or_else(|| "<unknown>".to_string(), |x| x.to_string());

    info!(
        target: "audit",
        _type = "UserAuthenticationFailed1",
        session = %session_id,
        client_ip = %client_ip,
        username = %username,
        credentials = %credentials,
        reason = %reason,
        "Authentication failed",
    );
}

/// Logs the browser session out: ends its login, then purges it, so the
/// session middleware deletes the stored browser session and clears the
/// cookie.
///
/// This fails closed unless every database write fails. If ending the login
/// fails, deleting the stored browser session ends it too when that was its
/// last backing. If the deletion fails, the response is an error and the
/// browser keeps its cookie, but the login is already ended.
pub async fn logout(
    session: &Session,
    session_middleware: &Mutex<SessionStore>,
    db: &DatabaseConnection,
) {
    end_login(session, session_middleware, db).await;
    session.purge();
    info!("Logout requested");
}

/// Ends the browser session's login and detaches it from this node, leaving
/// the browser session's own contents to the caller.
///
/// The login is ended first, in its own transaction. Once it is ended, no
/// node accepts a cookie that still carries its authorization
/// (`SessionStore::handle_for_request`), and a request still in flight cannot
/// write the authorization back (`SharedSessionStorage::update_session`).
/// The store is locked only to detach the session, not while waiting for the
/// database.
pub async fn end_login(
    session: &Session,
    session_middleware: &Mutex<SessionStore>,
    db: &DatabaseConnection,
) {
    if let Some(id) = session.get_session_id()
        && let Err(error) =
            entities::UserSession::mark_ended_including_target_sessions(db, id).await
    {
        error!(%error, %id, "Could not end the user session at logout");
    }
    session_middleware.lock().await.remove_session(session);
}

/// Outcome of the checks that guard the in-browser clients. Each endpoint maps
/// it onto its own `ApiResponse` enum.
pub enum WebClientTargetAccess {
    Authorized(TargetAuthorization),
    ReauthRequired,
    Forbidden,
    NotFound,
}

/// Gate for the in-browser SSH and desktop clients: a recent enough web login,
/// the global switch, and the user's authorization for the requested target.
pub async fn authorize_web_client_target(
    ctx: &AuthenticatedRequestContext,
    session: &Session,
    target_id: Uuid,
) -> poem::Result<WebClientTargetAccess> {
    // A ticket is authorized for exactly one target; it must not be able to open
    // an in-browser client to any target the *user* can reach. Requiring a
    // full-user proof keeps this endpoint off the ticket path entirely.
    let Some(full) = ctx.auth.as_full_user() else {
        return Ok(WebClientTargetAccess::Forbidden);
    };

    if web_reauth_required(ctx, session).await? {
        return Ok(WebClientTargetAccess::ReauthRequired);
    }

    if !ctx.parameters().await?.web_clients_enabled {
        return Ok(WebClientTargetAccess::Forbidden);
    }

    let config_provider = ctx.services().config_provider.as_ref();
    let Some(target) = config_provider.get_target_by_id(target_id).await? else {
        return Ok(WebClientTargetAccess::NotFound);
    };

    let Some(protocol) = web_client_protocol(&target.options) else {
        return Ok(WebClientTargetAccess::NotFound);
    };

    let identity = full.identity(protocol);

    Ok(authorize_for_target(config_provider, &identity, target)
        .await?
        .map_or(
            WebClientTargetAccess::Forbidden,
            WebClientTargetAccess::Authorized,
        ))
}

/// only the protocols that can be proxied through a web client (SSH, RDP, VNC)
const fn web_client_protocol(options: &TargetOptions) -> Option<Protocol> {
    match options {
        TargetOptions::Ssh(_) => Some(Protocol::Ssh),
        TargetOptions::Vnc(_) => Some(Protocol::Vnc),
        TargetOptions::Rdp(_) => Some(Protocol::Rdp),
        _ => None,
    }
}

/// Resolves the model for the authenticated account. Takes a
/// [`FullUserAuthorization`] rather than a raw `RequestAuthorization` so a
/// target-scoped ticket cannot be resolved to a full account here — the callers
/// that manage credentials and tokens all route through this.
///
/// Keyed by id, not username: a username is reusable, so a session issued to a
/// since-deleted account must not resolve to a new account carrying the same name.
pub async fn get_user(
    auth: &FullUserAuthorization,
    db: &DatabaseConnection,
) -> Result<Option<entities::User::Model>, WarpgateError> {
    Ok(entities::User::Entity::find_by_id(auth.user_id())
        .one(db)
        .await?)
}

/// The node holding a web-client session's live state. Web-client sessions
/// are direct-protocol user sessions, so the session id is the user-session
/// id and its row records the owning node. A missing or ended row resolves
/// `Local`, where the manager lookup then reports not-found.
pub async fn web_client_session_owner(
    ctx: &AuthenticatedRequestContext,
    session_id: UserSessionId,
) -> poem::Result<Owner> {
    let Some(row) = entities::UserSession::Entity::find_by_id(session_id)
        .one(&ctx.services().db)
        .await
        .map_err(WarpgateError::from)?
        .filter(|row| row.ended.is_none())
    else {
        return Ok(Owner::Local);
    };
    Ok(ctx.services().cluster.owner(row.node_id).await?)
}

/// Wraps a web-client websocket endpoint (`:session_id` in its path) with
/// session-owner forwarding: a stream request landing on a node that does not
/// hold the session's live state is forwarded to the node that does.
pub fn forward_ws_to_session_owner<E: Endpoint + 'static>(
    ep: E,
) -> impl Endpoint<Output = Response> {
    ep.around(|ep, req| async move {
        let Some(ctx) = req.data::<AuthenticatedRequestContext>().cloned() else {
            return ep.call(req).await.map(IntoResponse::into_response);
        };
        let session_id = req
            .raw_path_param("session_id")
            .and_then(|raw| raw.parse::<Uuid>().ok())
            .map(UserSessionId);
        let Some(session_id) = session_id else {
            return ep.call(req).await.map(IntoResponse::into_response);
        };
        match web_client_session_owner(&ctx, session_id).await? {
            Owner::Local => ep.call(req).await.map(IntoResponse::into_response),
            Owner::Remote(remote) => {
                let ws = WebSocket::from_request_without_body(&req).await?;
                forward_websocket(&ctx, &req, ws, remote).await
            }
        }
    })
}

#[cfg(test)]
mod logout_tests {
    //! Logging out ends the login everywhere: at once, against a request
    //! still in flight, when the database is briefly busy, when the IdP's
    //! single logout cannot run, and at the SSO step-up's forced logout.
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::Duration;

    use poem::session::{ServerSession, SessionStorage};
    use poem::test::{TestClient, TestResponse};
    use poem::web::Data;
    use poem::{Endpoint, EndpointExt, Request, Route, get, handler};
    use poem_openapi::OpenApiService;
    use sea_orm::ActiveValue::Set;
    use time::OffsetDateTime;
    use warpgate_common::StepUpIntervalConfig;
    use warpgate_common::auth::AuthStateUserInfo;
    use warpgate_common_http::auth::UnauthenticatedRequestContext;
    use warpgate_common_http::{RequestAuthorization, SessionAuthorization};
    use warpgate_core::Services;
    use warpgate_db_entities::{HttpSession, UserSession};
    use warpgate_sso::WarpgateIdToken;

    use super::*;
    use crate::common::{SESSION_COOKIE_NAME, SsoLoginState, session_cookie_config};
    use crate::session_storage::SharedSessionStorage;
    use crate::test_db::{file_db, hold_write_lock, memory_db, services};

    const ALICE: Uuid = Uuid::from_u128(1);
    const LOGOUT: &str = "/api/auth/logout";

    /// Logs the browser session in as alice, the way a completed login
    /// leaves it: a user session attributed to her, and her authorization.
    #[handler]
    async fn log_in(
        req: &Request,
        session: &Session,
        store: Data<&Arc<Mutex<SessionStore>>>,
        ctx: Data<&UnauthenticatedRequestContext>,
    ) -> poem::Result<String> {
        let handle = store.lock().await.handle_for_request(req, ctx.0).await?;
        handle
            .lock()
            .await
            .set_user_info(AuthStateUserInfo {
                id: ALICE,
                username: "alice".into(),
            })
            .await?;
        session.set_auth(SessionAuthorization::User {
            user_id: ALICE,
            username: "alice".into(),
        });
        let id = handle.lock().await.user_session_id();
        Ok(id.0.to_string())
    }

    /// Who the cookie is logged in as.
    #[handler]
    fn whoami(session: &Session) -> String {
        session
            .get_auth()
            .map_or_else(|| "nobody".into(), |auth| auth.username().to_owned())
    }

    /// Marks the browser session as an SSO login through `provider`, with an
    /// unsigned ID token: nothing on the logout path verifies it.
    #[handler]
    fn seed_sso_login(session: &Session) {
        let segment = |json: &str| data_encoding::BASE64URL_NOPAD.encode(json.as_bytes());
        let token = format!(
            "{}.{}.{}",
            segment(r#"{"alg":"RS256"}"#),
            segment(
                r#"{"iss":"https://idp.invalid","aud":["warpgate"],"exp":4102444800,"iat":1700000000,"sub":"alice"}"#
            ),
            segment("signature"),
        );
        session.set_sso_login_state(SsoLoginState {
            token: WarpgateIdToken::from_str(&token).unwrap(),
            provider: "removed".into(),
            supports_single_logout: true,
        });
    }

    const AFTER_GATE: &str = "written_after_the_gate";

    /// A route behind the real step-up gate (`_inner_auth`). When the gate
    /// logs the session out, the request goes on, as `page_auth` does into
    /// the login flow, and writes to the session.
    #[handler]
    fn gated() -> &'static str {
        "past the gate"
    }

    async fn step_up_gate<E: Endpoint + 'static>(
        ep: Arc<E>,
        mut req: Request,
    ) -> poem::Result<String> {
        let session = <&Session>::from_request_without_body(&req).await?.clone();
        let auth = session
            .get_auth()
            .ok_or_else(|| poem::Error::from_status(poem::http::StatusCode::UNAUTHORIZED))?;
        let ctx = Data::<&UnauthenticatedRequestContext>::from_request_without_body(&req)
            .await?
            .to_authenticated(RequestAuthorization::Session(auth));
        req.set_data(ctx);
        match crate::common::_inner_auth(ep, req).await? {
            Ok(_) => Ok("past the gate".into()),
            Err(_) => {
                session.set(AFTER_GATE, true);
                Ok("stepped up".into())
            }
        }
    }

    /// The real logout endpoints behind the session middleware production
    /// uses.
    async fn app(db: DatabaseConnection, storage: SharedSessionStorage) -> impl Endpoint {
        app_with(services(db).await, storage).await
    }

    async fn app_with(services: Services, storage: SharedSessionStorage) -> impl Endpoint {
        let ctx = UnauthenticatedRequestContext::new(services).await;
        Route::new()
            .at("/login", get(log_in))
            .at("/whoami", get(whoami))
            .at("/seed/sso-login", get(seed_sso_login))
            .at("/gated", get(gated).around(step_up_gate))
            .nest(
                "/api",
                OpenApiService::new(
                    (crate::api::auth::Api, crate::api::sso_provider_list::Api),
                    "test",
                    "1.0",
                ),
            )
            .data(SessionStore::new())
            .data(ctx)
            .with(ServerSession::new(session_cookie_config(), storage))
    }

    struct Login {
        cookie: String,
        storage_id: String,
        id: UserSessionId,
    }

    async fn log_in_as_alice(cli: &TestClient<impl Endpoint>) -> Login {
        let resp = cli.get("/login").send().await;
        resp.assert_status_is_ok();
        let cookie = session_cookie(&resp).expect("the login sets a cookie");
        let id = UserSessionId(
            resp.0
                .into_body()
                .into_string()
                .await
                .unwrap()
                .parse()
                .unwrap(),
        );
        let (_, storage_id) = cookie.split_once('=').unwrap();
        Login {
            storage_id: storage_id.to_owned(),
            cookie,
            id,
        }
    }

    /// The `name=value` pair of the session cookie the response sets, if any.
    fn session_cookie(resp: &TestResponse) -> Option<String> {
        resp.0
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .filter_map(|value| value.split(';').next())
            .find(|pair| pair.starts_with(&format!("{SESSION_COOKIE_NAME}=")))
            .map(ToOwned::to_owned)
    }

    fn clears_session_cookie(resp: &TestResponse) -> bool {
        resp.0
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .any(|value| {
                value.starts_with(&format!("{SESSION_COOKIE_NAME}="))
                    && value.to_ascii_lowercase().contains("max-age=0")
            })
    }

    async fn is_ended(db: &DatabaseConnection, id: UserSessionId) -> bool {
        UserSession::Entity::find_by_id(id)
            .one(db)
            .await
            .unwrap()
            .unwrap()
            .ended
            .is_some()
    }

    async fn is_stored(db: &DatabaseConnection, storage_id: &str) -> bool {
        HttpSession::Entity::find_by_id(storage_id.to_owned())
            .one(db)
            .await
            .unwrap()
            .is_some()
    }

    #[tokio::test]
    async fn logout_ends_the_login_and_clears_the_cookie() {
        let db = memory_db().await;
        let cli = TestClient::new(app(db.clone(), SharedSessionStorage::new(db.clone())).await);
        let login = log_in_as_alice(&cli).await;

        let resp = cli.post(LOGOUT).header("cookie", &login.cookie).send().await;
        resp.assert_status(poem::http::StatusCode::CREATED);

        assert!(is_ended(&db, login.id).await, "the login was not ended");
        assert!(
            !is_stored(&db, &login.storage_id).await,
            "the stored browser session survived the logout"
        );
        assert!(clears_session_cookie(&resp), "the logout did not clear the cookie");
    }

    /// A request that loaded the browser session before the logout and writes
    /// it back after (any request does, once a minute, to keep the session
    /// alive) must not restore the login.
    #[tokio::test]
    async fn an_in_flight_write_back_cannot_undo_a_logout() {
        let db = memory_db().await;
        let storage = SharedSessionStorage::new(db.clone());
        let cli = TestClient::new(app(db.clone(), storage.clone()).await);
        let login = log_in_as_alice(&cli).await;
        let in_flight = storage
            .load_session(&login.storage_id)
            .await
            .unwrap()
            .unwrap();

        let resp = cli.post(LOGOUT).header("cookie", &login.cookie).send().await;
        resp.assert_status(poem::http::StatusCode::CREATED);
        storage
            .update_session(&login.storage_id, &in_flight, Some(Duration::from_secs(3600)))
            .await
            .unwrap();

        let resp = cli.get("/whoami").header("cookie", &login.cookie).send().await;
        resp.assert_status_is_ok();
        resp.assert_text("nobody").await;
        assert!(is_ended(&db, login.id).await, "the login was not ended");
    }

    /// The database stays locked past the first write's busy timeout but
    /// not the second's: the login must still end.
    #[tokio::test]
    async fn logout_ends_the_login_when_the_database_is_briefly_busy() {
        let (db, _temp) = file_db(Duration::from_millis(400)).await;
        let cli = TestClient::new(app(db.clone(), SharedSessionStorage::new(db.clone())).await);
        let login = log_in_as_alice(&cli).await;

        let writer = hold_write_lock(&db, Duration::from_millis(600)).await;
        let resp = cli.post(LOGOUT).header("cookie", &login.cookie).send().await;
        writer.await.unwrap();

        assert!(is_ended(&db, login.id).await, "the login was not ended");
        assert!(
            !is_stored(&db, &login.storage_id).await,
            "the stored browser session survived the logout"
        );
        resp.assert_status(poem::http::StatusCode::CREATED);
    }

    /// A logout that could not write anything must not report success. The
    /// login itself survives here, which is accepted: without a database
    /// write nothing can end it cluster-wide, and clearing the browser's
    /// cookie alone is a separate decision.
    #[tokio::test]
    async fn logout_that_cannot_write_is_not_reported_as_success() {
        let (db, _temp) = file_db(Duration::from_millis(200)).await;
        let cli = TestClient::new(app(db.clone(), SharedSessionStorage::new(db.clone())).await);
        let login = log_in_as_alice(&cli).await;

        let writer = hold_write_lock(&db, Duration::from_millis(1500)).await;
        let resp = cli.post(LOGOUT).header("cookie", &login.cookie).send().await;
        writer.await.unwrap();

        assert!(!resp.0.status().is_success(), "status {}", resp.0.status());
    }

    /// The login must not depend on its last stored browser session for
    /// ending: with a second one naming it, removing the logged-out one does
    /// not end it, so only the logout's own step can.
    #[tokio::test]
    async fn logout_ends_a_login_that_has_another_browser_session() {
        let db = memory_db().await;
        let cli = TestClient::new(app(db.clone(), SharedSessionStorage::new(db.clone())).await);
        let login = log_in_as_alice(&cli).await;
        HttpSession::Entity::insert(HttpSession::ActiveModel {
            id: Set("another-browser".into()),
            expires: Set(None),
            data: Set("{}".into()),
            updated: Set(OffsetDateTime::now_utc()),
            user_session_id: Set(Some(login.id)),
        })
        .exec(&db)
        .await
        .unwrap();

        let resp = cli.post(LOGOUT).header("cookie", &login.cookie).send().await;
        resp.assert_status(poem::http::StatusCode::CREATED);

        assert!(is_ended(&db, login.id).await, "the login was not ended");
    }

    /// The SSO logout ends the Warpgate login even when the IdP's single
    /// logout cannot run, here because the provider is no longer configured.
    #[tokio::test]
    async fn sso_logout_ends_the_login_when_the_provider_is_gone() {
        let db = memory_db().await;
        let cli = TestClient::new(app(db.clone(), SharedSessionStorage::new(db.clone())).await);
        let login = log_in_as_alice(&cli).await;
        cli.get("/seed/sso-login")
            .header("cookie", &login.cookie)
            .send()
            .await
            .assert_status_is_ok();

        cli.get("/api/sso/logout")
            .header("cookie", &login.cookie)
            .header("host", "localhost")
            .send()
            .await;

        assert!(is_ended(&db, login.id).await, "the login was not ended");
    }

    /// The step-up's forced logout ends the login, and keeps the browser
    /// session writable for the login flow the request goes on to.
    #[tokio::test]
    async fn step_up_ends_the_login_and_keeps_later_session_writes() {
        let db = memory_db().await;
        let storage = SharedSessionStorage::new(db.clone());
        let services = services(db.clone()).await;
        services.config.lock().await.store.step_up_interval = Some(StepUpIntervalConfig {
            http: Some(Duration::from_secs(3600)),
            ..Default::default()
        });
        let cli = TestClient::new(app_with(services, storage.clone()).await);
        let login = log_in_as_alice(&cli).await;

        let resp = cli.get("/gated").header("cookie", &login.cookie).send().await;
        resp.assert_status_is_ok();
        resp.assert_text("stepped up").await;

        assert!(is_ended(&db, login.id).await, "the login was not ended");
        let stored = storage.load_session(&login.storage_id).await.unwrap();
        assert!(
            stored.is_some_and(|entries| entries.contains_key(AFTER_GATE)),
            "the write after the gate was lost"
        );
    }
}
