use std::collections::HashMap;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use poem::session::Session;
use poem::web::RemoteAddr;
use poem::{FromRequest, Request};
use sea_orm::{DatabaseConnection, EntityTrait};
use tokio::sync::{Mutex, broadcast, mpsc};
use tracing::{error, info, warn};
use uuid::Uuid;
use warpgate_common::{UserSessionId, WarpgateError};
use warpgate_common_http::auth::UnauthenticatedRequestContext;
use warpgate_common_http::logging::get_client_ip_addr;
use warpgate_common_http::{SessionAuthorization, SessionKeepalive};
use warpgate_core::{State, UserSessionStateInit, WarpgateServerHandle};
use warpgate_db_entities::{HttpSession, UserSession};

use crate::common::{PROTOCOL_NAME, SessionExt};
use crate::middleware::ticket::{TicketSessionKey, ticket_session_key};
use crate::session_handle::{HttpSessionHandle, SessionHandleCommand};

/// The node's view of one user session. Removing the entry fires its
/// `close_sender`, aborting the requests and websockets served through it, and
/// drops the last reference to `handle`, whose teardown detaches a
/// cookie-backed session and ends a node-owned (header-ticket) one. Anything
/// that stores a lasting clone of `handle` keeps that teardown from running.
struct SessionEntry {
    handle: Arc<Mutex<WarpgateServerHandle>>,
    close_sender: broadcast::Sender<()>,
    last_activity: Instant,
    keepalive: Weak<()>,
    /// Set for a [`TemporaryTicketSession`]: the key this entry is indexed
    /// under in `ticket_sessions`, so removing it clears the index too.
    ticket_key: Option<TicketSessionKey>,
}

fn is_session_expired(
    last_activity: Instant,
    keepalive: &Weak<()>,
    now: Instant,
    max_age: Duration,
) -> bool {
    now.duration_since(last_activity) > max_age && keepalive.strong_count() == 0
}

pub struct SessionStore {
    sessions: HashMap<UserSessionId, SessionEntry>,
    /// Lets consecutive header-ticket requests share one user session: they
    /// carry no cookie, so without this index every request would register a
    /// session (and a target session, and an audit event) of its own.
    ticket_sessions: HashMap<TicketSessionKey, UserSessionId>,
    this: Weak<Mutex<Self>>,
}

/// A server handle vetted against the request's own authorization: minted only
/// by [`SessionStore::handle_for_request`] (or its login-path variant
/// [`SessionStore::handle_for_login`]), after the user check every branch
/// runs. Request-serving code takes this instead of a bare handle, so a new
/// code path cannot skip the check.
pub struct UserBoundHandle(Arc<Mutex<WarpgateServerHandle>>);

impl std::ops::Deref for UserBoundHandle {
    type Target = Arc<Mutex<WarpgateServerHandle>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Why the cookie's session cannot serve the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    /// The session is attributed to a user other than the cookie's
    /// authorization (or the cookie carries none).
    OtherUser,
    /// The session is gone or ended, but the cookie still carries an
    /// authorization issued under it.
    EndedWithAuth,
}

enum Resolved {
    Handle(UserBoundHandle),
    Refused(Refusal),
}

enum Adoption {
    Adopted(Arc<Mutex<WarpgateServerHandle>>),
    /// The row is gone, ended or not a cookie-backed HTTP session.
    Gone,
    OtherUser,
}

/// The user the request's browser session is authorized as, if any.
fn request_auth_user_id(session: &Session) -> Option<Uuid> {
    match session.get_auth() {
        Some(SessionAuthorization::User { user_id, .. })
        | Some(SessionAuthorization::Ticket { user_id, .. }) => Some(user_id),
        None => None,
    }
}

pub const SESSION_ID_SESSION_KEY: &str = HttpSession::SESSION_ID_DATA_KEY;

impl SessionStore {
    pub fn new() -> Arc<Mutex<Self>> {
        Arc::new_cyclic(|me| {
            Mutex::new(Self {
                sessions: HashMap::new(),
                ticket_sessions: HashMap::new(),
                this: me.clone(),
            })
        })
    }

    pub async fn process_request(&mut self, mut req: Request) -> poem::Result<Request> {
        let session = <&Session>::from_request_without_body(&req).await?;
        crate::session_storage::mark_session_active(session);

        if let Some(session_id) = session.get_session_id() {
            if let Some(entry) = self.sessions.get_mut(&session_id) {
                entry.last_activity = Instant::now();
            }
            req.set_data(SessionKeepalive::new(self.keepalive(session_id)));
        }

        Ok(req)
    }

    /// The server handle for this request's browser session: the live local
    /// one, a re-attached view over the still-open session the cookie already
    /// references (created on another node, or detached here), or a fresh
    /// registration when the cookie references none. The one refusal is a
    /// cookie referencing a session attributed to a different user — checked
    /// here for every branch, which is what the returned [`UserBoundHandle`]
    /// attests.
    pub async fn handle_for_request(
        &mut self,
        req: &Request,
        ctx: &UnauthenticatedRequestContext,
    ) -> poem::Result<UserBoundHandle> {
        match self.resolve_handle(req, ctx).await? {
            Resolved::Handle(handle) => Ok(handle),
            Resolved::Refused(refusal) => {
                if refusal == Refusal::EndedWithAuth {
                    // The cookie names a session that is gone or ended. If it
                    // also carries an authorization, that authorization was
                    // issued under the ended session: deleting the stored
                    // browser sessions is what makes an administrative close
                    // cluster-wide, but a request already in flight when that
                    // happened writes its copy back afterwards, so a revoked
                    // cookie can outlive the close. Registering a replacement
                    // session would hand it a fresh login and undo the close,
                    // so the browser session is dropped instead and the caller
                    // has to authenticate again.
                    <&Session>::from_request_without_body(req).await?.purge();
                }
                Err(poem::Error::from_status(
                    poem::http::StatusCode::UNAUTHORIZED,
                ))
            }
        }
    }

    /// [`Self::handle_for_request`] for the login entry points (SSO start, SSO
    /// return, password and OTP submission), which are where a browser holding
    /// a stale cookie goes to get a working one.
    ///
    /// Where [`Self::handle_for_request`] refuses the cookie's session — it is
    /// attributed to a user other than the cookie's authorization, or it is
    /// gone or ended while the cookie still carries an authorization — this
    /// discards the browser session's contents and registers a fresh,
    /// unauthenticated session in its place, so the login can proceed. The
    /// refusal is an error, and an error skips the session middleware's
    /// write-back, so without this the stale cookie would come back unchanged
    /// and be refused again on every attempt.
    ///
    /// Security invariant: the refusal of an ended session's authorization is
    /// what keeps a revoked cookie from regaining it after an administrative
    /// close. The replacement carries none of the old browser session's
    /// entries — no authorization, no user session id — so the caller holds
    /// no login until it completes the IdP or password login again. The
    /// cookie's storage id is deliberately kept, so the write-back reaches the
    /// browser even from a forwarded request; the login that completes on it
    /// rotates that id, like every completed login (`authorize_session` on the
    /// first hop, `SharedSessionStorage::adopt_forwarded_login` after a
    /// forwarded step).
    ///
    /// Known limitations, all failing safe:
    /// - A password login that finds an in-progress auth state still keyed by
    ///   the stale session id (they live until the auth state store's vacuum)
    ///   reuses it and never gets here, so it still ends refused, as before,
    ///   until that state ages out.
    /// - Concurrent login entries on one stale cookie each register a
    ///   replacement and the last write-back wins; an SSO handshake bound to
    ///   a losing replacement fails at its return and has to be retried.
    /// - If the SSO return fails after replacing the session, the replacement
    ///   is not written back: the browser keeps the stale cookie, and the
    ///   unused replacement is ended by the orphan sweep.
    pub async fn handle_for_login(
        &mut self,
        req: &Request,
        ctx: &UnauthenticatedRequestContext,
    ) -> poem::Result<UserBoundHandle> {
        match self.resolve_handle(req, ctx).await? {
            Resolved::Handle(handle) => Ok(handle),
            Resolved::Refused(refusal) => {
                let session = <&Session>::from_request_without_body(req).await?;
                let old_session_id = session.get_session_id();
                // `clear`, not `purge`: a purged session ignores every later
                // write, so the replacement's session id would be dropped and
                // the cookie removed. A cleared one is marked changed and is
                // written back under the same cookie id — which also survives
                // a forwarded request, whose own cookie changes never reach
                // the browser — with only the replacement's entries.
                session.clear();
                let handle = self.create_handle_for(req, ctx).await?;
                let new_session_id = session.get_session_id();
                match refusal {
                    // A cookie authorized as one user naming another user's
                    // session is an inconsistency worth an operator's look.
                    Refusal::OtherUser => warn!(
                        ?refusal,
                        ?old_session_id,
                        ?new_session_id,
                        "Replacing a browser session attributed to another user at login"
                    ),
                    Refusal::EndedWithAuth => info!(
                        ?refusal,
                        ?old_session_id,
                        ?new_session_id,
                        "Replacing a stale browser session at a login entry point"
                    ),
                }
                Ok(UserBoundHandle(handle))
            }
        }
    }

    async fn resolve_handle(
        &mut self,
        req: &Request,
        ctx: &UnauthenticatedRequestContext,
    ) -> poem::Result<Resolved> {
        let session = <&Session>::from_request_without_body(req).await?;

        // A header-borne ticket has no cookie to resolve, so it is recognised
        // by the ticket it presents instead — otherwise every request would
        // register a session of its own.
        if let Some(key) = ticket_session_key(req, session) {
            if let Some(entry) = self
                .ticket_sessions
                .get(&key)
                .copied()
                .and_then(|id| self.sessions.get_mut(&id))
            {
                entry.last_activity = Instant::now();
                return Ok(Resolved::Handle(UserBoundHandle(entry.handle.clone())));
            }
            return Ok(Resolved::Handle(UserBoundHandle(
                self.create_handle_for(req, ctx).await?,
            )));
        }

        if let Some(handle) = self.handle_for(session) {
            // An adopted view's user is stamped lazily, so an unattributed
            // handle passes; once attributed, it is handed out only to its
            // user — the live-entry equivalent of `adopt_handle_for`'s check.
            let state_user_id = handle
                .lock()
                .await
                .user_session_state()
                .lock()
                .await
                .user_info
                .as_ref()
                .map(|user| user.id);
            if state_user_id.is_some() && state_user_id != request_auth_user_id(session) {
                return Ok(Resolved::Refused(Refusal::OtherUser));
            }
            return Ok(Resolved::Handle(UserBoundHandle(handle)));
        }
        if let Some(id) = session.get_session_id() {
            match self.adopt_handle_for(req, ctx, id).await? {
                Adoption::Adopted(handle) => {
                    return Ok(Resolved::Handle(UserBoundHandle(handle)));
                }
                Adoption::OtherUser => return Ok(Resolved::Refused(Refusal::OtherUser)),
                Adoption::Gone => {}
            }
            if request_auth_user_id(session).is_some() {
                return Ok(Resolved::Refused(Refusal::EndedWithAuth));
            }
            // Unauthenticated, so there is no authority to carry over and
            // nothing to undo — the id is a leftover (its session reaped while
            // the cookie lived on) and this is someone arriving to log in.
        }
        Ok(Resolved::Handle(UserBoundHandle(
            self.create_handle_for(req, ctx).await?,
        )))
    }

    async fn create_handle_for(
        &mut self,
        req: &Request,
        ctx: &UnauthenticatedRequestContext,
    ) -> poem::Result<Arc<Mutex<WarpgateServerHandle>>> {
        let session = <&Session>::from_request_without_body(req).await?;

        let (session_handle, session_handle_rx) = HttpSessionHandle::new();
        let init = Self::state_init_for(req, ctx, session_handle).await?;
        // A header-ticket session is held open by this node's entry alone: it
        // has no stored browser session, so the orphan sweep would end it
        // while it is still serving. Its lifetime is this node's, and it
        // registers as such.
        let server_handle = if ticket_session_key(req, session).is_some() {
            State::register_node_local_user_session(&ctx.services().state, PROTOCOL_NAME, init)
                .await?
        } else {
            State::register_nonlocal_user_session(&ctx.services().state, PROTOCOL_NAME, init)
                .await?
        };

        let id = server_handle.lock().await.user_session_id();
        session.set(SESSION_ID_SESSION_KEY, id);
        self.install_entry(req, ctx, id, server_handle.clone(), session_handle_rx)?;
        Ok(server_handle)
    }

    /// A node-local handle over a still-open user session this node has no
    /// live entry for: the parent row is validated once here. `None` means the
    /// row is gone, ended or not an HTTP session — nothing to re-attach to.
    /// Per-request liveness comes from the cookie-session storage row, which a
    /// close deletes cluster-wide.
    async fn adopt_handle_for(
        &mut self,
        req: &Request,
        ctx: &UnauthenticatedRequestContext,
        id: UserSessionId,
    ) -> poem::Result<Adoption> {
        if let Some(entry) = self.sessions.get(&id) {
            return Ok(Adoption::Adopted(entry.handle.clone()));
        }

        let session = <&Session>::from_request_without_body(req).await?;
        let Some(row) = warpgate_db_entities::UserSession::Entity::find_by_id(id)
            .one(&ctx.services().db)
            .await
            .map_err(WarpgateError::from)?
            // `node_id` must be NULL: a node-owned (ticket) session lives and
            // dies with its node and is never re-attached to from a cookie —
            // the query enforces it rather than the absence of such a cookie.
            .filter(|row| {
                row.ended.is_none()
                    && row.node_id.is_none()
                    && row.protocol == PROTOCOL_NAME.to_string()
            })
        else {
            return Ok(Adoption::Gone);
        };
        if row.user_id != request_auth_user_id(session) {
            return Ok(Adoption::OtherUser);
        }

        let (session_handle, session_handle_rx) = HttpSessionHandle::new();
        let server_handle = State::adopt_user_session(
            &ctx.services().state,
            id,
            PROTOCOL_NAME,
            Self::state_init_for(req, ctx, session_handle).await?,
        )
        .await;
        self.install_entry(req, ctx, id, server_handle.clone(), session_handle_rx)?;
        Ok(Adoption::Adopted(server_handle))
    }

    /// With `http.client_ip_header` set, the session records the address from
    /// that header (the visitor behind the tunnel), not the tunnel's own peer
    /// address. Both the create and the adopt path come through here.
    async fn state_init_for(
        req: &Request,
        ctx: &UnauthenticatedRequestContext,
        session_handle: HttpSessionHandle,
    ) -> poem::Result<UserSessionStateInit> {
        let use_header = ctx
            .services()
            .config
            .lock()
            .await
            .store
            .http
            .client_ip_header
            .is_some();
        let remote_address = if use_header {
            get_client_ip_addr(req, ctx.services())
                .await
                .map(|ip| std::net::SocketAddr::new(ip, 0))
        } else {
            <&RemoteAddr>::from_request_without_body(req)
                .await?
                .0
                .as_socket_addr()
                .copied()
        };
        Ok(UserSessionStateInit {
            remote_address,
            handle: Box::new(session_handle),
        })
    }

    fn install_entry(
        &mut self,
        req: &Request,
        ctx: &UnauthenticatedRequestContext,
        id: UserSessionId,
        server_handle: Arc<Mutex<WarpgateServerHandle>>,
        session_handle_rx: mpsc::UnboundedReceiver<SessionHandleCommand>,
    ) -> poem::Result<()> {
        let ticket_key = req
            .extensions()
            .get::<Session>()
            .and_then(|session| ticket_session_key(req, session));

        let (session_close_sender, _) = broadcast::channel(1);
        self.sessions.insert(
            id,
            SessionEntry {
                handle: server_handle,
                close_sender: session_close_sender,
                last_activity: Instant::now(),
                keepalive: Weak::new(),
                ticket_key,
            },
        );
        if let Some(key) = ticket_key {
            self.ticket_sessions.insert(key, id);
        }

        let Some(this) = self.this.upgrade() else {
            return Err(anyhow::anyhow!("Invalid session state").into());
        };
        self.spawn_close_listener(this, ctx.services().db.clone(), id, session_handle_rx);
        Ok(())
    }

    fn spawn_close_listener(
        &self,
        this: Arc<Mutex<Self>>,
        db: DatabaseConnection,
        id: UserSessionId,
        mut session_handle_rx: mpsc::UnboundedReceiver<SessionHandleCommand>,
    ) {
        tokio::spawn(async move {
            while let Some(command) = session_handle_rx.recv().await {
                match command {
                    SessionHandleCommand::Close => {
                        // A cluster-wide logout, not just a local detach: the
                        // stored browser sessions are what keep the login
                        // valid on every node.
                        if let Err(error) = UserSession::revoke(&db, id).await {
                            error!(%id, %error, "Could not revoke the closed HTTP session");
                        }
                        info!(%id, "Removed HTTP session");
                        this.lock().await.remove_session_by_id(id);
                    }
                }
            }
        });
    }

    pub fn handle_for(&self, session: &Session) -> Option<Arc<Mutex<WarpgateServerHandle>>> {
        session
            .get_session_id()
            .and_then(|id| self.sessions.get(&id))
            .map(|entry| entry.handle.clone())
    }

    /// The login's close signal: fires when the session is removed from this
    /// node — an admin close, a logout, or expiry — aborting whatever is
    /// served through it. `None` only for a session this node holds no entry
    /// for.
    pub fn close_receiver_by_id(&self, id: UserSessionId) -> Option<broadcast::Receiver<()>> {
        self.sessions
            .get(&id)
            .map(|entry| entry.close_sender.subscribe())
    }

    /// Get a token that prevents the session from getting cleaned up
    /// until it's dropped. For an unknown (already removed) session id the
    /// token is returned unstored — there is nothing left to keep alive.
    fn keepalive(&mut self, id: UserSessionId) -> Arc<()> {
        let Some(entry) = self.sessions.get_mut(&id) else {
            return Arc::new(());
        };
        if let Some(token) = entry.keepalive.upgrade() {
            return token;
        }
        let token = Arc::new(());
        entry.keepalive = Arc::downgrade(&token);
        token
    }

    pub fn remove_session(&mut self, session: &Session) {
        if let Some(id) = session.get_session_id() {
            self.remove_session_by_id(id);
        }
    }

    /// Expires idle local entries. Removing an entry drops the last handle
    /// reference, and what that does is the session's own business: a
    /// connection-bound session (a header ticket's) ends, while a cookie-backed
    /// one is only detached, since another node may still be serving it and
    /// shared storage GC is the authority for global idle expiration.
    pub fn vacuum(&mut self, session_max_age: Duration) {
        let now = Instant::now();
        let to_remove: Vec<UserSessionId> = self
            .sessions
            .iter()
            .filter(|(_, entry)| {
                // A handle a request still holds is in use even if the entry
                // looks idle: a header-ticket request registers no keepalive,
                // since the token is attached before its session exists.
                Arc::strong_count(&entry.handle) == 1
                    && is_session_expired(
                        entry.last_activity,
                        &entry.keepalive,
                        now,
                        session_max_age,
                    )
            })
            .map(|(id, _)| *id)
            .collect();
        for id in to_remove {
            info!(%id, "Expiring idle local HTTP session handle");
            self.remove_session_by_id(id);
        }
    }

    /// The sessions this node is actively serving, so their stored browser
    /// sessions can be kept from ageing out under a long-lived connection.
    pub fn live_session_ids(&self) -> Vec<UserSessionId> {
        self.sessions
            .iter()
            .filter(|(_, entry)| {
                entry.keepalive.strong_count() > 0 || Arc::strong_count(&entry.handle) > 1
            })
            .map(|(id, _)| *id)
            .collect()
    }

    /// Detaches the parent's local handle. Its target sessions are owned by
    /// the parent state and drop with it, which is what aborts the requests
    /// served through them.
    fn remove_session_by_id(&mut self, id: UserSessionId) {
        if let Some(entry) = self.sessions.remove(&id) {
            // Only if it still points here: the key may already have been
            // re-registered by a later request.
            if let Some(key) = entry.ticket_key
                && self.ticket_sessions.get(&key) == Some(&id)
            {
                self.ticket_sessions.remove(&key);
            }
            let _ = entry.close_sender.send(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_session_expires() {
        let now = Instant::now();
        let stale = now - Duration::from_secs(60);
        assert!(is_session_expired(
            stale,
            &Weak::new(),
            now,
            Duration::from_secs(1)
        ));
        assert!(!is_session_expired(
            now,
            &Weak::new(),
            now,
            Duration::from_secs(1)
        ));
    }

    #[test]
    fn live_connection_spares_session() {
        let now = Instant::now();
        let stale = now - Duration::from_secs(60);

        let token = Arc::new(());
        let keepalive = Arc::downgrade(&token);
        assert!(!is_session_expired(
            stale,
            &keepalive,
            now,
            Duration::from_secs(1)
        ));

        drop(token);
        assert!(is_session_expired(
            stale,
            &keepalive,
            now,
            Duration::from_secs(1)
        ));
    }
}

#[cfg(test)]
mod stale_cookie_login_tests {
    //! A browser whose cookie names a session the store refuses — attributed
    //! to another user, or gone while the cookie still carries a login — gets
    //! a fresh, unauthenticated session at a login entry point, and keeps it:
    //! the refusal is an error, which the session middleware does not write
    //! back, so unless the login path replaces the session itself the same
    //! cookie is refused on every attempt. Anywhere else the refusal stands.
    use std::path::PathBuf;

    use poem::session::{CookieConfig, MemoryStorage, ServerSession, SessionStorage};
    use poem::test::{TestClient, TestResponse};
    use poem::web::Data;
    use poem::{Endpoint, EndpointExt, Route, get, handler};
    use sea_orm::sea_query::Expr;
    use sea_orm::{ColumnTrait, Database, QueryFilter};
    use time::OffsetDateTime;
    use warpgate_common::auth::AuthStateUserInfo;
    use warpgate_common::{GlobalParams, WarpgateConfig, WarpgateConfigStore};
    use warpgate_core::cluster::Cluster;
    use warpgate_core::login_protection::LoginProtectionService;
    use warpgate_core::rate_limiting::RateLimiterRegistry;
    use warpgate_core::recordings::SessionRecordings;
    use warpgate_core::{ApprovalRequestSink, AuthStateStore, DatabaseConfigProvider, Services};

    use super::*;
    use crate::session_storage::SharedSessionStorage;

    const ALICE: Uuid = Uuid::from_u128(1);
    const BOB: Uuid = Uuid::from_u128(2);

    async fn services() -> Services {
        warpgate_db_entities::Parameters::set_config_migration_values(
            warpgate_db_entities::Parameters::ConfigMigrationValues::default(),
        );
        let db = Database::connect("sqlite::memory:").await.unwrap();
        warpgate_db_migrations::migrate_database(&db).await.unwrap();
        let params = GlobalParams::new(PathBuf::from("/warpgate.yaml"), false).unwrap();
        let rate_limiter_registry = Arc::new(Mutex::new(RateLimiterRegistry::new(db.clone())));
        let cluster = Arc::new(Cluster::new(db.clone(), 0).await.unwrap());
        Services {
            db: db.clone(),
            recordings: Arc::new(SessionRecordings::new(db.clone(), &params)),
            config: Arc::new(Mutex::new(WarpgateConfig {
                store: WarpgateConfigStore::default(),
            })),
            state: State::new(&db, &rate_limiter_registry, cluster.node_id),
            cluster: cluster.clone(),
            rate_limiter_registry,
            config_provider: Arc::new(DatabaseConfigProvider::new(&db).into()),
            auth_state_store: Arc::new(Mutex::new(AuthStateStore::new(ApprovalRequestSink {
                db: db.clone(),
                cluster,
            }))),
            admin_token: Arc::new(None),
            login_protection: Arc::new(LoginProtectionService::new(db.clone()).await.unwrap()),
            global_params: Arc::new(params),
            listener_status: Default::default(),
        }
    }

    type Store = Arc<Mutex<SessionStore>>;

    /// What the resolved session looks like: its user session id and the
    /// login the browser session carries.
    fn describe(id: UserSessionId, session: &Session) -> String {
        let user = match session.get_auth() {
            Some(SessionAuthorization::User { username, .. }) => username,
            Some(SessionAuthorization::Ticket { username, .. }) => format!("ticket:{username}"),
            None => "nobody".into(),
        };
        format!("{id} {user}")
    }

    /// A login entry point: resolves the session the way SSO start, SSO
    /// return and password/OTP submission do.
    #[handler]
    async fn login_entry(
        req: &Request,
        session: &Session,
        ctx: Data<&UnauthenticatedRequestContext>,
    ) -> poem::Result<String> {
        let id = crate::common::session_id_for_login(req, ctx.0)
            .await
            .map_err(poem::Error::from)?;
        Ok(describe(id, session))
    }

    /// Any other caller of the store, such as the catchall.
    #[handler]
    async fn other_entry(
        req: &Request,
        session: &Session,
        store: Data<&Store>,
        ctx: Data<&UnauthenticatedRequestContext>,
    ) -> poem::Result<String> {
        let handle = store.lock().await.handle_for_request(req, ctx.0).await?;
        let id = handle.lock().await.user_session_id();
        Ok(describe(id, session))
    }

    /// Case (1): a live session attributed to alice, behind a cookie that is
    /// logged in as bob.
    #[handler]
    async fn seed_other_user(
        req: &Request,
        session: &Session,
        store: Data<&Store>,
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
            user_id: BOB,
            username: "bob".into(),
        });
        let id = handle.lock().await.user_session_id();
        Ok(describe(id, session))
    }

    /// Case (2): a cookie logged in as alice that names a user session that
    /// no longer exists (closed and reaped, or never on this cluster).
    #[handler]
    fn seed_gone_with_auth(session: &Session) -> String {
        let gone = UserSessionId(Uuid::new_v4());
        session.set(SESSION_ID_SESSION_KEY, gone);
        session.set_auth(SessionAuthorization::User {
            user_id: ALICE,
            username: "alice".into(),
        });
        describe(gone, session)
    }

    /// Case (2) as an administrative close leaves it: alice's session, ended
    /// in the database and dropped from this node, behind her logged-in
    /// cookie.
    #[handler]
    async fn seed_ended_with_auth(
        req: &Request,
        session: &Session,
        store: Data<&Store>,
        ctx: Data<&UnauthenticatedRequestContext>,
    ) -> poem::Result<String> {
        let mut store = store.lock().await;
        let handle = store.handle_for_request(req, ctx.0).await?;
        let alice = AuthStateUserInfo {
            id: ALICE,
            username: "alice".into(),
        };
        handle.lock().await.set_user_info(alice).await?;
        session.set_auth(SessionAuthorization::User {
            user_id: ALICE,
            username: "alice".into(),
        });
        let id = handle.lock().await.user_session_id();
        drop(handle);
        UserSession::Entity::update_many()
            .col_expr(
                UserSession::Column::Ended,
                Expr::value(OffsetDateTime::now_utc()),
            )
            .filter(UserSession::Column::Id.eq(id))
            .exec(&ctx.services().db)
            .await
            .map_err(WarpgateError::from)?;
        store.remove_session_by_id(id);
        Ok(describe(id, session))
    }

    async fn app() -> impl Endpoint {
        let ctx = UnauthenticatedRequestContext::new(services().await).await;
        app_on(ctx, MemoryStorage::new())
    }

    fn app_on(ctx: UnauthenticatedRequestContext, storage: impl SessionStorage) -> impl Endpoint {
        let store: Store = SessionStore::new();
        Route::new()
            .at("/login", get(login_entry))
            .at("/other", get(other_entry))
            .at("/seed/other-user", get(seed_other_user))
            .at("/seed/gone-with-auth", get(seed_gone_with_auth))
            .at("/seed/ended-with-auth", get(seed_ended_with_auth))
            .data(store)
            .data(ctx)
            .with(ServerSession::new(CookieConfig::default(), storage))
    }

    fn cookie_pair(resp: &TestResponse) -> Option<String> {
        resp.0
            .headers()
            .get("set-cookie")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map(ToOwned::to_owned)
    }

    /// Runs a seed endpoint; returns its cookie and the stale session's
    /// description.
    async fn seed(cli: &TestClient<impl Endpoint>, path: &str) -> (String, String) {
        let resp = cli.get(path).send().await;
        resp.assert_status_is_ok();
        let cookie = cookie_pair(&resp).expect("the seed sets a cookie");
        (cookie, resp.0.into_body().into_string().await.unwrap())
    }

    /// Asserts a login-path request on the stale cookie succeeds on a fresh
    /// session that carries no login, then that the cookie the browser holds
    /// afterwards resolves to that same replacement.
    async fn assert_login_replaces_stale_session(path: &str) {
        let cli = TestClient::new(app().await);
        let (cookie, stale) = seed(&cli, path).await;
        let stale_id = stale.split(' ').next().unwrap().to_owned();

        let resp = cli.get("/login").header("cookie", &cookie).send().await;
        resp.assert_status_is_ok();
        // Written back under the same cookie id: a forwarded login's cookie
        // changes never reach the browser, so a new id would be lost there.
        assert!(
            cookie_pair(&resp).is_none(),
            "the replacement was given a new cookie id"
        );
        let first = resp.0.into_body().into_string().await.unwrap();
        let (fresh_id, user) = first.split_once(' ').unwrap();
        assert_ne!(fresh_id, stale_id, "the stale session was reused");
        assert_eq!(user, "nobody", "the replacement kept the old login");

        // The replacement was written back: the browser's cookie now resolves
        // to it, on the login path and off it.
        for path in ["/login", "/other"] {
            let resp = cli.get(path).header("cookie", &cookie).send().await;
            resp.assert_status_is_ok();
            resp.assert_text(&first).await;
        }
    }

    #[tokio::test]
    async fn login_replaces_a_session_attributed_to_another_user() {
        assert_login_replaces_stale_session("/seed/other-user").await;
    }

    #[tokio::test]
    async fn login_replaces_a_gone_session_whose_cookie_is_logged_in() {
        assert_login_replaces_stale_session("/seed/gone-with-auth").await;
    }

    #[tokio::test]
    async fn login_replaces_an_ended_session_whose_cookie_is_logged_in() {
        assert_login_replaces_stale_session("/seed/ended-with-auth").await;
    }

    /// On the database-backed storage production uses, the replacement
    /// updates the browser session's stored row in place: it now names the
    /// replacement, and it was never removed — removing it would have ended
    /// the old user session, which it was the only backing of.
    #[tokio::test]
    async fn login_replacement_updates_the_stored_browser_session_in_place() {
        let services = services().await;
        let db = services.db.clone();
        let ctx = UnauthenticatedRequestContext::new(services).await;
        let cli = TestClient::new(app_on(ctx, SharedSessionStorage::new(db.clone())));
        let (cookie, stale) = seed(&cli, "/seed/other-user").await;
        let stale_id = UserSessionId(stale.split(' ').next().unwrap().parse().unwrap());

        let resp = cli.get("/login").header("cookie", &cookie).send().await;
        resp.assert_status_is_ok();
        assert!(
            cookie_pair(&resp).is_none(),
            "the replacement was given a new cookie id"
        );
        let first = resp.0.into_body().into_string().await.unwrap();
        let (fresh_id, user) = first.split_once(' ').unwrap();
        let fresh_id = UserSessionId(fresh_id.parse().unwrap());
        assert_ne!(fresh_id, stale_id, "the stale session was reused");
        assert_eq!(user, "nobody", "the replacement kept the old login");

        let (_, storage_id) = cookie.split_once('=').unwrap();
        let row = HttpSession::Entity::find_by_id(storage_id.to_owned())
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.user_session_id, Some(fresh_id));
        let stale_row = UserSession::Entity::find_by_id(stale_id)
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert!(
            stale_row.ended.is_none(),
            "the browser session's row was removed"
        );

        let resp = cli.get("/other").header("cookie", &cookie).send().await;
        resp.assert_status_is_ok();
        resp.assert_text(&first).await;
    }

    /// Off the login path the refusal is unchanged: a logged-in cookie naming
    /// a gone session is refused, not given a session of its own — the
    /// administrative close it outlived stays in force.
    #[tokio::test]
    async fn other_callers_still_refuse_a_gone_session_whose_cookie_is_logged_in() {
        for seed_path in ["/seed/gone-with-auth", "/seed/ended-with-auth"] {
            let cli = TestClient::new(app().await);
            let (cookie, _) = seed(&cli, seed_path).await;
            for _ in 0..2 {
                let resp = cli.get("/other").header("cookie", &cookie).send().await;
                resp.assert_status(poem::http::StatusCode::UNAUTHORIZED);
            }
        }
    }

    /// Likewise for a live session attributed to another user.
    #[tokio::test]
    async fn other_callers_still_refuse_a_session_attributed_to_another_user() {
        let cli = TestClient::new(app().await);
        let (cookie, _) = seed(&cli, "/seed/other-user").await;
        let resp = cli.get("/other").header("cookie", &cookie).send().await;
        resp.assert_status(poem::http::StatusCode::UNAUTHORIZED);
    }
}
