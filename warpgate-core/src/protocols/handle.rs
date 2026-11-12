use std::net::IpAddr;
use std::sync::Arc;

use sea_orm::{ColumnTrait, Condition, DatabaseConnection, EntityTrait, QueryFilter};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;
use tracing::{Instrument, info_span, warn};
use uuid::Uuid;
use warpgate_common::auth::AuthStateUserInfo;
use warpgate_common::{
    NodeId, Protocol, Target, TargetOptionsVariant, TargetSessionId, UserSessionId, WarpgateError,
};
use warpgate_db_entities::TargetSession::TargetSessionOpenOutcome;
use warpgate_db_entities::{TargetSession, UserSession};

use crate::rate_limiting::{RateLimiterRegistry, stack_rate_limiters};
use crate::{
    ApprovedTarget, State, TargetAuthorization, UserSessionState, session_user_still_admitted,
};

pub trait SessionHandle {
    fn close(&mut self);
}

// Deliberately not Clone: `Drop` tears the session down, so a second copy
// would end the session while the first is still proxying. Share via the
// surrounding `Arc<Mutex<..>>` instead.
pub struct WarpgateServerHandle {
    user_session_id: UserSessionId,
    db: DatabaseConnection,
    state: Arc<Mutex<State>>,
    user_session_state: Arc<Mutex<UserSessionState>>,
    rate_limiters_registry: Arc<Mutex<RateLimiterRegistry>>,
    protocol: Protocol,
    /// is this session's lifetime bound to this node?
    /// Often no for HTTP (cookie session), otherwise yes
    node_owned: bool,
    node_id: NodeId,
    provisional: bool,
}

impl WarpgateServerHandle {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        user_session_id: UserSessionId,
        db: DatabaseConnection,
        state: Arc<Mutex<State>>,
        user_session_state: Arc<Mutex<UserSessionState>>,
        rate_limiters_registry: Arc<Mutex<RateLimiterRegistry>>,
        protocol: Protocol,
        node_owned: bool,
        node_id: NodeId,
    ) -> Self {
        Self {
            user_session_id,
            db,
            state,
            user_session_state,
            rate_limiters_registry,
            protocol,
            node_owned,
            node_id,
            provisional: false,
        }
    }

    pub const fn user_session_id(&self) -> UserSessionId {
        self.user_session_id
    }

    /// Marks a session that was registered before its authentication finished
    /// (so that it is addressable across the cluster while a web approval is
    /// pending). Dropping the handle while still provisional deletes the
    /// session instead of ending it, so an attempt that never became a session
    /// leaves nothing behind.
    pub const fn mark_provisional(&mut self) {
        self.provisional = true;
    }

    /// Turns a provisional session into a real one.
    pub const fn confirm(&mut self) {
        self.provisional = false;
    }

    pub const fn user_session_state(&self) -> &Arc<Mutex<UserSessionState>> {
        &self.user_session_state
    }

    /// Attributes the session to the user whose sign-in completed, judged
    /// from the address the session was opened from.
    pub async fn set_user_info(&self, user_info: AuthStateUserInfo) -> Result<(), WarpgateError> {
        self.set_user_info_from(user_info, None).await
    }

    /// As [`Self::set_user_info`], judged from `remote_ip` when it is known:
    /// a web sign-in completes on a later request than the one that opened
    /// the browser session, possibly from another address.
    pub async fn set_user_info_from(
        &self,
        user_info: AuthStateUserInfo,
        remote_ip: Option<IpAddr>,
    ) -> Result<(), WarpgateError> {
        {
            // Kubernetes reuses one session handle for many concurrent requests, so
            // most calls are no-ops, and the lock must span the no-op check and the
            // commit to keep the DB and in-memory state consistent.
            let mut state = self.user_session_state.lock().await;
            self.set_user_info_in(&mut state, user_info, remote_ip)
                .await?;
        }

        self.update_rate_limiters().await
    }

    /// The point a sign-in becomes a session of the user. It is refused,
    /// with [`WarpgateError::UserNoLongerAdmitted`], unless the user still
    /// exists and their allowed IP ranges, as stored now, admit the address:
    /// the rule a signed-in web session is held to on every later request
    /// ([`session_user_still_admitted`]). The auth state checked the ranges
    /// when the sign-in started, and they can change before it completes.
    ///
    /// The row is attributed first and the user read after, both under the
    /// session's state lock. An edit or delete of the user that commits
    /// before the read is seen by it and the sign-in is refused. One that
    /// commits after the read committed after the attribution too, and its
    /// close of the user's sessions runs after its commit: it finds the row
    /// by its user, and the live handle by the identity set below, because
    /// that close waits for the state lock held here. Reading first would
    /// leave a gap: a change committing between the read and the attribution
    /// would find nothing of this session to close.
    ///
    /// A refused sign-in leaves the in-memory identity unset, so a retry is
    /// judged again, and the row attributed, so a close of the user's
    /// sessions still finds it; the caller ends or discards the session.
    async fn set_user_info_in(
        &self,
        state: &mut UserSessionState,
        user_info: AuthStateUserInfo,
        remote_ip: Option<IpAddr>,
    ) -> Result<(), WarpgateError> {
        use sea_orm::ActiveValue::Set;

        if state.user_info.as_ref() == Some(&user_info) {
            return Ok(());
        }

        // The row itself carries the invariant: a node that adopted this
        // session has no in-memory identity to compare against, so an
        // unguarded write would let a login on someone else's still-valid
        // cookie re-attribute their sessions and audit history.
        let result = UserSession::Entity::update_many()
            .set(UserSession::ActiveModel {
                username: Set(Some(user_info.username.clone())),
                user_id: Set(Some(user_info.id)),
                ..Default::default()
            })
            .filter(UserSession::Column::Id.eq(self.user_session_id))
            .filter(
                Condition::any()
                    .add(UserSession::Column::UserId.is_null())
                    .add(UserSession::Column::UserId.eq(user_info.id)),
            )
            .exec(&self.db)
            .await?;
        if result.rows_affected == 0 {
            return Err(WarpgateError::UserSessionAlreadyAttributed);
        }

        let remote_ip = remote_ip.or_else(|| state.remote_address.map(|addr| addr.ip()));
        if !session_user_still_admitted(&self.db, user_info.id, remote_ip).await? {
            warn!(
                session = %self.user_session_id,
                user_id = %user_info.id,
                "Sign-in refused at completion: the user is gone or the address is outside their allowed ranges"
            );
            return Err(WarpgateError::UserNoLongerAdmitted);
        }

        state.user_info = Some(user_info);
        state.emit_change();
        Ok(())
    }

    pub async fn start_target_session<O>(
        &mut self,
        authorization: TargetAuthorization<O>,
    ) -> Result<TargetSessionStart<O>, WarpgateError> {
        self.stamp_target_session_identity(&authorization).await?;

        if self.needs_target_approval(authorization.target()).await? {
            return Ok(TargetSessionStart::NeedsApproval(authorization));
        }

        let id = self.open_target_session_row(&authorization).await?;
        Ok(TargetSessionStart::Started(AdmittedTarget {
            id,
            approved: ApprovedTarget::new(authorization),
        }))
    }

    /// Register the target session in the DB and issue an ID
    pub async fn register_approved_target_session<O>(
        &self,
        approved: ApprovedTarget<O>,
    ) -> Result<AdmittedTarget<O>, WarpgateError> {
        self.stamp_target_session_identity(&approved).await?;
        let id = self.open_target_session_row(&approved).await?;
        Ok(AdmittedTarget { id, approved })
    }

    async fn stamp_target_session_identity<O>(
        &self,
        authorization: &TargetAuthorization<O>,
    ) -> Result<(), WarpgateError> {
        if authorization.protocol() != self.protocol {
            return Err(WarpgateError::InconsistentState(
                "target authorization protocol does not match the user session".into(),
            ));
        }

        {
            let mut parent = self.user_session_state.lock().await;
            if parent.user_info.is_none() {
                self.set_user_info_in(&mut parent, authorization.user_info().clone(), None)
                    .await?;
            } else if parent.user_info.as_ref() != Some(authorization.user_info()) {
                return Err(WarpgateError::InconsistentState(
                    "target authorization user does not match the user session".into(),
                ));
            }
            parent.target = Some(authorization.target().clone());
        }
        self.update_rate_limiters().await
    }

    async fn open_target_session_row<O>(
        &self,
        authorization: &TargetAuthorization<O>,
    ) -> Result<TargetSessionId, WarpgateError> {
        let outcome = TargetSession::open_or_lookup(
            &self.db,
            TargetSessionId(Uuid::new_v4()),
            self.user_session_id,
            authorization.target(),
            self.node_owned.then_some(self.node_id),
            authorization.ticket_id(),
            authorization.user_info(),
        )
        .await?;

        let target_session = match outcome {
            TargetSessionOpenOutcome::Created(model) => {
                self.user_session_state.lock().await.emit_change();

                model
            }
            TargetSessionOpenOutcome::AlreadyExists(model) => model,
        };
        Ok(target_session.id)
    }

    async fn needs_target_approval(&self, target: &Target) -> Result<bool, WarpgateError> {
        if !target.require_approval {
            return Ok(false);
        }
        // skip the check if there is already a matching open target session in this user session
        Ok(!TargetSession::is_open(&self.db, self.user_session_id, target.id).await?)
    }

    /// Wraps a client stream, adding rate limiters. Wrapping happens at connection time
    /// and the limiters are swapped out later. See [State::register_user_session_with_stream]
    pub(crate) async fn wrap_stream<S>(
        &self,
        stream: S,
    ) -> Result<impl AsyncRead + AsyncWrite + Unpin + Send + use<S>, WarpgateError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let (stream, handle) = stack_rate_limiters(stream);
        let mut state = self.user_session_state.lock().await;
        self.rate_limiters_registry
            .lock()
            .await
            .update_user_rate_limiter(state.user_info.as_ref(), &handle)
            .await?;
        state.rate_limiter_handles.push(handle);
        Ok(stream)
    }

    async fn update_rate_limiters(&self) -> Result<(), WarpgateError> {
        let mut state = self.user_session_state.lock().await;
        let mut registry = self.rate_limiters_registry.lock().await;
        registry.update_session_rate_limiters(&mut state).await?;
        Ok(())
    }
}

/// Wehther a session can be started without approval or not
pub enum TargetSessionStart<O> {
    Started(AdmittedTarget<O>),
    // returns TargetAuthorization back -> proceed to Services::require_admin_approval/poll_admin_approval -> register_approved_target_session
    NeedsApproval(TargetAuthorization<O>),
}

/// An admitted target session = approved session + its DB ID
pub struct AdmittedTarget<O = warpgate_common::TargetOptions> {
    id: TargetSessionId,
    approved: ApprovedTarget<O>,
}

impl<O> AdmittedTarget<O> {
    pub const fn id(&self) -> TargetSessionId {
        self.id
    }

    pub fn into_approved(self) -> ApprovedTarget<O> {
        self.approved
    }
}

impl AdmittedTarget {
    pub fn narrow<O: TargetOptionsVariant>(self) -> Result<AdmittedTarget<O>, WarpgateError> {
        Ok(AdmittedTarget {
            id: self.id,
            approved: self.approved.narrow()?,
        })
    }
}

impl<O> std::ops::Deref for AdmittedTarget<O> {
    type Target = ApprovedTarget<O>;

    fn deref(&self) -> &Self::Target {
        &self.approved
    }
}

#[cfg(test)]
impl<O> TargetSessionStart<O> {
    /// For tests that set up an ungated target and only care about the row.
    ///
    /// Deliberately test-only: in production every caller answers
    /// `NeedsApproval` by holding the connection at the gate, and a shorthand
    /// for turning it into an error is a shorthand for skipping the gate.
    pub(crate) fn started(self) -> AdmittedTarget<O> {
        match self {
            Self::Started(started) => started,
            Self::NeedsApproval(_) => panic!("the test target should not require approval"),
        }
    }
}

impl Drop for WarpgateServerHandle {
    fn drop(&mut self) {
        let id = self.user_session_id;
        let state = self.state.clone();
        let user_session_state = self.user_session_state.clone();
        let provisional = self.provisional;
        let protocol = self.protocol;

        // Unowned sessions are managed by their backing (HTTP session store);
        // this handle is just a node-local view
        let end_user_session_on_drop = self.node_owned;
        tokio::spawn(async move {
            if provisional {
                State::discard_session(&state, id).await;
                return;
            }
            if !end_user_session_on_drop {
                state
                    .lock()
                    .await
                    .detach_user_session(id, &user_session_state);
                return;
            }
            // session ID from the span is needed for the audit log to get stored in the DB
            let username = user_session_state
                .lock()
                .await
                .user_info
                .as_ref()
                .map_or_else(String::new, |x| x.username.clone());
            let span = info_span!("Teardown", protocol=protocol.name(), session=%id, session_username=%username);
            State::remove_session(&state, id).instrument(span).await;
        });
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod sign_in_completion_tests {
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use sea_orm::ActiveValue::Set;
    use sea_orm::{ActiveModelTrait, Database, IntoActiveModel};
    use warpgate_db_entities::Parameters::{ConfigMigrationValues, set_config_migration_values};
    use warpgate_db_entities::User;
    use warpgate_db_migrations::migrate_database;

    use super::*;
    use crate::rate_limiting::RateLimiterRegistry;
    use crate::{SessionHandle, SessionsFilter, UserSessionStateInit};

    struct CountingHandle(Arc<AtomicUsize>);

    impl SessionHandle for CountingHandle {
        fn close(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    const INSIDE: &str = "10.1.2.3";
    const OUTSIDE: &str = "192.0.2.1";

    struct Fixture {
        db: DatabaseConnection,
        state: Arc<Mutex<State>>,
        user: AuthStateUserInfo,
    }

    async fn fixture_with(db: DatabaseConnection) -> Fixture {
        set_config_migration_values(ConfigMigrationValues::default());
        migrate_database(&db).await.unwrap();
        let rate_limiters = Arc::new(Mutex::new(RateLimiterRegistry::new(db.clone())));
        let state = State::new(&db, &rate_limiters, NodeId(Uuid::new_v4()));
        let id = Uuid::new_v4();
        User::ActiveModel {
            id: Set(id),
            username: Set("alice".into()),
            description: Set(String::new()),
            credential_policy: Set(serde_json::Value::Null),
            rate_limit_bytes_per_second: Set(None),
            ldap_server_id: Set(None),
            ldap_object_uuid: Set(None),
            allowed_ip_ranges: Set(serde_json::Value::Null),
        }
        .insert(&db)
        .await
        .unwrap();
        Fixture {
            db,
            state,
            user: AuthStateUserInfo {
                id,
                username: "alice".into(),
            },
        }
    }

    async fn fixture() -> Fixture {
        fixture_with(Database::connect("sqlite::memory:").await.unwrap()).await
    }

    impl Fixture {
        /// A sign-in in progress from `ip`, registered as an SSH connection
        /// is: before its credentials are checked.
        async fn sign_in_from(
            &self,
            ip: &str,
        ) -> (Arc<Mutex<WarpgateServerHandle>>, Arc<AtomicUsize>) {
            let closed = Arc::new(AtomicUsize::new(0));
            let handle = State::register_node_local_user_session(
                &self.state,
                Protocol::Ssh,
                UserSessionStateInit {
                    remote_address: Some(SocketAddr::new(ip.parse().unwrap(), 22)),
                    handle: Box::new(CountingHandle(closed.clone())),
                },
            )
            .await
            .unwrap();
            (handle, closed)
        }

        async fn set_ranges(&self, ranges: serde_json::Value) {
            let mut user = User::Entity::find_by_id(self.user.id)
                .one(&self.db)
                .await
                .unwrap()
                .unwrap()
                .into_active_model();
            user.allowed_ip_ranges = Set(ranges);
            user.update(&self.db).await.unwrap();
        }

        async fn attributed_user(&self, id: UserSessionId) -> Option<Uuid> {
            UserSession::Entity::find_by_id(id)
                .one(&self.db)
                .await
                .unwrap()
                .unwrap()
                .user_id
        }
    }

    /// The administrator narrows the ranges while the sign-in is in
    /// progress; completing it from an address now outside is refused.
    #[tokio::test]
    async fn a_sign_in_completing_outside_narrowed_ranges_is_refused() {
        let f = fixture().await;
        let (handle, _) = f.sign_in_from(OUTSIDE).await;
        f.set_ranges(serde_json::json!(["10.0.0.0/8"])).await;

        let completed = handle.lock().await.set_user_info(f.user.clone()).await;

        assert!(
            matches!(completed, Err(WarpgateError::UserNoLongerAdmitted)),
            "{completed:?}"
        );
        assert!(
            handle
                .lock()
                .await
                .user_session_state()
                .lock()
                .await
                .user_info
                .is_none()
        );
        // A retry is judged again, not taken for an already completed one.
        let again = handle.lock().await.set_user_info(f.user.clone()).await;
        assert!(matches!(again, Err(WarpgateError::UserNoLongerAdmitted)));
    }

    /// Narrowed ranges that still hold the address leave the sign-in alone.
    #[tokio::test]
    async fn a_sign_in_completing_inside_narrowed_ranges_is_admitted() {
        let f = fixture().await;
        let (handle, _) = f.sign_in_from(INSIDE).await;
        f.set_ranges(serde_json::json!(["10.0.0.0/8"])).await;

        handle
            .lock()
            .await
            .set_user_info(f.user.clone())
            .await
            .unwrap();

        let id = handle.lock().await.user_session_id();
        assert_eq!(f.attributed_user(id).await, Some(f.user.id));
    }

    /// The user is deleted while the sign-in is in progress.
    #[tokio::test]
    async fn a_sign_in_of_a_deleted_user_is_refused() {
        let f = fixture().await;
        let (handle, _) = f.sign_in_from(INSIDE).await;
        User::Entity::delete_by_id(f.user.id)
            .exec(&f.db)
            .await
            .unwrap();

        let completed = handle.lock().await.set_user_info(f.user.clone()).await;

        assert!(
            matches!(completed, Err(WarpgateError::UserNoLongerAdmitted)),
            "{completed:?}"
        );
    }

    /// A web sign-in is judged by the address of the request that completes
    /// it, which can differ from the one the browser session was opened from.
    #[tokio::test]
    async fn a_web_sign_in_is_judged_by_the_completing_address() {
        let f = fixture().await;
        let (handle, _) = f.sign_in_from(INSIDE).await;
        f.set_ranges(serde_json::json!(["10.0.0.0/8"])).await;
        let outside: IpAddr = OUTSIDE.parse().unwrap();

        let completed = handle
            .lock()
            .await
            .set_user_info_from(f.user.clone(), Some(outside))
            .await;

        assert!(
            matches!(completed, Err(WarpgateError::UserNoLongerAdmitted)),
            "{completed:?}"
        );
    }

    /// A session opened under a ticket is attributed when its target session
    /// starts; that attribution is judged the same way.
    #[tokio::test]
    async fn a_target_session_attributing_its_parent_is_judged_too() {
        let f = fixture().await;
        let (handle, _) = f.sign_in_from(OUTSIDE).await;
        f.set_ranges(serde_json::json!(["10.0.0.0/8"])).await;
        let target = Target {
            id: Uuid::new_v4(),
            name: "ssh".into(),
            description: String::new(),
            allow_roles: vec![],
            options: warpgate_common::TargetOptions::Http(warpgate_common::TargetHTTPOptions {
                url: "http://target".into(),
                tls: warpgate_common::Tls::default(),
                headers: Default::default(),
                external_host: None,
                public: false,
                unix_socket: None,
            }),
            rate_limit_bytes_per_second: None,
            group_id: None,
            ticket_max_duration_seconds: None,
            ticket_requests_disabled: false,
            ticket_require_approval: false,
            require_approval: false,
            ticket_max_uses: None,
        };

        let started = handle
            .lock()
            .await
            .start_target_session(crate::TargetAuthorization::for_test(
                f.user.clone(),
                target,
                Protocol::Ssh,
            ))
            .await;

        assert!(
            matches!(started, Err(WarpgateError::UserNoLongerAdmitted)),
            "{}",
            started.err().map(|e| e.to_string()).unwrap_or_default()
        );
    }

    /// The attribution is written before the user is read. A change of the
    /// user that commits after that read therefore commits after the
    /// attribution, and its close of the user's sessions, which runs after
    /// its commit, finds this one: by the row, and by the live handle, whose
    /// identity is set before the state lock the close waits on is released.
    #[tokio::test]
    async fn the_attribution_is_written_before_the_user_is_read() {
        let mut db = Database::connect("sqlite::memory:").await.unwrap();
        let log = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let sink = log.clone();
        db.set_metric_callback(move |info| sink.lock().unwrap().push(info.statement.sql.clone()));
        let f = fixture_with(db).await;
        let (handle, _) = f.sign_in_from(INSIDE).await;
        log.lock().unwrap().clear();

        handle
            .lock()
            .await
            .set_user_info(f.user.clone())
            .await
            .unwrap();

        let statements = log.lock().unwrap().clone();
        let attributed = statements
            .iter()
            .position(|s| s.starts_with(r#"UPDATE "user_sessions""#))
            .expect("the session is attributed");
        let read = statements
            .iter()
            .position(|s| s.starts_with("SELECT") && s.contains(r#"FROM "users""#))
            .expect("the user is read");
        assert!(attributed < read, "{statements:#?}");
    }

    /// The other side of the ordering: a change that commits just after a
    /// sign-in passed its check still ends that session through its close.
    #[tokio::test]
    async fn a_change_committing_after_the_check_closes_the_signed_in_session() {
        let f = fixture().await;
        let (handle, closed) = f.sign_in_from(OUTSIDE).await;
        handle
            .lock()
            .await
            .set_user_info(f.user.clone())
            .await
            .unwrap();
        let id = handle.lock().await.user_session_id();

        f.set_ranges(serde_json::json!(["10.0.0.0/8"])).await;
        let sweep = SessionsFilter::User { user_id: f.user.id };
        sweep.revoke(&f.db).await.unwrap();
        State::close_local_sessions(&f.state, &sweep).await;

        assert_eq!(closed.load(Ordering::SeqCst), 1);
        assert!(
            UserSession::Entity::find_by_id(id)
                .one(&f.db)
                .await
                .unwrap()
                .unwrap()
                .ended
                .is_some()
        );
    }
}
