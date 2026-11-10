use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use sea_orm::sea_query::Expr;
use sea_orm::{
    ColumnTrait, DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter, TransactionTrait,
};
use time::OffsetDateTime;
use tokio::sync::{Mutex, broadcast};
use tracing::warn;
use uuid::Uuid;
use warpgate_common::auth::{AuthState, CredentialKind};
use warpgate_common::{
    GlobalParams, Protocol, Secret, UserSessionId, WarpgateConfig, WarpgateError,
};
use warpgate_db_entities::Parameters::MfaEnforcement;
use warpgate_db_entities::{
    OtpCredential, Parameters, PendingSessionClose, PendingUserClose, SsoCredential, TargetSession,
    Ticket, TicketRequest, UserSession,
};

use crate::auth_state_store::ApprovalRequestSink;
use crate::cluster::{Cluster, ClusterNotification};
use crate::db::connect_to_db_and_migrate;
use crate::helpers::i64_seconds_to_duration;
use crate::live_streams::LiveStreams;
use crate::login_protection::LoginProtectionService;
use crate::rate_limiting::RateLimiterRegistry;
use crate::recordings::SessionRecordings;
use crate::resources::AdmittedSessions;
use crate::revocation::PendingRevocations;
use crate::{
    AuthStateStore, ConfigProviderEnum, DatabaseConfigProvider, ListenerStatusRegistry,
    SecretBackendRegistry, SessionsFilter, State,
};

#[derive(Clone)]
pub struct Services {
    pub db: DatabaseConnection,
    pub recordings: Arc<SessionRecordings>,
    pub config: Arc<Mutex<WarpgateConfig>>,
    pub cluster: Arc<Cluster>,
    pub state: Arc<Mutex<State>>,
    pub config_provider: Arc<ConfigProviderEnum>,
    pub auth_state_store: Arc<Mutex<AuthStateStore>>,
    pub admin_token: Arc<Option<Secret<String>>>,
    pub rate_limiter_registry: Arc<Mutex<RateLimiterRegistry>>,
    pub login_protection: Arc<LoginProtectionService>,
    pub global_params: Arc<GlobalParams>,
    pub listener_status: ListenerStatusRegistry,
    pub secret_backends: Arc<SecretBackendRegistry>,
    /// Live proxied HTTP requests by user and target, so a revocation can end
    /// them ([`Services::close_sessions_no_longer_authorised`]).
    pub live_streams: LiveStreams,
    /// Access changes whose session re-check failed, retried every 5 s.
    pub pending_revocations: PendingRevocations,
}

/// How often a node picks up self approvals decided elsewhere. One query per
/// node, so the interval is set by how long a user should wait after clicking.
const APPROVAL_SWEEP_INTERVAL: Duration = Duration::from_secs(1);

/// Session changes arrive in bursts (a scan opening connections, a mass
/// close); everything within this window becomes one cluster notification.
const SESSION_CHANGE_COALESCE_WINDOW: Duration = Duration::from_millis(100);

pub(crate) const TICKET_EXPIRY_SWEEP_INTERVAL: Duration = Duration::from_secs(5);

impl Services {
    pub async fn close_sessions(&self, scope: SessionsFilter) -> Result<(), WarpgateError> {
        scope.revoke(&self.db).await?;
        State::close_local_sessions(&self.state, &scope).await;
        self.cluster.close_sessions_on_peers(&scope).await;
        Ok(())
    }

    /// Closes sessions whose admission ended in a change that has already
    /// committed (a deleted ticket or target). The change cannot be undone, so
    /// a close that fails is queued and retried by the expiry sweep rather
    /// than reported: the sessions would otherwise stay open, because nothing
    /// else can find them (the ticket row is gone).
    pub async fn close_admitted_sessions(
        &self,
        sessions: AdmittedSessions,
    ) -> Result<(), WarpgateError> {
        if sessions.0.is_empty() {
            return Ok(());
        }
        let ids = sessions.0.clone();
        match self
            .close_sessions(SessionsFilter::Sessions { ids: sessions.0 })
            .await
        {
            Ok(()) => self.forget_persisted_closes(&ids).await,
            Err(error) => {
                warn!(%error, sessions = ids.len(), "Could not close sessions after their admission was deleted; retrying on the next sweep");
                self.pending_revocations.push_closes(ids);
            }
        }
        Ok(())
    }

    /// Settles the close of all of a user's open sessions that follows a
    /// committed edit or delete. The change's own transaction wrote the user's
    /// pending-close row ([`PendingUserClose::mark`], which returned `queued`),
    /// so the row exists exactly when the change committed and a restart cannot
    /// lose the close.
    ///
    /// A close that succeeded removes the row, unless a later change wrote it
    /// again (`queued` is then older than the row, so the row stays for that
    /// change's own close). A close that failed leaves the row for the expiry
    /// sweep. Nothing is queued in memory: the row is the one record, so a
    /// later close that succeeds also ends the retry, where a memory copy
    /// would go on closing sessions that opened after it.
    pub async fn settle_user_session_close(
        &self,
        user_id: Uuid,
        queued: OffsetDateTime,
        closed: Result<(), WarpgateError>,
    ) {
        match closed {
            Ok(()) => {
                if let Err(error) = PendingUserClose::clear(&self.db, user_id, queued).await {
                    warn!(%error, %user_id, "Could not clear the record of a closed user's sessions; the next sweep closes them again");
                }
            }
            Err(error) => {
                warn!(%error, %user_id, "Could not close the user's sessions after saving a change; retrying on the next sweep");
            }
        }
    }

    /// Whether a close of all of this user's sessions is still recorded in the
    /// database. A queue that cannot be read counts as pending, so an
    /// unreadable queue never lets a close be skipped.
    pub async fn user_close_pending(&self, user_id: Uuid) -> bool {
        PendingUserClose::is_pending(&self.db, user_id)
            .await
            .unwrap_or_else(|error| {
                warn!(%error, %user_id, "Could not read the queue of users whose sessions are waiting to be closed; treating this user's close as pending");
                true
            })
    }

    pub async fn delete_ticket_closing_sessions(
        &self,
        ticket_id: Uuid,
    ) -> Result<(), WarpgateError> {
        let txn = self.db.begin().await?;
        // Locked first: a session being registered under this ticket either
        // committed before this point, so it is collected below, or finds the
        // ticket gone and is refused.
        Ticket::lock_for_update(&txn, ticket_id).await?;
        let admitted = TargetSession::open_user_sessions_admitted_by_tickets(
            &txn,
            Ticket::Column::Id.eq(ticket_id),
        )
        .await?;
        // Recorded with the delete: if the node stops before the close below
        // succeeds, the sweep after the restart still finds these sessions.
        PendingSessionClose::mark(&txn, &admitted).await?;
        TicketRequest::Entity::delete_many()
            .filter(TicketRequest::Column::TicketId.eq(Some(ticket_id)))
            .exec(&txn)
            .await?;
        Ticket::Entity::delete_by_id(ticket_id).exec(&txn).await?;
        txn.commit().await?;

        self.close_admitted_sessions(AdmittedSessions(admitted))
            .await
    }

    pub async fn close_sessions_of_expired_tickets(&self) -> Result<(), WarpgateError> {
        let ids = TargetSession::open_user_sessions_admitted_by_tickets(
            &self.db,
            Ticket::Column::Expiry.lt(OffsetDateTime::now_utc()),
        )
        .await?;
        self.close_admitted_sessions(AdmittedSessions(ids)).await
    }

    pub async fn new(
        config: WarpgateConfig,
        admin_token: Option<String>,
        params: GlobalParams,
    ) -> Result<Self> {
        let db = connect_to_db_and_migrate(&config, &params).await?;
        let recordings = Arc::new(SessionRecordings::new(db.clone(), &params));

        let cluster = Arc::new(Cluster::new(db.clone(), config.store.http.listen.port()).await?);

        let config = Arc::new(Mutex::new(config));

        let config_provider = Arc::new(DatabaseConfigProvider::new(&db).into());

        let login_protection = Arc::new(LoginProtectionService::new(db.clone()).await?);

        let auth_state_store = Arc::new(Mutex::new(AuthStateStore::new(ApprovalRequestSink {
            db: db.clone(),
            cluster: cluster.clone(),
        })));

        tokio::spawn({
            let auth_state_store = auth_state_store.clone();
            let db = db.clone();
            async move {
                loop {
                    auth_state_store.lock().await.vacuum();
                    // Approval requests are normally deleted by their resolver
                    // or their waiter; rows whose owning node died are aged out
                    // here.
                    if let Err(error) = crate::approvals::reap_stale(&db).await {
                        warn!("Failed to reap stale session approval requests: {error}");
                    }
                    tokio::time::sleep(Duration::from_secs(60)).await;
                }
            }
        });

        let rate_limiter_registry = RateLimiterRegistry::new(db.clone());
        rate_limiter_registry.refresh().await?;
        let rate_limiter_registry = Arc::new(Mutex::new(rate_limiter_registry));

        // Opt-in usage analytics reporter. Always spawned; it re-reads consent
        // from the DB on every run and reports nothing unless enabled.
        crate::analytics::start(db.clone());

        // Background cleanup task — always started; cleanup_expired() skips
        // work (and logs its own summary) when there is something to do, and
        // re-reads the enabled flag from the DB on each run.
        {
            let login_protection = login_protection.clone();
            tokio::spawn(async move {
                let mut interval = crate::cluster::db_task_interval(Duration::from_secs(3600));
                loop {
                    interval.tick().await;
                    if let Err(e) = login_protection.cleanup_expired().await {
                        warn!("Login protection cleanup failed: {e}");
                    }
                }
            });
        }

        let secret_backends = Arc::new(SecretBackendRegistry::new(db.clone()));

        let services = Self {
            db: db.clone(),
            recordings,
            config: config.clone(),
            state: State::new(&db, &rate_limiter_registry, cluster.node_id),
            cluster,
            rate_limiter_registry,
            config_provider,
            auth_state_store,
            admin_token: Arc::new(admin_token.map(Secret::new)),
            login_protection,
            global_params: Arc::new(params),
            listener_status: Arc::default(),
            secret_backends,
            live_streams: LiveStreams::default(),
            pending_revocations: PendingRevocations::default(),
        };

        {
            let mut rx = services.state.lock().await.subscribe();
            let cluster = services.cluster.clone();
            tokio::spawn(async move {
                // A missed burst still means "changed" - one notification covers it
                while let Ok(()) | Err(broadcast::error::RecvError::Lagged(_)) = rx.recv().await {
                    tokio::time::sleep(SESSION_CHANGE_COALESCE_WINDOW).await;
                    while !matches!(
                        rx.try_recv(),
                        Err(broadcast::error::TryRecvError::Empty
                            | broadcast::error::TryRecvError::Closed)
                    ) {}
                    cluster.notify_global(ClusterNotification::SessionsChanged);
                }
            });
        }

        {
            let services = services.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(TICKET_EXPIRY_SWEEP_INTERVAL);
                // Role assignments that expired after this point are handled
                // on the next tick; `None` takes every expired one first.
                let mut role_expiry_swept_until = None;
                loop {
                    interval.tick().await;
                    if let Err(error) = services.close_sessions_of_expired_tickets().await {
                        warn!("Failed to close sessions of expired tickets: {error}");
                    }
                    services.retry_pending_revocations().await;
                    // The notification that normally triggers this re-check is
                    // best effort towards other nodes; the sweep makes a missed
                    // one cost at most one interval.
                    if let Err(error) = services.reauthorize_live_streams().await {
                        warn!("Failed to re-check live proxied requests: {error}");
                    }
                    let now = OffsetDateTime::now_utc();
                    match services
                        .close_sessions_of_expired_role_assignments(role_expiry_swept_until, now)
                        .await
                    {
                        Ok(()) => role_expiry_swept_until = Some(now),
                        Err(error) => {
                            warn!("Failed to close sessions of expired role assignments: {error}");
                        }
                    }
                }
            });
        }

        // Any node's revocation re-checks this node's live proxied requests.
        {
            let services = services.clone();
            let mut rx = services.cluster.subscribe();
            tokio::spawn(async move {
                loop {
                    match rx.recv().await {
                        Ok(ClusterNotification::LiveStreamsReauthorize)
                        | Err(broadcast::error::RecvError::Lagged(_)) => {
                            if let Err(error) = services.reauthorize_live_streams().await {
                                warn!("Failed to re-check live proxied requests: {error}");
                            }
                        }
                        Ok(_) => {}
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
            });
        }

        // Asynchronously detect user approvals received by other nodes
        // and apply them to our AuthStates
        {
            let services = services.clone();
            tokio::spawn(async move {
                let mut interval = crate::cluster::db_task_interval(APPROVAL_SWEEP_INTERVAL);
                loop {
                    interval.tick().await;
                    if let Err(error) = services.apply_decided_user_approvals().await {
                        warn!("Failed to apply resolved session approvals: {error}");
                    }
                }
            });
        }

        Ok(services)
    }

    pub async fn admin_approval_timeout(&self) -> Result<Duration, WarpgateError> {
        crate::approvals::admin_approval_timeout(&self.db).await
    }

    pub async fn admin_approval_grace_period(&self) -> Result<Option<Duration>, WarpgateError> {
        Ok(Parameters::Entity::get(&self.db)
            .await?
            .admin_approval_grace_period_seconds
            .and_then(i64_seconds_to_duration))
    }

    /// Resolves the user/policy (without the store lock) and inserts a new
    /// [`AuthState`] under a brief store lock. This is the only sanctioned way
    /// to create an auth state, so the "no DB I/O while holding the store lock"
    /// invariant is enforced structurally rather than by convention.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_auth_state(
        &self,
        session_id: &UserSessionId,
        username: &str,
        protocol: Protocol,
        target_name: &str,
        supported_credential_types: &[CredentialKind],
        remote_ip: Option<IpAddr>,
        rate_limit_credential_type: Option<&str>,
    ) -> Result<Arc<Mutex<AuthState>>, WarpgateError> {
        let (user, policy) = AuthStateStore::resolve_user_and_policy(
            &self.config_provider,
            &self.login_protection,
            username,
            protocol,
            supported_credential_types,
            remote_ip,
            rate_limit_credential_type,
        )
        .await?;

        // Link user session to this node which is gonna hold the auth state
        UserSession::Entity::update_many()
            .col_expr(
                UserSession::Column::AuthStateNodeId,
                Expr::value(self.cluster.node_id),
            )
            .filter(UserSession::Column::Id.eq(*session_id))
            .exec(&self.db)
            .await?;

        Ok(self.auth_state_store.lock().await.create(
            session_id,
            &user,
            protocol,
            target_name,
            policy,
            remote_ip,
        ))
    }

    async fn user_has_sso_credential(&self, user_id: Uuid) -> Result<bool, WarpgateError> {
        Ok(SsoCredential::Entity::find()
            .filter(SsoCredential::Column::UserId.eq(user_id))
            .count(&self.db)
            .await?
            > 0)
    }

    async fn user_has_otp_credential(&self, user_id: Uuid) -> Result<bool, WarpgateError> {
        Ok(OtpCredential::Entity::find()
            .filter(OtpCredential::Column::UserId.eq(user_id))
            .count(&self.db)
            .await?
            > 0)
    }

    /// User's SSO credential can override MFA enforcement if configured
    pub async fn effective_mfa_enforcement(
        &self,
        parameters: &Parameters::Model,
        user_id: Uuid,
    ) -> Result<MfaEnforcement, WarpgateError> {
        let has_sso = self.user_has_sso_credential(user_id).await?;
        Ok(parameters.effective_mfa_enforcement_for_user(has_sso))
    }

    pub async fn mfa_required_factor(
        &self,
        parameters: &Parameters::Model,
        user_id: Uuid,
        protocol: Protocol,
    ) -> Result<Option<CredentialKind>, WarpgateError> {
        if parameters.mfa_enforcement == MfaEnforcement::Off {
            // quick exit without querying for creds
            return Ok(None);
        }
        let has_sso = self.user_has_sso_credential(user_id).await?;
        let has_totp = self.user_has_otp_credential(user_id).await?;
        Ok(parameters.mfa_required_factor(protocol, has_sso, has_totp))
    }

    pub async fn mfa_setup_required(
        &self,
        parameters: &Parameters::Model,
        user_id: Uuid,
    ) -> Result<bool, WarpgateError> {
        if self.effective_mfa_enforcement(parameters, user_id).await? == MfaEnforcement::Off {
            return Ok(false);
        }
        Ok(!self.user_has_otp_credential(user_id).await?)
    }

    /// Configured web-approval caching window, or `None` if caching is disabled.
    pub async fn web_approval_grace_period(&self) -> Result<Option<Duration>, WarpgateError> {
        crate::approvals::web_approval_grace_period(&self.db).await
    }

    /// If a matching web approval is still within the grace period, satisfies the
    /// pending `WebUserApproval` requirement and logs an audit event.
    pub async fn try_web_approval_bypass(
        &self,
        state_arc: &Arc<Mutex<AuthState>>,
    ) -> Result<bool, WarpgateError> {
        crate::approvals::try_web_approval_bypass(&self.db, &self.cluster, state_arc).await
    }
}
