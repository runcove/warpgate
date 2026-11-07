//! Cutting live sessions whose target their user may no longer reach, after a
//! change that can take access away.

use std::collections::HashMap;

use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QuerySelect};
use time::OffsetDateTime;
use tracing::{info, warn};
use uuid::Uuid;
use warpgate_common::{Protocol, TargetOptions, UserSessionId, WarpgateError};
use warpgate_db_entities::{
    PendingSessionClose, TargetSession, User, UserRoleAssignment, UserSession,
};
use warpgate_sso::{SsoLoginResponse, SsoProviderConfig};

use crate::cluster::ClusterNotification;
use crate::live_streams::LiveStreamKind;
use crate::{ConfigProvider, Services, SessionsFilter, apply_sso_mappings, resolve_sso_username};

/// Whose live sessions an access change can affect.
#[derive(Debug, Clone)]
pub enum AccessChange {
    /// These users' role memberships changed.
    Users(Vec<Uuid>),
    /// A user, by name, whose roles an SSO login re-synced.
    Username(String),
    /// These targets lost roles, stopped being public, or were deleted.
    Targets(Vec<Uuid>),
    /// A role went away: anyone may be affected.
    All,
}

/// Queue size past which a warning is logged. Nothing is ever dropped: the
/// queue is a set of session ids, so it cannot outgrow the real sessions.
const PENDING_CLOSES_WARN_AT: usize = 10_000;

/// Sessions closed per attempt in a retry.
const CLOSE_RETRY_CHUNK: usize = 100;

/// Example ids named in a retry summary line.
const CLOSE_RETRY_EXAMPLES: usize = 3;

/// What one sweep of the close retry queue did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct CloseRetryOutcome {
    /// Ids taken from the queue for this sweep.
    pub retried: usize,
    /// Ids whose close failed again and went back into the queue.
    pub failed_count: usize,
    /// Ids waiting in the queue once the sweep ended (the queue length, which
    /// also counts anything queued meanwhile).
    pub queued: usize,
    /// A few of the failing ids, at most [`CLOSE_RETRY_EXAMPLES`].
    pub examples: Vec<UserSessionId>,
    /// The first error seen in the sweep.
    pub first_error: Option<String>,
}

impl CloseRetryOutcome {
    fn record_failure(&mut self, id: UserSessionId, error: &WarpgateError) {
        self.failed_count += 1;
        if self.examples.len() < CLOSE_RETRY_EXAMPLES {
            self.examples.push(id);
        }
        if self.first_error.is_none() {
            self.first_error = Some(error.to_string());
        }
    }

    /// The single log line for the sweep: its size does not grow with the
    /// number of failing ids.
    pub fn summary(&self) -> String {
        let closed = self.retried - self.failed_count;
        let mut line = format!(
            "Close retry: {} retried, {} closed, {} failed, {} still queued",
            self.retried, closed, self.failed_count, self.queued
        );
        if !self.examples.is_empty() {
            let ids: Vec<String> = self.examples.iter().map(|id| id.0.to_string()).collect();
            line.push_str(&format!(" (e.g. {})", ids.join(", ")));
        }
        if let Some(error) = &self.first_error {
            let error = error.replace(['\n', '\r'], " ");
            line.push_str(&format!("; first error: {error}"));
        }
        line
    }
}

/// Access changes whose re-check failed, and sessions whose close failed
/// after the change that ended their admission had committed, both retried by
/// the expiry sweep.
#[derive(Clone, Default)]
pub struct PendingRevocations {
    changes: std::sync::Arc<std::sync::Mutex<Vec<AccessChange>>>,
    closes: std::sync::Arc<std::sync::Mutex<std::collections::BTreeSet<UserSessionId>>>,
}

impl PendingRevocations {
    /// A panic elsewhere must not drop revocations: a poisoned lock is used
    /// as is.
    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<AccessChange>> {
        self.changes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn lock_closes(&self) -> std::sync::MutexGuard<'_, std::collections::BTreeSet<UserSessionId>> {
        self.closes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn push(&self, change: AccessChange) {
        self.lock().push(change);
    }

    fn take(&self) -> Vec<AccessChange> {
        std::mem::take(&mut *self.lock())
    }

    /// Queues sessions whose close failed. Ids already queued collapse. An
    /// id is never dropped: a revoked session left open is the fault this
    /// queue exists to prevent.
    pub(crate) fn push_closes(&self, ids: Vec<UserSessionId>) {
        let mut queue = self.lock_closes();
        queue.extend(ids);
        if queue.len() > PENDING_CLOSES_WARN_AT {
            warn!(
                queued = queue.len(),
                "Many sessions are waiting for a close retry"
            );
        }
    }

    fn take_closes(&self) -> Vec<UserSessionId> {
        std::mem::take(&mut *self.lock_closes())
            .into_iter()
            .collect()
    }

    /// Sessions waiting for a close to be retried.
    pub fn closes_len(&self) -> usize {
        self.lock_closes().len()
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Services {
    /// Closes the live sessions whose user may no longer reach the target the
    /// session is connected to, after `change` committed. Sessions to targets
    /// the user can still reach stay up.
    ///
    /// "May reach" is [`ConfigProvider::authorize_target_by_id`], the check
    /// the connection path makes (`authorize_for_target`), so there is one
    /// definition of it. Closing goes through [`Services::close_sessions`], so
    /// the database row ends and every node drops its live handle.
    ///
    /// Left alone:
    /// - Sessions a ticket admitted: a ticket grants its one target whatever
    ///   the user's roles, and deleting the ticket is what cuts them.
    /// - HTTP browser sessions: the proxy re-authorizes every request
    ///   (`catchall::get_target_for_request` calls `authorize_for_target`), so
    ///   a revoked target is refused on the next request, and one browser
    ///   session spans several targets, which cutting it would take away too.
    ///   Requests still running to a revoked target (websockets, streamed
    ///   bodies) are ended instead, on every node, through
    ///   [`ClusterNotification::LiveStreamsReauthorize`] and
    ///   [`Self::reauthorize_live_streams`]; the browser session stays. That
    ///   includes requests admitted through the public bypass, which end once
    ///   the target is no longer public (or is deleted), whoever made them.
    ///
    /// Fails closed and cannot lose a revocation: the cluster is told to
    /// re-check live streams before anything that can fail; a session whose
    /// check errors is closed; and if the work itself fails, `change` is
    /// queued and retried by the 5 s expiry sweep
    /// ([`Self::retry_pending_revocations`]). So this returns `Ok` once the
    /// revocation is either done or queued.
    pub async fn close_sessions_no_longer_authorised(
        &self,
        change: AccessChange,
    ) -> Result<(), WarpgateError> {
        // Long-lived proxied HTTP requests, on this node and the others.
        self.cluster
            .notify_global(ClusterNotification::LiveStreamsReauthorize);
        if let Err(error) = self
            .try_close_sessions_no_longer_authorised(change.clone())
            .await
        {
            warn!(%error, ?change, "Could not close sessions after an access change; retrying on the next sweep");
            self.pending_revocations.push(change);
        }
        Ok(())
    }

    /// Resolve the Warpgate user for a verified SSO response and apply its
    /// role mappings. If the mappings took a role away, or failed partway (a
    /// role may already be gone), the user's sessions and live streams are
    /// re-checked; that re-check cannot be lost (see
    /// [`Self::close_sessions_no_longer_authorised`]).
    pub async fn resolve_and_map_sso_user(
        &self,
        provider_config: &SsoProviderConfig,
        response: &SsoLoginResponse,
    ) -> Result<Option<String>, WarpgateError> {
        let cp = self.config_provider.as_ref();
        let Some(username) = resolve_sso_username(cp, provider_config, response).await? else {
            return Ok(None);
        };
        let mapped = apply_sso_mappings(cp, provider_config, response, &username).await;
        if !matches!(mapped, Ok(false)) {
            self.close_sessions_no_longer_authorised(AccessChange::Username(username.clone()))
                .await?;
        }
        mapped.map(|_| Some(username))
    }

    /// Runs the access changes whose re-check failed earlier; one that fails
    /// again is queued again.
    pub async fn retry_pending_revocations(&self) {
        for change in self.pending_revocations.take() {
            let _ = self.close_sessions_no_longer_authorised(change).await;
        }
        self.retry_pending_closes().await;
    }

    /// Retries queued session closes in chunks. A chunk that fails is retried
    /// id by id, so one bad id does not hold back the rest; only the ids that
    /// still fail are queued again. A session already ended is a no-op for the
    /// close (it only touches open sessions) and is not queued again.
    ///
    /// One summary line is logged per sweep that had anything to retry, however
    /// many ids failed. Nothing is ever dropped from the queue.
    async fn retry_pending_closes(&self) -> CloseRetryOutcome {
        let mut ids: std::collections::BTreeSet<UserSessionId> =
            self.pending_revocations.take_closes().into_iter().collect();
        // Closes recorded in the database survive a restart, which the
        // in-memory queue does not.
        match PendingSessionClose::pending(&self.db).await {
            Ok(persisted) => ids.extend(persisted),
            Err(error) => {
                warn!(%error, "Could not read the sessions waiting to be closed; retrying the queued ones only");
            }
        }
        let ids: Vec<UserSessionId> = ids.into_iter().collect();
        let mut outcome = CloseRetryOutcome {
            retried: ids.len(),
            ..Default::default()
        };
        for chunk in ids.chunks(CLOSE_RETRY_CHUNK) {
            if self
                .close_sessions(SessionsFilter::Sessions {
                    ids: chunk.to_vec(),
                })
                .await
                .is_ok()
            {
                self.forget_persisted_closes(chunk).await;
                continue;
            }
            for id in chunk {
                match self
                    .close_sessions(SessionsFilter::Sessions { ids: vec![*id] })
                    .await
                {
                    Ok(()) => self.forget_persisted_closes(&[*id]).await,
                    Err(error) => {
                        outcome.record_failure(*id, &error);
                        self.pending_revocations.push_closes(vec![*id]);
                    }
                }
            }
        }
        outcome.queued = self.pending_revocations.closes_len();
        if outcome.retried > 0 {
            if outcome.failed_count > 0 {
                warn!("{}", outcome.summary());
            } else {
                info!("{}", outcome.summary());
            }
        }
        outcome
    }

    /// Removes the database record of closes owed once the sessions are
    /// closed. A failure is only logged: the record stays, and the next sweep
    /// closes the (already ended) session again, which is a no-op.
    pub(crate) async fn forget_persisted_closes(&self, ids: &[UserSessionId]) {
        if let Err(error) = PendingSessionClose::clear(&self.db, ids).await {
            warn!(%error, sessions = ids.len(), "Could not clear the record of closed sessions");
        }
    }

    async fn try_close_sessions_no_longer_authorised(
        &self,
        change: AccessChange,
    ) -> Result<(), WarpgateError> {
        let mut query = TargetSession::Entity::find()
            .inner_join(UserSession::Entity)
            .filter(TargetSession::Column::Ended.is_null())
            .filter(TargetSession::Column::TicketId.is_null())
            .filter(UserSession::Column::Ended.is_null())
            .filter(UserSession::Column::UserId.is_not_null())
            .filter(UserSession::Column::Protocol.ne(Protocol::Http.name()));
        query = match change {
            AccessChange::Users(ids) => query.filter(UserSession::Column::UserId.is_in(ids)),
            AccessChange::Username(username) => {
                let Some(user) = User::Entity::find()
                    .filter(User::Entity::username_eq_ci(&username))
                    .one(&self.db)
                    .await?
                else {
                    return Ok(());
                };
                query.filter(UserSession::Column::UserId.eq(user.id))
            }
            AccessChange::Targets(ids) => query.filter(TargetSession::Column::TargetId.is_in(ids)),
            AccessChange::All => query,
        };
        let open: Vec<(UserSessionId, Option<Uuid>, Uuid)> = query
            .select_only()
            .column(TargetSession::Column::UserSessionId)
            .column(UserSession::Column::UserId)
            .column(TargetSession::Column::TargetId)
            .into_tuple()
            .all(&self.db)
            .await?;

        let mut verdicts = HashMap::new();
        let mut ids = vec![];
        for (session_id, user_id, target_id) in open {
            let Some(user_id) = user_id else {
                continue;
            };
            let authorized = match verdicts.get(&(user_id, target_id)) {
                Some(authorized) => *authorized,
                None => {
                    let authorized = self.still_authorised(user_id, target_id).await;
                    verdicts.insert((user_id, target_id), authorized);
                    authorized
                }
            };
            if !authorized {
                ids.push(session_id);
            }
        }
        ids.sort();
        ids.dedup();
        if !ids.is_empty() {
            info!(
                sessions = ids.len(),
                "Closing sessions whose user may no longer reach their target"
            );
            self.close_sessions(SessionsFilter::Sessions { ids })
                .await?;
        }
        Ok(())
    }

    /// [`ConfigProvider::authorize_target_by_id`], failing closed: a check that
    /// errors counts as not authorised.
    async fn still_authorised(&self, user_id: Uuid, target_id: Uuid) -> bool {
        match self
            .config_provider
            .authorize_target_by_id(user_id, target_id)
            .await
        {
            Ok(authorized) => authorized,
            Err(error) => {
                warn!(%error, %user_id, %target_id, "Could not re-check access; treating it as revoked");
                false
            }
        }
    }

    /// Whether `target_id` is still reachable through the public bypass: it
    /// exists, is an HTTP target, is `public` and does not require approval.
    /// This is the predicate that admits a request through the bypass
    /// (`catchall::decide_public_target_access`). Fails closed: a lookup that
    /// errors counts as no longer shared.
    pub async fn public_target_still_shared(&self, target_id: Uuid) -> bool {
        match self.config_provider.get_target_by_id(target_id).await {
            Ok(Some(target)) => {
                !target.require_approval
                    && matches!(&target.options, TargetOptions::Http(options) if options.public)
            }
            Ok(None) => false,
            Err(error) => {
                warn!(%error, %target_id, "Could not re-check that the target is public; treating it as unshared");
                false
            }
        }
    }

    /// Ends this node's live proxied HTTP requests that may no longer run, by
    /// the rule that admitted each. A role-based request ends when its user
    /// may no longer reach the target, by the same check as
    /// [`Self::close_sessions_no_longer_authorised`]. A public-bypass request
    /// ends when the target is no longer public
    /// ([`Self::public_target_still_shared`]), whatever the user's roles. The
    /// browser session that carries them, and its requests to other targets,
    /// stay. A pair whose check errors is ended too (fail closed).
    pub async fn reauthorize_live_streams(&self) -> Result<(), WarpgateError> {
        // One lookup per target in a pass, however many visitors share it.
        let mut shared: std::collections::HashMap<Uuid, bool> = std::collections::HashMap::new();
        for (user_id, target_id, kind) in self.live_streams.in_use() {
            let allowed = match kind {
                LiveStreamKind::RoleBased => self.still_authorised(user_id, target_id).await,
                LiveStreamKind::Public => match shared.get(&target_id) {
                    Some(allowed) => *allowed,
                    None => {
                        let allowed = self.public_target_still_shared(target_id).await;
                        shared.insert(target_id, allowed);
                        allowed
                    }
                },
            };
            if !allowed {
                let ended = self.live_streams.cancel(user_id, target_id, kind);
                info!(
                    %user_id,
                    %target_id,
                    ended,
                    ?kind,
                    "Ended live proxied requests to a target the user may no longer reach"
                );
            }
        }
        Ok(())
    }

    /// Closes the sessions of users whose role assignment expired after
    /// `since` (every expired one, if `None`) and no later than `now`, as an
    /// admin's revocation would. Run on the ticket-expiry sweep.
    pub async fn close_sessions_of_expired_role_assignments(
        &self,
        since: Option<OffsetDateTime>,
        now: OffsetDateTime,
    ) -> Result<(), WarpgateError> {
        let mut query = UserRoleAssignment::Entity::find()
            .filter(UserRoleAssignment::Column::RevokedAt.is_null())
            .filter(UserRoleAssignment::Column::ExpiresAt.lte(now));
        if let Some(since) = since {
            query = query.filter(UserRoleAssignment::Column::ExpiresAt.gt(since));
        }
        let users: Vec<Uuid> = query
            .select_only()
            .column(UserRoleAssignment::Column::UserId)
            .distinct()
            .into_tuple()
            .all(&self.db)
            .await?;
        if users.is_empty() {
            return Ok(());
        }
        self.close_sessions_no_longer_authorised(AccessChange::Users(users))
            .await
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use sea_orm::ActiveValue::Set;
    use sea_orm::{ActiveModelTrait, DatabaseConnection};
    use time::OffsetDateTime;
    use warpgate_common::TargetSessionId;
    use warpgate_db_entities::Target::TargetKind;
    use warpgate_db_entities::{Role, Target, TargetRoleAssignment, UserRoleAssignment};

    use super::*;
    use crate::approvals::tests::delivery::test_services;

    async fn migrated_db() -> DatabaseConnection {
        warpgate_db_entities::Parameters::set_config_migration_values(
            warpgate_db_entities::Parameters::ConfigMigrationValues::default(),
        );
        let db = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
        warpgate_db_migrations::migrate_database(&db).await.unwrap();
        db
    }

    async fn user(db: &DatabaseConnection) -> Uuid {
        let id = Uuid::new_v4();
        User::ActiveModel {
            id: Set(id),
            username: Set(format!("user-{id}")),
            description: Set(String::new()),
            credential_policy: Set(serde_json::Value::Null),
            rate_limit_bytes_per_second: Set(None),
            ldap_server_id: Set(None),
            ldap_object_uuid: Set(None),
            allowed_ip_ranges: Set(serde_json::Value::Null),
        }
        .insert(db)
        .await
        .unwrap();
        id
    }

    async fn role(db: &DatabaseConnection) -> Uuid {
        let id = Uuid::new_v4();
        Role::ActiveModel {
            id: Set(id),
            name: Set(format!("role-{id}")),
            description: Set(String::new()),
            is_default: Set(false),
        }
        .insert(db)
        .await
        .unwrap();
        id
    }

    async fn target(db: &DatabaseConnection) -> Uuid {
        let id = Uuid::new_v4();
        Target::ActiveModel {
            id: Set(id),
            name: Set(format!("target-{id}")),
            description: Set(String::new()),
            kind: Set(TargetKind::Ssh),
            options: Set(serde_json::json!({"ssh": {"host": "h"}})),
            rate_limit_bytes_per_second: Set(None),
            group_id: Set(None),
            ticket_max_duration_seconds: Set(None),
            ticket_requests_disabled: Set(false),
            ticket_require_approval: Set(false),
            ticket_max_uses: Set(None),
            require_approval: Set(false),
        }
        .insert(db)
        .await
        .unwrap();
        id
    }

    async fn grant_user(db: &DatabaseConnection, user_id: Uuid, role_id: Uuid) {
        UserRoleAssignment::ActiveModel {
            user_id: Set(user_id),
            role_id: Set(role_id),
            granted_at: Set(Some(OffsetDateTime::now_utc())),
            expires_at: Set(None),
            revoked_at: Set(None),
        }
        .insert(db)
        .await
        .unwrap();
    }

    async fn grant_target(db: &DatabaseConnection, target_id: Uuid, role_id: Uuid) {
        TargetRoleAssignment::ActiveModel {
            target_id: Set(target_id),
            role_id: Set(role_id),
        }
        .insert(db)
        .await
        .unwrap();
    }

    /// An open SSH session of `user_id` connected to `target_id`.
    async fn session(db: &DatabaseConnection, user_id: Uuid, target_id: Uuid) -> UserSessionId {
        let id = UserSessionId(Uuid::new_v4());
        UserSession::ActiveModel {
            id: Set(id),
            username: Set(Some("someone".into())),
            user_id: Set(Some(user_id)),
            remote_address: Set("127.0.0.1:22".into()),
            started: Set(OffsetDateTime::now_utc()),
            ended: Set(None),
            protocol: Set(Protocol::Ssh.name().into()),
            node_id: Set(None),
            auth_state_node_id: Set(None),
        }
        .insert(db)
        .await
        .unwrap();
        TargetSession::ActiveModel {
            id: Set(TargetSessionId(Uuid::new_v4())),
            user_session_id: Set(id),
            target_snapshot: Set(r#"{"name":"t"}"#.into()),
            target_id: Set(target_id),
            started: Set(OffsetDateTime::now_utc()),
            ended: Set(None),
            ticket_id: Set(None),
            node_id: Set(None),
        }
        .insert(db)
        .await
        .unwrap();
        id
    }

    async fn ended(db: &DatabaseConnection, id: UserSessionId) -> bool {
        UserSession::Entity::find_by_id(id)
            .one(db)
            .await
            .unwrap()
            .unwrap()
            .ended
            .is_some()
    }

    async fn open_user_session(db: &DatabaseConnection, username: &str) -> UserSessionId {
        let id = UserSessionId(Uuid::new_v4());
        UserSession::ActiveModel {
            id: Set(id),
            username: Set(Some(username.into())),
            user_id: Set(None),
            remote_address: Set("127.0.0.1:22".into()),
            started: Set(OffsetDateTime::now_utc()),
            ended: Set(None),
            protocol: Set("HTTP".into()),
            node_id: Set(None),
            auth_state_node_id: Set(None),
        }
        .insert(db)
        .await
        .unwrap();
        id
    }

    /// The same ids queued again collapse into one entry each.
    #[tokio::test]
    async fn queued_closes_collapse_duplicates() {
        let pending = PendingRevocations::default();
        let ids: Vec<_> = (0..3).map(|_| UserSessionId(Uuid::new_v4())).collect();
        pending.push_closes(ids.clone());
        pending.push_closes(ids.clone());
        pending.push_closes(vec![ids[0], ids[0]]);
        assert_eq!(pending.closes_len(), 3);
    }

    /// However large the queue gets, no id is dropped.
    #[tokio::test]
    async fn the_close_queue_never_drops_an_id() {
        let pending = PendingRevocations::default();
        let ids: Vec<_> = (0..PENDING_CLOSES_WARN_AT + 5)
            .map(|_| UserSessionId(Uuid::new_v4()))
            .collect();
        pending.push_closes(ids.clone());
        pending.push_closes(ids.clone());
        assert_eq!(pending.closes_len(), ids.len());
        let taken = pending.take_closes();
        let taken: std::collections::HashSet<_> = taken.into_iter().collect();
        assert!(ids.iter().all(|id| taken.contains(id)));
    }

    /// One session whose close keeps failing does not hold back the others
    /// queued with it; only it stays queued, and an already-ended session is
    /// not queued again.
    #[tokio::test]
    async fn a_failing_close_does_not_block_the_others() {
        use sea_orm::ConnectionTrait;

        let db = migrated_db().await;
        let services = test_services(&db).await;
        let good_a = open_user_session(&db, "good").await;
        let bad = open_user_session(&db, "bad").await;
        let good_b = open_user_session(&db, "good").await;
        let already_ended = open_user_session(&db, "good").await;
        warpgate_db_entities::UserSession::revoke(&db, already_ended)
            .await
            .unwrap();

        db.execute_unprepared(
            "CREATE TRIGGER fail_bad BEFORE UPDATE ON user_sessions \
             WHEN OLD.username = 'bad' \
             BEGIN SELECT RAISE(ABORT, 'close failed'); END",
        )
        .await
        .unwrap();
        services
            .pending_revocations
            .push_closes(vec![good_a, bad, good_b, already_ended]);
        services.retry_pending_revocations().await;

        assert!(ended(&db, good_a).await);
        assert!(ended(&db, good_b).await);
        assert!(!ended(&db, bad).await);
        assert_eq!(services.pending_revocations.closes_len(), 1);

        db.execute_unprepared("DROP TRIGGER fail_bad")
            .await
            .unwrap();
        services.retry_pending_revocations().await;
        assert!(ended(&db, bad).await);
        assert_eq!(services.pending_revocations.closes_len(), 0);
    }

    /// A sweep with many failing ids yields one summary, whose length does not
    /// depend on how many ids failed, and whose queue length matches the queue.
    #[test]
    fn the_retry_summary_is_one_line_however_many_ids_fail() {
        let mut outcome = CloseRetryOutcome {
            retried: 5000,
            queued: 4000,
            ..Default::default()
        };
        let error = WarpgateError::InvalidCredentialType;
        for _ in 0..4000 {
            outcome.record_failure(UserSessionId(Uuid::new_v4()), &error);
        }
        let line = outcome.summary();
        assert!(!line.contains('\n'));
        assert!(line.contains("5000 retried, 1000 closed, 4000 failed, 4000 still queued"));
        assert_eq!(outcome.examples.len(), CLOSE_RETRY_EXAMPLES);
        assert_eq!(line.matches("(e.g. ").count(), 1);
        assert!(
            line.len() < 400,
            "summary grew with the ids: {}",
            line.len()
        );
    }

    /// The sweep's reported queue length is the queue's own length.
    #[tokio::test]
    async fn the_retry_outcome_reports_the_queue_length() {
        use sea_orm::ConnectionTrait;

        let db = migrated_db().await;
        let services = test_services(&db).await;
        let good = open_user_session(&db, "good").await;
        let bad_a = open_user_session(&db, "bad").await;
        let bad_b = open_user_session(&db, "bad").await;
        db.execute_unprepared(
            "CREATE TRIGGER fail_bad BEFORE UPDATE ON user_sessions \
             WHEN OLD.username = 'bad' \
             BEGIN SELECT RAISE(ABORT, 'close failed'); END",
        )
        .await
        .unwrap();
        services
            .pending_revocations
            .push_closes(vec![good, bad_a, bad_b]);
        let outcome = services.retry_pending_closes().await;
        assert_eq!(outcome.retried, 3);
        assert_eq!(outcome.failed_count, 2);
        assert_eq!(outcome.queued, 2);
        assert_eq!(outcome.queued, services.pending_revocations.closes_len());
        assert!(outcome.summary().contains("2 still queued"));
        assert!(outcome.summary().contains("1 closed"));
    }

    async fn revoke_user_role(db: &DatabaseConnection, user_id: Uuid, role_id: Uuid) {
        UserRoleAssignment::Entity::delete_by_id((user_id, role_id))
            .exec(db)
            .await
            .unwrap();
    }

    /// A role taken from a user ends their session to the target only that
    /// role granted, and keeps their session to a target another role grants.
    #[tokio::test]
    async fn removing_a_users_role_ends_only_the_sessions_it_granted() {
        let db = migrated_db().await;
        let services = test_services(&db).await;
        let (alice, lost, kept) = (user(&db).await, role(&db).await, role(&db).await);
        let (lost_target, kept_target) = (target(&db).await, target(&db).await);
        grant_user(&db, alice, lost).await;
        grant_user(&db, alice, kept).await;
        grant_target(&db, lost_target, lost).await;
        grant_target(&db, kept_target, kept).await;
        let to_lost = session(&db, alice, lost_target).await;
        let to_kept = session(&db, alice, kept_target).await;

        revoke_user_role(&db, alice, lost).await;
        services
            .close_sessions_no_longer_authorised(AccessChange::Users(vec![alice]))
            .await
            .unwrap();

        assert!(ended(&db, to_lost).await);
        assert!(!ended(&db, to_kept).await);
    }

    /// A target still granted to the user through another role keeps its
    /// session.
    #[tokio::test]
    async fn a_target_still_granted_through_another_role_keeps_its_session() {
        let db = migrated_db().await;
        let services = test_services(&db).await;
        let (alice, first, second) = (user(&db).await, role(&db).await, role(&db).await);
        let both = target(&db).await;
        grant_user(&db, alice, first).await;
        grant_user(&db, alice, second).await;
        grant_target(&db, both, first).await;
        grant_target(&db, both, second).await;
        let to_both = session(&db, alice, both).await;

        revoke_user_role(&db, alice, first).await;
        services
            .close_sessions_no_longer_authorised(AccessChange::Users(vec![alice]))
            .await
            .unwrap();

        assert!(!ended(&db, to_both).await);
    }

    /// A target taken from a role ends the sessions of every user who reached
    /// it only through that role, and no one else's.
    #[tokio::test]
    async fn removing_a_target_from_a_role_ends_every_user_who_lost_it() {
        let db = migrated_db().await;
        let services = test_services(&db).await;
        let (alice, bob, carol) = (user(&db).await, user(&db).await, user(&db).await);
        let (shared, other) = (role(&db).await, role(&db).await);
        let (lost_target, kept_target) = (target(&db).await, target(&db).await);
        for user_id in [alice, bob] {
            grant_user(&db, user_id, shared).await;
        }
        grant_user(&db, carol, other).await;
        grant_target(&db, lost_target, shared).await;
        grant_target(&db, lost_target, other).await;
        grant_target(&db, kept_target, shared).await;
        let alice_lost = session(&db, alice, lost_target).await;
        let bob_lost = session(&db, bob, lost_target).await;
        let alice_kept = session(&db, alice, kept_target).await;
        let carol_lost = session(&db, carol, lost_target).await;

        TargetRoleAssignment::Entity::delete_by_id((lost_target, shared))
            .exec(&db)
            .await
            .unwrap();
        services
            .close_sessions_no_longer_authorised(AccessChange::Targets(vec![lost_target]))
            .await
            .unwrap();

        assert!(ended(&db, alice_lost).await);
        assert!(ended(&db, bob_lost).await);
        assert!(!ended(&db, alice_kept).await);
        // Still granted through her own role.
        assert!(!ended(&db, carol_lost).await);
    }

    /// HTTP browser sessions are re-authorized per request instead; the SSH
    /// session on the same ungranted target is the control.
    #[tokio::test]
    async fn http_sessions_are_left_alone() {
        let db = migrated_db().await;
        let services = test_services(&db).await;
        let alice = user(&db).await;
        let ungranted = target(&db).await;
        let ssh = session(&db, alice, ungranted).await;
        let http = session(&db, alice, ungranted).await;
        let mut model: UserSession::ActiveModel = UserSession::Entity::find_by_id(http)
            .one(&db)
            .await
            .unwrap()
            .unwrap()
            .into();
        model.protocol = Set(Protocol::Http.name().into());
        model.update(&db).await.unwrap();

        services
            .close_sessions_no_longer_authorised(AccessChange::All)
            .await
            .unwrap();

        assert!(ended(&db, ssh).await);
        assert!(!ended(&db, http).await);
    }

    /// A role assignment whose expiry passes is swept like a revocation: the
    /// session to the target only it granted ends, the other stays; a sweep
    /// window that ends before the expiry leaves both.
    #[tokio::test]
    async fn an_expired_role_assignment_ends_the_sessions_it_granted() {
        let db = migrated_db().await;
        let services = test_services(&db).await;
        let (alice, expiring, kept) = (user(&db).await, role(&db).await, role(&db).await);
        let (lost_target, kept_target) = (target(&db).await, target(&db).await);
        grant_user(&db, alice, expiring).await;
        grant_user(&db, alice, kept).await;
        grant_target(&db, lost_target, expiring).await;
        grant_target(&db, kept_target, kept).await;
        let to_lost = session(&db, alice, lost_target).await;
        let to_kept = session(&db, alice, kept_target).await;

        let expired_at = OffsetDateTime::now_utc() - time::Duration::seconds(1);
        let mut assignment: UserRoleAssignment::ActiveModel =
            UserRoleAssignment::Entity::find_by_id((alice, expiring))
                .one(&db)
                .await
                .unwrap()
                .unwrap()
                .into();
        assignment.expires_at = Set(Some(expired_at));
        assignment.update(&db).await.unwrap();

        // Already swept past this expiry: nothing to do.
        services
            .close_sessions_of_expired_role_assignments(
                Some(OffsetDateTime::now_utc()),
                OffsetDateTime::now_utc(),
            )
            .await
            .unwrap();
        assert!(!ended(&db, to_lost).await);

        services
            .close_sessions_of_expired_role_assignments(
                Some(expired_at - time::Duration::seconds(5)),
                OffsetDateTime::now_utc(),
            )
            .await
            .unwrap();
        assert!(ended(&db, to_lost).await);
        assert!(!ended(&db, to_kept).await);
    }

    async fn fired(rx: &mut tokio::sync::broadcast::Receiver<()>) -> bool {
        tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv())
            .await
            .is_ok()
    }

    /// A revocation ends the live proxied HTTP requests to the target the
    /// user lost and keeps those to a target they still reach, without
    /// closing the browser session; every node is told to re-check.
    #[tokio::test]
    async fn a_revocation_ends_live_http_requests_to_the_lost_target_only() {
        let db = migrated_db().await;
        let services = test_services(&db).await;
        let (alice, lost, kept) = (user(&db).await, role(&db).await, role(&db).await);
        let (lost_target, kept_target) = (target(&db).await, target(&db).await);
        grant_user(&db, alice, lost).await;
        grant_user(&db, alice, kept).await;
        grant_target(&db, lost_target, lost).await;
        grant_target(&db, kept_target, kept).await;

        let (_browser_session, browser_close) = tokio::sync::broadcast::channel(1);
        let mut to_lost = services.live_streams.watch(
            browser_close.resubscribe(),
            alice,
            lost_target,
            LiveStreamKind::RoleBased,
        );
        let mut to_kept = services.live_streams.watch(
            browser_close,
            alice,
            kept_target,
            LiveStreamKind::RoleBased,
        );
        let mut notifications = services.cluster.subscribe();

        revoke_user_role(&db, alice, lost).await;
        services
            .close_sessions_no_longer_authorised(AccessChange::Users(vec![alice]))
            .await
            .unwrap();
        assert!(matches!(
            notifications.recv().await,
            Ok(ClusterNotification::LiveStreamsReauthorize)
        ));
        services.reauthorize_live_streams().await.unwrap();

        assert!(fired(&mut to_lost).await);
        assert!(!fired(&mut to_kept).await);
    }

    /// An HTTP target with `public` as given.
    async fn http_target(db: &DatabaseConnection, public: bool) -> Uuid {
        let id = Uuid::new_v4();
        Target::ActiveModel {
            id: Set(id),
            name: Set(format!("target-{id}")),
            description: Set(String::new()),
            kind: Set(TargetKind::Http),
            options: Set(serde_json::json!({"http": {"url": "http://h", "public": public}})),
            rate_limit_bytes_per_second: Set(None),
            group_id: Set(None),
            ticket_max_duration_seconds: Set(None),
            ticket_requests_disabled: Set(false),
            ticket_require_approval: Set(false),
            ticket_max_uses: Set(None),
            require_approval: Set(false),
        }
        .insert(db)
        .await
        .unwrap();
        id
    }

    /// A public-bypass stream runs while the target is public, ends once it
    /// is not, and a deleted target ends it too. A user with no role on the
    /// target gets no pass from the roles check.
    #[tokio::test]
    async fn a_public_bypass_stream_ends_when_the_target_stops_being_public() {
        let db = migrated_db().await;
        let services = test_services(&db).await;
        let (alice, target_id) = (user(&db).await, http_target(&db, true).await);
        let (_browser_session, browser_close) = tokio::sync::broadcast::channel(1);
        let mut anonymous = services.live_streams.watch(
            browser_close.resubscribe(),
            Uuid::nil(),
            target_id,
            LiveStreamKind::Public,
        );
        let mut logged_in =
            services
                .live_streams
                .watch(browser_close, alice, target_id, LiveStreamKind::Public);

        services.reauthorize_live_streams().await.unwrap();
        assert!(!fired(&mut anonymous).await);
        assert!(!fired(&mut logged_in).await);

        let mut unshared: Target::ActiveModel = Target::Entity::find_by_id(target_id)
            .one(&db)
            .await
            .unwrap()
            .unwrap()
            .into();
        unshared.options = Set(serde_json::json!({"http": {"url": "http://h", "public": false}}));
        unshared.update(&db).await.unwrap();
        services.reauthorize_live_streams().await.unwrap();

        assert!(fired(&mut anonymous).await);
        assert!(fired(&mut logged_in).await);
    }

    /// A public-bypass stream ends once the target requires approval: such a
    /// target is never served through the bypass.
    #[tokio::test]
    async fn a_public_bypass_stream_ends_when_the_target_requires_approval() {
        let db = migrated_db().await;
        let services = test_services(&db).await;
        let target_id = http_target(&db, true).await;
        let (_browser_session, browser_close) = tokio::sync::broadcast::channel(1);
        let mut anonymous = services.live_streams.watch(
            browser_close,
            Uuid::nil(),
            target_id,
            LiveStreamKind::Public,
        );

        let mut gated: Target::ActiveModel = Target::Entity::find_by_id(target_id)
            .one(&db)
            .await
            .unwrap()
            .unwrap()
            .into();
        gated.require_approval = Set(true);
        gated.update(&db).await.unwrap();
        services.reauthorize_live_streams().await.unwrap();

        assert!(fired(&mut anonymous).await);
    }

    /// A public re-check that errors ends the stream (fail closed).
    #[tokio::test]
    async fn a_public_bypass_stream_ends_when_its_check_errors() {
        use sea_orm::ConnectionTrait;

        let db = migrated_db().await;
        let services = test_services(&db).await;
        let target_id = http_target(&db, true).await;
        let (_browser_session, browser_close) = tokio::sync::broadcast::channel(1);
        let mut anonymous = services.live_streams.watch(
            browser_close,
            Uuid::nil(),
            target_id,
            LiveStreamKind::Public,
        );

        db.execute_unprepared("DROP TABLE targets").await.unwrap();
        services.reauthorize_live_streams().await.unwrap();

        assert!(fired(&mut anonymous).await);
    }

    /// A public-bypass stream to a target that no longer exists ends.
    #[tokio::test]
    async fn a_public_bypass_stream_ends_when_the_target_is_deleted() {
        let db = migrated_db().await;
        let services = test_services(&db).await;
        let target_id = http_target(&db, true).await;
        let (_browser_session, browser_close) = tokio::sync::broadcast::channel(1);
        let mut anonymous = services.live_streams.watch(
            browser_close,
            Uuid::nil(),
            target_id,
            LiveStreamKind::Public,
        );

        Target::Entity::delete_by_id(target_id)
            .exec(&db)
            .await
            .unwrap();
        services.reauthorize_live_streams().await.unwrap();

        assert!(fired(&mut anonymous).await);
    }

    /// A re-check that errors ends the stream (fail closed), and the loop
    /// goes on to the next pair instead of stopping.
    #[tokio::test]
    async fn an_authorisation_error_ends_the_live_stream() {
        use sea_orm::ConnectionTrait;

        let db = migrated_db().await;
        let services = test_services(&db).await;
        let (alice, bob, granting) = (user(&db).await, user(&db).await, role(&db).await);
        let target_id = target(&db).await;
        grant_user(&db, alice, granting).await;
        grant_user(&db, bob, granting).await;
        grant_target(&db, target_id, granting).await;
        let (_browser_session, browser_close) = tokio::sync::broadcast::channel(1);
        let mut first = services.live_streams.watch(
            browser_close.resubscribe(),
            alice,
            target_id,
            LiveStreamKind::RoleBased,
        );
        let mut second =
            services
                .live_streams
                .watch(browser_close, bob, target_id, LiveStreamKind::RoleBased);

        db.execute_unprepared("DROP TABLE user_roles")
            .await
            .unwrap();
        services.reauthorize_live_streams().await.unwrap();

        assert!(fired(&mut first).await);
        assert!(fired(&mut second).await);
    }

    /// A session whose re-check errors is closed (fail closed).
    #[tokio::test]
    async fn an_authorisation_error_closes_the_session() {
        use sea_orm::ConnectionTrait;

        let db = migrated_db().await;
        let services = test_services(&db).await;
        let (alice, granting) = (user(&db).await, role(&db).await);
        let target_id = target(&db).await;
        grant_user(&db, alice, granting).await;
        grant_target(&db, target_id, granting).await;
        let open = session(&db, alice, target_id).await;

        db.execute_unprepared("DROP TABLE target_roles")
            .await
            .unwrap();
        services
            .close_sessions_no_longer_authorised(AccessChange::Users(vec![alice]))
            .await
            .unwrap();

        assert!(ended(&db, open).await);
        assert!(services.pending_revocations.is_empty());
    }

    /// A re-check that cannot run at all is queued for the sweep, not lost,
    /// and the cluster is still told to re-check its streams.
    #[tokio::test]
    async fn a_failed_recheck_is_queued_and_streams_are_still_rechecked() {
        use sea_orm::ConnectionTrait;

        let db = migrated_db().await;
        let services = test_services(&db).await;
        let alice = user(&db).await;
        let mut notifications = services.cluster.subscribe();

        db.execute_unprepared("DROP TABLE target_sessions")
            .await
            .unwrap();
        services
            .close_sessions_no_longer_authorised(AccessChange::Users(vec![alice]))
            .await
            .unwrap();

        assert!(matches!(
            notifications.recv().await,
            Ok(ClusterNotification::LiveStreamsReauthorize)
        ));
        assert_eq!(services.pending_revocations.len(), 1);

        // Still failing: it stays queued.
        services.retry_pending_revocations().await;
        assert_eq!(services.pending_revocations.len(), 1);
    }
}
