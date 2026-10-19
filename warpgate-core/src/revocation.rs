//! Cutting live sessions whose target their user may no longer reach, after a
//! change that can take access away.

use std::collections::HashMap;

use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QuerySelect};
use tracing::info;
use uuid::Uuid;
use warpgate_common::{Protocol, UserSessionId, WarpgateError};
use warpgate_db_entities::{TargetSession, User, UserSession};

use crate::{ConfigProvider, Services, SessionsFilter};

/// Whose live sessions an access change can affect.
#[derive(Debug, Clone)]
pub enum AccessChange {
    /// These users' role memberships changed.
    Users(Vec<Uuid>),
    /// A user, by name, whose roles an SSO login re-synced.
    Username(String),
    /// These targets lost roles, or were deleted.
    Targets(Vec<Uuid>),
    /// A role went away: anyone may be affected.
    All,
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
    pub async fn close_sessions_no_longer_authorised(
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
                    let authorized = self
                        .config_provider
                        .authorize_target_by_id(user_id, target_id)
                        .await?;
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
        if ids.is_empty() {
            return Ok(());
        }
        info!(
            sessions = ids.len(),
            "Closing sessions whose user may no longer reach their target"
        );
        self.close_sessions(SessionsFilter::Sessions { ids }).await
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
}
