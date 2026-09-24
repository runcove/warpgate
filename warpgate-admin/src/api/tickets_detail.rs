use poem::http::StatusCode;
use poem_openapi::param::Path;
use poem_openapi::{ApiResponse, OpenApi};
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use tracing::warn;
use uuid::Uuid;
use warpgate_common::{AdminPermission, UserSessionId, WarpgateError};
use warpgate_core::State;
use warpgate_core::logging::AuditEvent;
use warpgate_core::ticket_requests::delete_ticket;
use warpgate_db_entities::{Target, TargetSession, User, UserSession};

use super::ClusterOrAdminContext;
use crate::api::cluster_proxy::fan_out_to_peers_expecting;

pub struct Api;

#[derive(ApiResponse)]
enum DeleteTicketResponse {
    #[oai(status = 204)]
    Deleted,

    #[oai(status = 404)]
    NotFound,
}

/// The user sessions that opened a target session with this ticket.
///
/// Must be read while the ticket row still exists: `target_sessions.ticket_id`
/// is `ON DELETE SET NULL`, so after the delete nothing points back at it.
/// `open_only` limits it to sessions still running; a cluster peer passes
/// `false`, because by the time it is asked the originating node has already
/// ended those rows.
async fn user_sessions_opened_with_ticket(
    db: &DatabaseConnection,
    ticket_id: Uuid,
    open_only: bool,
) -> Result<Vec<UserSessionId>, WarpgateError> {
    let mut query = TargetSession::Entity::find().filter(TargetSession::Column::TicketId.eq(ticket_id));
    if open_only {
        query = query.filter(TargetSession::Column::Ended.is_null());
    }
    let mut ids = query
        .all(db)
        .await?
        .into_iter()
        .map(|target_session| target_session.user_session_id)
        .collect::<Vec<_>>();
    ids.sort();
    ids.dedup();
    Ok(ids)
}

#[OpenApi]
impl Api {
    #[oai(
        path = "/tickets/:id",
        method = "delete",
        operation_id = "delete_ticket"
    )]
    async fn api_delete_ticket(
        &self,
        admin: ClusterOrAdminContext,
        id: Path<Uuid>,
        req: &poem::Request,
    ) -> Result<DeleteTicketResponse, WarpgateError> {
        use warpgate_db_entities::Ticket;

        admin.require(AdminPermission::TicketsDelete)?;

        let db = &admin.services().db;

        if admin.is_intra_cluster_request() {
            // The originating node has already revoked these sessions in the
            // DB and fanned out before deleting the ticket; all that is left
            // here is this node's own live handles.
            let ids = user_sessions_opened_with_ticket(db, id.0, false).await?;
            State::close_local_sessions_by_ids(&admin.services().state, &ids).await;
            return Ok(DeleteTicketResponse::Deleted);
        }

        let Some(ticket) = Ticket::Entity::find_by_id(id.0).one(db).await? else {
            return Ok(DeleteTicketResponse::NotFound);
        };

        // Collected before the ticket goes (see user_sessions_opened_with_ticket).
        let ids = user_sessions_opened_with_ticket(db, ticket.id, true).await?;

        // End the sessions in the DB before closing handles, as the user
        // delete does: an HTTP session opened with this ticket is otherwise
        // still honoured from its cookie, which never re-checks the ticket.
        for session_id in &ids {
            UserSession::revoke(db, *session_id).await?;
        }
        State::close_local_sessions_by_ids(&admin.services().state, &ids).await;

        // Peers look the sessions up by ticket too, so they are asked while
        // the ticket row still exists.
        for (node, status) in fan_out_to_peers_expecting(&admin, req, StatusCode::NO_CONTENT).await
        {
            warn!(%node, %status, "Failed to close the ticket's sessions on a cluster node");
        }

        let user = User::Entity::find_by_id(ticket.user_id).one(db).await?;

        let target = Target::Entity::find_by_id(ticket.target_id).one(db).await?;

        if let (Some(user), Some(target)) = (user, target) {
            AuditEvent::TicketDeleted {
                ticket_id: ticket.id,
                user_id: user.id,
                username: user.username,
                target: target.name,
                actor_user_id: admin.auth.user_id(),
            }
            .emit();
        }

        delete_ticket(db, ticket.id).await?;
        Ok(DeleteTicketResponse::Deleted)
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::ActiveValue::Set;
    use sea_orm::{ActiveModelTrait, Database};
    use time::OffsetDateTime;
    use warpgate_common::{NodeId, TargetSessionId};
    use warpgate_db_entities::Parameters::{ConfigMigrationValues, set_config_migration_values};
    use warpgate_db_entities::Target::TargetKind;
    use warpgate_db_entities::Ticket;
    use warpgate_db_migrations::migrate_database;

    use super::*;

    /// A migrated database with one ticket, one user session that opened a
    /// target session with it, and one unrelated user session.
    async fn fixture() -> (DatabaseConnection, Uuid, UserSessionId, UserSessionId) {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();

        let user_id = Uuid::new_v4();
        User::ActiveModel {
            id: Set(user_id),
            username: Set("alice".into()),
            description: Set(String::new()),
            credential_policy: Set(serde_json::json!({})),
            rate_limit_bytes_per_second: Set(None),
            ldap_server_id: Set(None),
            ldap_object_uuid: Set(None),
            allowed_ip_ranges: Set(serde_json::Value::Null),
        }
        .insert(&db)
        .await
        .unwrap();
        let target_id = Uuid::new_v4();
        Target::ActiveModel {
            id: Set(target_id),
            name: Set("web".into()),
            description: Set(String::new()),
            kind: Set(TargetKind::Http),
            options: Set(serde_json::json!({})),
            rate_limit_bytes_per_second: Set(None),
            group_id: Set(None),
            ticket_max_duration_seconds: Set(None),
            ticket_requests_disabled: Set(false),
            ticket_require_approval: Set(false),
            ticket_max_uses: Set(None),
            require_approval: Set(false),
        }
        .insert(&db)
        .await
        .unwrap();
        let ticket_id = Uuid::new_v4();
        Ticket::ActiveModel {
            id: Set(ticket_id),
            secret_hash: Set("not-a-real-hash".into()),
            user_id: Set(user_id),
            description: Set(String::new()),
            target_id: Set(target_id),
            uses_left: Set(None),
            self_service: Set(false),
            expiry: Set(None),
            created: Set(OffsetDateTime::now_utc()),
        }
        .insert(&db)
        .await
        .unwrap();

        let node_id = NodeId(Uuid::new_v4());
        let mut session_ids = vec![];
        for ticket in [Some(ticket_id), None] {
            let session_id = UserSessionId(Uuid::new_v4());
            UserSession::ActiveModel {
                id: Set(session_id),
                username: Set(Some("alice".into())),
                user_id: Set(Some(user_id)),
                remote_address: Set("127.0.0.1:22".into()),
                started: Set(OffsetDateTime::now_utc()),
                ended: Set(None),
                protocol: Set("HTTP".into()),
                node_id: Set(Some(node_id)),
                auth_state_node_id: Set(None),
            }
            .insert(&db)
            .await
            .unwrap();
            TargetSession::ActiveModel {
                id: Set(TargetSessionId(Uuid::new_v4())),
                user_session_id: Set(session_id),
                target_snapshot: Set(r#"{"name":"web"}"#.into()),
                target_id: Set(target_id),
                started: Set(OffsetDateTime::now_utc()),
                ended: Set(None),
                ticket_id: Set(ticket),
                node_id: Set(Some(node_id)),
            }
            .insert(&db)
            .await
            .unwrap();
            session_ids.push(session_id);
        }

        (db, ticket_id, session_ids[0], session_ids[1])
    }

    /// Only the session that used the ticket is found, and only while the
    /// ticket row exists: the delete nulls `ticket_id`, which is why the
    /// handler collects the ids first.
    #[tokio::test]
    async fn ticket_sessions_are_found_only_before_the_ticket_is_deleted() {
        let (db, ticket_id, with_ticket, _without) = fixture().await;

        assert_eq!(
            user_sessions_opened_with_ticket(&db, ticket_id, true)
                .await
                .unwrap(),
            vec![with_ticket]
        );

        delete_ticket(&db, ticket_id).await.unwrap();

        assert!(
            user_sessions_opened_with_ticket(&db, ticket_id, false)
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// Revoking ends the ticket's session in the DB and leaves the other
    /// alone; a cluster peer, asked afterwards, still finds the ended one.
    #[tokio::test]
    async fn revoking_the_ticket_sessions_ends_only_those() {
        let (db, ticket_id, with_ticket, without) = fixture().await;

        for id in user_sessions_opened_with_ticket(&db, ticket_id, true)
            .await
            .unwrap()
        {
            UserSession::revoke(&db, id).await.unwrap();
        }

        let ended = |id: UserSessionId| {
            let db = db.clone();
            async move {
                UserSession::Entity::find_by_id(id)
                    .one(&db)
                    .await
                    .unwrap()
                    .unwrap()
                    .ended
                    .is_some()
            }
        };
        assert!(ended(with_ticket).await);
        assert!(!ended(without).await);

        assert!(
            user_sessions_opened_with_ticket(&db, ticket_id, true)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            user_sessions_opened_with_ticket(&db, ticket_id, false)
                .await
                .unwrap(),
            vec![with_ticket]
        );
    }
}
