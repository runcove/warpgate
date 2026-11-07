use sea_orm::entity::prelude::*;
use sea_orm::sea_query::OnConflict;
use sea_orm::{QuerySelect, Set};
use time::OffsetDateTime;
use warpgate_common::{UserSessionId, WarpgateError};

/// Rows deleted per statement, well under every backend's bound-parameter
/// limit.
const DELETE_CHUNK: usize = 500;

/// A session that must be closed because what admitted it (a ticket) has been
/// deleted. The row is written in the same transaction as the delete, so the
/// need to close survives a restart of the node that never got to it: once the
/// ticket row is gone, `target_sessions.ticket_id` is cleared and nothing else
/// records which open sessions it admitted. A sweep closes the sessions named
/// here and then removes the rows ([`clear`]).
///
/// Not part of the copied database: the rows are short-lived.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "pending_session_closes")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub user_session_id: UserSessionId,
    pub queued: OffsetDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

/// Records that these sessions must be closed. Ids already recorded stay as
/// they are.
pub async fn mark<C: ConnectionTrait>(db: &C, ids: &[UserSessionId]) -> Result<(), WarpgateError> {
    if ids.is_empty() {
        return Ok(());
    }
    let now = OffsetDateTime::now_utc();
    let rows = ids.iter().map(|id| ActiveModel {
        user_session_id: Set(*id),
        queued: Set(now),
    });
    // The no-op self-assignment is the conflict form every backend renders
    // validly (see `TargetSession::insert_unless_already_open`).
    Entity::insert_many(rows)
        .on_conflict(
            OnConflict::column(Column::UserSessionId)
                .update_column(Column::UserSessionId)
                .to_owned(),
        )
        .exec_without_returning(db)
        .await?;
    Ok(())
}

/// Every session still waiting to be closed.
pub async fn pending<C: ConnectionTrait>(db: &C) -> Result<Vec<UserSessionId>, WarpgateError> {
    Ok(Entity::find()
        .select_only()
        .column(Column::UserSessionId)
        .into_tuple()
        .all(db)
        .await?)
}

/// Forgets these sessions once they are closed.
pub async fn clear<C: ConnectionTrait>(db: &C, ids: &[UserSessionId]) -> Result<(), WarpgateError> {
    for chunk in ids.chunks(DELETE_CHUNK) {
        Entity::delete_many()
            .filter(Column::UserSessionId.is_in(chunk.to_vec()))
            .exec(db)
            .await?;
    }
    Ok(())
}
