use sea_orm::entity::prelude::*;
use sea_orm::{QuerySelect, Set};
use time::OffsetDateTime;
use warpgate_common::WarpgateError;

/// A user whose open sessions must all be closed. Recorded when the close that
/// follows an edit of the user fails after the edit was saved; a sweep closes
/// every open session of the user and then removes the row ([`clear`]). The
/// record names the user, not sessions, so it needs no lookup of the sessions
/// and covers one opened after it was written.
///
/// Not part of the copied database: copying the database drops the per-user
/// queue, and a stale row only closes sessions.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "pending_user_closes")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub user_id: Uuid,
    pub queued: OffsetDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

/// Records that this user's sessions must be closed. A user already recorded
/// has the time refreshed, so a sweep that read the older time leaves the row.
pub async fn mark<C: ConnectionTrait>(db: &C, user_id: Uuid) -> Result<(), WarpgateError> {
    Entity::insert(ActiveModel {
        user_id: Set(user_id),
        queued: Set(OffsetDateTime::now_utc()),
    })
    .on_conflict(
        sea_orm::sea_query::OnConflict::column(Column::UserId)
            .update_column(Column::Queued)
            .to_owned(),
    )
    .exec_without_returning(db)
    .await?;
    Ok(())
}

/// Every user still waiting to have their sessions closed.
pub async fn pending<C: ConnectionTrait>(db: &C) -> Result<Vec<Uuid>, WarpgateError> {
    Ok(Entity::find()
        .select_only()
        .column(Column::UserId)
        .into_tuple()
        .all(db)
        .await?)
}

/// Whether this user is waiting to have their sessions closed.
pub async fn is_pending<C: ConnectionTrait>(db: &C, user_id: Uuid) -> Result<bool, WarpgateError> {
    Ok(Entity::find_by_id(user_id).one(db).await?.is_some())
}

/// Forgets this user, unless the row was written after `up_to`.
pub async fn clear<C: ConnectionTrait>(
    db: &C,
    user_id: Uuid,
    up_to: OffsetDateTime,
) -> Result<(), WarpgateError> {
    Entity::delete_many()
        .filter(Column::UserId.eq(user_id))
        .filter(Column::Queued.lte(up_to))
        .exec(db)
        .await?;
    Ok(())
}
