use sea_orm::entity::prelude::*;
use sea_orm::{QuerySelect, Set};
use time::OffsetDateTime;
use warpgate_common::WarpgateError;

/// A user whose open sessions must all be closed. Written in the same
/// transaction as the edit or delete of the user that makes the close
/// necessary, so the row exists exactly when that change committed and
/// survives a restart of the node that never finished the close. The request
/// removes it once its own close succeeded ([`clear`]); otherwise a sweep
/// closes every open session of the user and then removes it. The record
/// names the user, not sessions, so it needs no lookup of the sessions and
/// covers one opened after it was written.
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

/// How much later than the row it replaces a record is stamped at least. One
/// second, so the order survives a backend that stores whole seconds (MySQL
/// `timestamp` does).
const MIN_STEP: time::Duration = time::Duration::seconds(1);

/// Records that this user's sessions must be closed, and returns the time the
/// row now carries, to pass to [`clear`] once the close succeeded. A user
/// already recorded has the time refreshed to a later one than the row had,
/// so a clear or sweep that read an older time leaves the row.
///
/// See [`mark_at`] for how the time is chosen.
pub async fn mark<C: ConnectionTrait>(
    db: &C,
    user_id: Uuid,
) -> Result<OffsetDateTime, WarpgateError> {
    mark_at(db, user_id, OffsetDateTime::now_utc()).await
}

/// [`mark`] with the clock's reading passed in, so a test can hold it still or
/// set it back.
///
/// The row is stamped `max(the row it replaces + 1 second, now)`: strictly
/// later than any time an earlier mark of this user returned, however close
/// together the marks are, however coarse the backend's timestamps are, and
/// whatever the clock of the node that wrote them said. A clear that carries an
/// earlier mark's time therefore never removes a later mark's row.
///
/// The row is read and written on `db`, which is the transaction of the change
/// that needs the close. That change has already written the user's own row as
/// its first statement, before any read (an edit by its update, a delete by
/// [`crate::User::lock_for_update`]), so concurrent changes of one user
/// serialise there, and the read below, whose snapshot MySQL fixes at the first
/// read, sees the row of the change that committed first.
///
/// Stamps only move forward. A node whose clock runs ahead leaves a `queued`
/// in the future, which later marks never lower: they take the later of the
/// two. The close of the change that wrote it still clears it, since that
/// clears at the time `mark` returned. The sweep does not: it clears only rows
/// older than its read less one sweep interval, so it skips such a row until
/// wall time catches up, and meanwhile closes that user's sessions on every
/// sweep. That happens only after a failed close or a node that stopped before
/// its own close.
///
/// The returned time is read back from the row: a backend that stores less
/// precision than the clock (or rounds) would otherwise leave a row that a
/// clear at the unrounded time cannot match.
pub async fn mark_at<C: ConnectionTrait>(
    db: &C,
    user_id: Uuid,
    now: OffsetDateTime,
) -> Result<OffsetDateTime, WarpgateError> {
    let queued = match Entity::find_by_id(user_id).one(db).await? {
        Some(existing) => now.max(existing.queued + MIN_STEP),
        None => now,
    };
    Entity::insert(ActiveModel {
        user_id: Set(user_id),
        queued: Set(queued),
    })
    .on_conflict(
        sea_orm::sea_query::OnConflict::column(Column::UserId)
            .update_column(Column::Queued)
            .to_owned(),
    )
    .exec_without_returning(db)
    .await?;
    let row = Entity::find_by_id(user_id)
        .one(db)
        .await?
        .ok_or_else(|| DbErr::RecordNotFound(format!("pending_user_closes row for {user_id}")))?;
    Ok(row.queued)
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
