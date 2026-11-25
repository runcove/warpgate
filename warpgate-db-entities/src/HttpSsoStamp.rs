use sea_orm::entity::prelude::*;
use sea_orm::sea_query::{OnConflict, Query};
use sea_orm::{QueryFilter, Set};
use time::OffsetDateTime;
use warpgate_common::WarpgateError;

use crate::UserSession;

/// The latest SSO sign-in of each HTTP user session, shared by every node.
///
/// A user session's browser sessions each carry their own copy of the stamp:
/// the control-plane one from its SSO return, each target host's from the
/// handoff that made it. When a later sign-in (a step-up) raises the stamp
/// here, a target-host session carrying an older copy is refused, for good,
/// on its next request (`warpgate_protocol_http::step_up`).
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "cove_http_sso_stamps")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub user_session_id: Uuid,
    pub last_sso_at: OffsetDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

/// Raises the user session's stamp to `at`; a stamp already later stays. Safe
/// to run on several nodes at once: the stamp only ever goes up.
pub async fn raise<C: ConnectionTrait>(
    db: &C,
    user_session_id: Uuid,
    at: OffsetDateTime,
) -> Result<(), WarpgateError> {
    Entity::insert(ActiveModel {
        user_session_id: Set(user_session_id),
        last_sso_at: Set(at),
    })
    .on_conflict(
        OnConflict::column(Column::UserSessionId)
            .do_nothing()
            .to_owned(),
    )
    .do_nothing()
    .exec_without_returning(db)
    .await?;
    Entity::update_many()
        .col_expr(Column::LastSsoAt, Expr::value(at))
        .filter(Column::UserSessionId.eq(user_session_id))
        .filter(Column::LastSsoAt.lt(at))
        .exec(db)
        .await?;
    Ok(())
}

/// The user session's latest stamp, if one was recorded.
pub async fn latest<C: ConnectionTrait>(
    db: &C,
    user_session_id: Uuid,
) -> Result<Option<OffsetDateTime>, WarpgateError> {
    Ok(Entity::find_by_id(user_session_id)
        .one(db)
        .await?
        .map(|row| row.last_sso_at))
}

/// Deletes the stamps of user sessions that are ended or gone: no browser
/// session of theirs is accepted any more.
pub async fn purge_ended<C: ConnectionTrait>(db: &C) -> Result<u64, WarpgateError> {
    Ok(Entity::delete_many()
        .filter(
            Column::UserSessionId.not_in_subquery(
                Query::select()
                    .column(UserSession::Column::Id)
                    .from(UserSession::Entity)
                    .and_where(UserSession::Column::Ended.is_null())
                    .to_owned(),
            ),
        )
        .exec(db)
        .await?
        .rows_affected)
}
