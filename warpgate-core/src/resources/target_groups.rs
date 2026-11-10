use poem_openapi::Object;
use sea_orm::prelude::Expr;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DbBackend, EntityTrait, ModelTrait,
    QueryFilter, Set, TransactionTrait,
};
use uuid::Uuid;
use warpgate_db_entities::TargetGroup::BootstrapThemeColor;
use warpgate_db_entities::{Target, TargetGroup};

use super::{ResourceError, check_name, name_taken};

#[derive(Object)]
pub struct TargetGroupDataRequest {
    pub name: String,
    pub description: Option<String>,
    pub color: Option<BootstrapThemeColor>,
}

fn set_data(model: &mut TargetGroup::ActiveModel, data: &TargetGroupDataRequest) {
    model.name = Set(data.name.clone());
    model.description = Set(data.description.clone().unwrap_or_default());
    model.color = Set(data.color.clone());
}

pub async fn create<C: ConnectionTrait>(
    db: &C,
    data: &TargetGroupDataRequest,
) -> Result<TargetGroup::Model, ResourceError> {
    check_name(&data.name)?;
    let mut model = TargetGroup::ActiveModel {
        id: Set(Uuid::new_v4()),
        ..Default::default()
    };
    set_data(&mut model, data);
    model.insert(db).await.map_err(name_taken)
}

pub async fn update<C: ConnectionTrait>(
    db: &C,
    id: Uuid,
    data: &TargetGroupDataRequest,
) -> Result<TargetGroup::Model, ResourceError> {
    check_name(&data.name)?;
    let group = TargetGroup::Entity::find_by_id(id)
        .one(db)
        .await?
        .ok_or(ResourceError::NotFound)?;

    let mut model: TargetGroup::ActiveModel = group.into();
    set_data(&mut model, data);
    model.update(db).await.map_err(name_taken)
}

pub async fn delete<C: ConnectionTrait + TransactionTrait>(
    db: &C,
    id: Uuid,
) -> Result<(), ResourceError> {
    let txn = db.begin().await?;
    // On SQLite, a transaction that has read and then writes cannot wait for
    // another writer: the upgrade fails at once with SQLITE_BUSY and
    // `busy_timeout` never applies. Making the first statement a write takes
    // the database's write lock up front, which does wait. This is what
    // `BEGIN IMMEDIATE` would do, but sea-orm 1.1 always begins with a plain
    // `BEGIN` and ignores `begin_with_config`'s options on SQLite. The no-op
    // update touches only the row being removed, and only on SQLite: on
    // PostgreSQL and MySQL it would lock this row before the rows the delete
    // locks next, which is not the order they are locked in today.
    if db.get_database_backend() == DbBackend::Sqlite {
        TargetGroup::Entity::update_many()
            .col_expr(
                TargetGroup::Column::Id,
                Expr::col(TargetGroup::Column::Id).into(),
            )
            .filter(TargetGroup::Column::Id.eq(id))
            .exec(&txn)
            .await?;
    }
    let group = TargetGroup::Entity::find_by_id(id)
        .one(&txn)
        .await?
        .ok_or(ResourceError::NotFound)?;

    Target::Entity::update_many()
        .col_expr(Target::Column::GroupId, Expr::value(Option::<Uuid>::None))
        .filter(Target::Column::GroupId.eq(id))
        .exec(&txn)
        .await?;

    group.delete(&txn).await?;
    txn.commit().await?;
    Ok(())
}
