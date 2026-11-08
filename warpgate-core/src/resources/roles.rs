use poem_openapi::Object;
use sea_orm::sea_query::Expr;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DbBackend, EntityTrait, ModelTrait,
    QueryFilter, Set, TransactionTrait,
};
use uuid::Uuid;
use warpgate_db_entities::{Role, TargetRoleAssignment, UserRoleAssignment};

use super::{ResourceError, check_name, name_taken};

#[derive(Object)]
pub struct RoleDataRequest {
    pub name: String,
    pub description: Option<String>,
    pub is_default: Option<bool>,
}

fn set_data(model: &mut Role::ActiveModel, data: &RoleDataRequest) {
    model.name = Set(data.name.clone());
    model.description = Set(data.description.clone().unwrap_or_default());
    if let Some(is_default) = data.is_default {
        model.is_default = Set(is_default);
    }
}

pub async fn create<C: ConnectionTrait>(
    db: &C,
    data: &RoleDataRequest,
) -> Result<Role::Model, ResourceError> {
    check_name(&data.name)?;
    let mut model = Role::ActiveModel {
        id: Set(Uuid::new_v4()),
        is_default: Set(false),
        ..Default::default()
    };
    set_data(&mut model, data);
    model.insert(db).await.map_err(name_taken)
}

pub async fn update<C: ConnectionTrait>(
    db: &C,
    id: Uuid,
    data: &RoleDataRequest,
) -> Result<Role::Model, ResourceError> {
    check_name(&data.name)?;
    let role = Role::Entity::find_by_id(id)
        .one(db)
        .await?
        .ok_or(ResourceError::NotFound)?;

    let mut model: Role::ActiveModel = role.into();
    set_data(&mut model, data);
    model.update(db).await.map_err(name_taken)
}

/// Also removes every assignment of the role, including revoked ones
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
        Role::Entity::update_many()
            .col_expr(Role::Column::Id, Expr::col(Role::Column::Id).into())
            .filter(Role::Column::Id.eq(id))
            .exec(&txn)
            .await?;
    }
    let role = Role::Entity::find_by_id(id)
        .one(&txn)
        .await?
        .ok_or(ResourceError::NotFound)?;

    UserRoleAssignment::Entity::delete_many()
        .filter(UserRoleAssignment::Column::RoleId.eq(id))
        .exec(&txn)
        .await?;

    TargetRoleAssignment::Entity::delete_many()
        .filter(TargetRoleAssignment::Column::RoleId.eq(id))
        .exec(&txn)
        .await?;

    role.delete(&txn).await?;
    txn.commit().await?;
    Ok(())
}
