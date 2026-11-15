use sea_orm::DbBackend;
use sea_orm::prelude::Expr;
use sea_orm::sea_query::SimpleExpr;

/// MySQL 8.0.13+ requires expression defaults (parenthesised) for TEXT columns
pub fn string_default_value(backend: DbBackend, value: &str) -> SimpleExpr {
    if backend == DbBackend::MySql {
        Expr::cust(format!("('{value}')"))
    } else {
        value.into()
    }
}

/// Refuses to roll back the migration named `migration` while any
/// `http_sessions` row remains. Rolling back to a release before these
/// migrations requires those rows to be gone, and the check runs before the
/// migration drops anything, so a refusal changes nothing.
pub async fn refuse_down_while_http_sessions_remain(
    manager: &sea_orm_migration::SchemaManager<'_>,
    migration: &str,
) -> Result<(), sea_orm::DbErr> {
    use sea_orm::sea_query::{Alias, Asterisk, Query};
    use sea_orm::{ConnectionTrait, DbErr};

    let db = manager.get_connection();
    let query = Query::select()
        .expr(Expr::col(Asterisk).count())
        .from(Alias::new("http_sessions"))
        .to_owned();
    let row = db
        .query_one(db.get_database_backend().build(&query))
        .await?
        .ok_or_else(|| DbErr::Custom("COUNT(*) returned no row".into()))?;
    let count: i64 = row.try_get_by_index(0)?;
    if count > 0 {
        return Err(DbErr::Migration(format!(
            "refusing to roll back {migration}: http_sessions still has {count} row(s). \
             With every Warpgate node stopped, delete every row \
             (DELETE FROM http_sessions;) and run this command again."
        )));
    }
    Ok(())
}
