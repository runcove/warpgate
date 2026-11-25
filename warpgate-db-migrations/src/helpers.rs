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

/// The statement that keeps new `http_sessions` rows out until the rollback
/// commits, if the backend can hold one for that long. Only Postgres can:
/// sea-orm-migration runs a Postgres `down` in one transaction, so the lock
/// taken before the count holds through the drops. MySQL commits each DDL
/// statement on its own and SQLite gets no table locks, so neither is given
/// one; there the check relies on every node being stopped.
pub(crate) fn http_sessions_lock_statement(backend: DbBackend) -> Option<sea_orm::Statement> {
    (backend == DbBackend::Postgres)
        .then(|| sea_orm::Statement::from_string(backend, "LOCK TABLE http_sessions IN SHARE MODE"))
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
    if let Some(lock) = http_sessions_lock_statement(db.get_database_backend()) {
        db.execute(lock).await?;
    }
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

#[cfg(test)]
mod tests {
    use sea_orm::DbBackend;

    use super::http_sessions_lock_statement;

    /// Only Postgres gets the lock: it is the one backend whose `down` runs in
    /// a single transaction, and `LOCK TABLE` is not SQLite or MySQL syntax.
    #[test]
    fn http_sessions_lock_is_taken_on_postgres_only() {
        let lock = http_sessions_lock_statement(DbBackend::Postgres).unwrap();
        assert_eq!(lock.sql, "LOCK TABLE http_sessions IN SHARE MODE");
        assert!(http_sessions_lock_statement(DbBackend::Sqlite).is_none());
        assert!(http_sessions_lock_statement(DbBackend::MySql).is_none());
    }
}
