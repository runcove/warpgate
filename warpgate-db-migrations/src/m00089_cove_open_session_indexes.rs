use sea_orm::{ConnectionTrait, DbBackend, Statement};
use sea_orm_migration::prelude::*;

/// Indexes only the open sessions, which the cluster reaper reads every 15 s.
///
/// Its two sweeps (`end_children_of_ended_parents`, `end_sessions_without_cookie`)
/// are UPDATEs, so on SQLite they hold the database's write lock while they
/// run. Without these indexes each one scans every user session ever recorded
/// (35k rows on the lobby in Oct 2026), and on slow storage that scan held the
/// lock past every other writer's 30 s busy timeout. With them, a sweep reads
/// only the sessions that are still open.
///
/// SQLite and PostgreSQL get partial indexes (`WHERE ended IS NULL`). MySQL has
/// none, so it gets ordinary indexes that lead with `ended`.
#[derive(DeriveMigrationName)]
pub struct Migration;

const TARGET_INDEX: &str = "idx_target_sessions_open_by_user_session";
const USER_INDEX: &str = "idx_user_sessions_open_by_node";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Safe to re-run. Only PostgreSQL wraps a migration in a transaction, so
        // on SQLite and MySQL a crash between the two statements leaves one
        // index in place and the migration unrecorded; the next start must not
        // fail on "index already exists".
        let db = manager.get_connection();
        match manager.get_database_backend() {
            DbBackend::MySql => {
                for (name, sql) in [
                    (
                        TARGET_INDEX,
                        format!(
                            "CREATE INDEX {TARGET_INDEX} ON target_sessions (ended, user_session_id)"
                        ),
                    ),
                    (
                        USER_INDEX,
                        format!("CREATE INDEX {USER_INDEX} ON user_sessions (ended, node_id)"),
                    ),
                ] {
                    let exists = db
                        .query_one(Statement::from_sql_and_values(
                            DbBackend::MySql,
                            "SELECT 1 FROM information_schema.statistics \
                             WHERE table_schema = DATABASE() AND index_name = ? LIMIT 1",
                            [name.into()],
                        ))
                        .await?
                        .is_some();
                    if !exists {
                        db.execute_unprepared(&sql).await?;
                    }
                }
            }
            DbBackend::Postgres | DbBackend::Sqlite => {
                db.execute_unprepared(&format!(
                    "CREATE INDEX IF NOT EXISTS {TARGET_INDEX} ON target_sessions (user_session_id) \
                     WHERE ended IS NULL"
                ))
                .await?;
                db.execute_unprepared(&format!(
                    "CREATE INDEX IF NOT EXISTS {USER_INDEX} ON user_sessions (node_id) \
                     WHERE ended IS NULL"
                ))
                .await?;
            }
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for (table, name) in [
            ("target_sessions", TARGET_INDEX),
            ("user_sessions", USER_INDEX),
        ] {
            manager
                .drop_index(Index::drop().name(name).table(Alias::new(table)).to_owned())
                .await?;
        }
        Ok(())
    }
}
