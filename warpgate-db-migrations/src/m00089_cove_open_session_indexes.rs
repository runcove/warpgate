use sea_orm::{ConnectionTrait, DbBackend};
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
        let db = manager.get_connection();
        let statements: [String; 2] = match manager.get_database_backend() {
            DbBackend::MySql => [
                format!("CREATE INDEX {TARGET_INDEX} ON target_sessions (ended, user_session_id)"),
                format!("CREATE INDEX {USER_INDEX} ON user_sessions (ended, node_id)"),
            ],
            DbBackend::Postgres | DbBackend::Sqlite => [
                format!(
                    "CREATE INDEX {TARGET_INDEX} ON target_sessions (user_session_id) WHERE ended IS NULL"
                ),
                format!("CREATE INDEX {USER_INDEX} ON user_sessions (node_id) WHERE ended IS NULL"),
            ],
        };
        for statement in statements {
            db.execute_unprepared(&statement).await?;
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
