//! Databases and services for this crate's tests.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use sea_orm::{Database, DatabaseConnection};
use tokio::sync::Mutex;
use uuid::Uuid;
use warpgate_common::{GlobalParams, WarpgateConfig, WarpgateConfigStore};
use warpgate_core::cluster::Cluster;
use warpgate_core::login_protection::LoginProtectionService;
use warpgate_core::rate_limiting::RateLimiterRegistry;
use warpgate_core::recordings::SessionRecordings;
use warpgate_core::{
    ApprovalRequestSink, AuthStateStore, DatabaseConfigProvider, Services, State,
};

/// A migrated in-memory database.
pub async fn memory_db() -> DatabaseConnection {
    warpgate_db_entities::Parameters::set_config_migration_values(
        warpgate_db_entities::Parameters::ConfigMigrationValues::default(),
    );
    let db = Database::connect("sqlite::memory:").await.unwrap();
    warpgate_db_migrations::migrate_database(&db).await.unwrap();
    db
}

/// An on-disk database removed on drop. Lock contention needs a real file
/// in WAL mode, as in production: in-memory SQLite has neither.
pub struct TempDb(PathBuf);

impl Drop for TempDb {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let mut path = self.0.clone().into_os_string();
            path.push(suffix);
            let _ = std::fs::remove_file(path);
        }
    }
}

/// A migrated on-disk database, connected the way `warpgate_core::db` does:
/// WAL, with the given busy timeout (production uses 30 s).
pub async fn file_db(busy_timeout: Duration) -> (DatabaseConnection, TempDb) {
    use sea_orm::SqlxSqliteConnector;
    use sea_orm::sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};

    warpgate_db_entities::Parameters::set_config_migration_values(
        warpgate_db_entities::Parameters::ConfigMigrationValues::default(),
    );
    let path = std::env::temp_dir().join(format!("warpgate-test-{}.db", Uuid::new_v4()));
    let temp = TempDb(path.clone());
    let options = SqliteConnectOptions::new()
        .filename(&path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .busy_timeout(busy_timeout);
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await
        .unwrap();
    let db = SqlxSqliteConnector::from_sqlx_sqlite_pool(pool);
    warpgate_db_migrations::migrate_database(&db).await.unwrap();
    (db, temp)
}

/// Holds the database's write lock from another connection for `hold`,
/// as a concurrent request's write would. Returns once the lock is held.
pub async fn hold_write_lock(
    db: &DatabaseConnection,
    hold: Duration,
) -> tokio::task::JoinHandle<()> {
    let mut conn = db.get_sqlite_connection_pool().acquire().await.unwrap();
    sea_orm::sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut *conn)
        .await
        .unwrap();
    tokio::spawn(async move {
        tokio::time::sleep(hold).await;
        sea_orm::sqlx::query("COMMIT")
            .execute(&mut *conn)
            .await
            .unwrap();
    })
}

pub const HOLD: Duration = Duration::from_millis(500);

/// The services a node runs with, over `db`.
pub async fn services(db: DatabaseConnection) -> Services {
    let params = GlobalParams::new(PathBuf::from("/warpgate.yaml"), false).unwrap();
    let rate_limiter_registry = Arc::new(Mutex::new(RateLimiterRegistry::new(db.clone())));
    let cluster = Arc::new(Cluster::new(db.clone(), 0).await.unwrap());
    Services {
        db: db.clone(),
        recordings: Arc::new(SessionRecordings::new(db.clone(), &params)),
        config: Arc::new(Mutex::new(WarpgateConfig {
            store: WarpgateConfigStore::default(),
        })),
        state: State::new(&db, &rate_limiter_registry, cluster.node_id),
        cluster: cluster.clone(),
        rate_limiter_registry,
        config_provider: Arc::new(DatabaseConfigProvider::new(&db).into()),
        auth_state_store: Arc::new(Mutex::new(AuthStateStore::new(ApprovalRequestSink {
            db: db.clone(),
            cluster,
        }))),
        admin_token: Arc::new(None),
        login_protection: Arc::new(LoginProtectionService::new(db.clone()).await.unwrap()),
        global_params: Arc::new(params),
        listener_status: Default::default(),
    }
}
