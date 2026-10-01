use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use poem::error::InternalServerError;
use poem::session::{Session, SessionStorage};
use sea_orm::ActiveValue::Set;
use sea_orm::sea_query::{Expr, OnConflict};
use sea_orm::{
    ColumnTrait, Condition, ConnectionTrait, DatabaseConnection, DbBackend, EntityTrait,
    PaginatorTrait, QueryFilter, TransactionTrait,
};
use serde_json::Value;
use time::OffsetDateTime;
use tracing::{error, warn};
use uuid::Uuid;
use warpgate_common::{UserSessionId, WarpgateError};
use warpgate_db_entities::{HttpSession, UserSession};

use crate::common::SessionExt;
use crate::session::SESSION_ID_SESSION_KEY;

/// The database-backed [`SessionStorage`] behind poem's session middleware:
/// browser sessions live in `http_sessions`, shared by every node, and a
/// stored row is what keeps its user session alive.
#[derive(Clone)]
pub struct SharedSessionStorage {
    db: DatabaseConnection,
    recently_loaded: Arc<std::sync::Mutex<RecentlyLoaded>>,
}

/// Storage ids this node has served through `load_session`. `update_session`
/// consults it to tell a loaded session's write-back (update-only, so a row
/// removed or rotated mid-request stays gone) from a fresh session's first
/// write (insert) — poem's storage trait itself carries no such context. Loads
/// and their write-backs happen on the same node, so a node-local set suffices.
///
/// Ids are never removed individually — a removed or rotated row's id must
/// stay known precisely so a stale concurrent request's write-back updates
/// nothing instead of re-inserting it. Two generations, swapped on an interval
/// that dwarfs any request's lifetime, bound the memory instead; ids are
/// random and never reused, so a lingering one can only match those stale
/// write-backs.
struct RecentlyLoaded {
    current: HashSet<String>,
    previous: HashSet<String>,
    swapped_at: Instant,
}

const RECENTLY_LOADED_SWAP_INTERVAL: Duration = Duration::from_secs(3600);

impl RecentlyLoaded {
    fn new() -> Self {
        Self {
            current: HashSet::new(),
            previous: HashSet::new(),
            swapped_at: Instant::now(),
        }
    }

    fn record(&mut self, id: &str) {
        if self.swapped_at.elapsed() >= RECENTLY_LOADED_SWAP_INTERVAL {
            self.previous = std::mem::take(&mut self.current);
            self.swapped_at = Instant::now();
        }
        self.current.insert(id.to_owned());
    }

    fn contains(&self, id: &str) -> bool {
        self.current.contains(id) || self.previous.contains(id)
    }
}

/// A browser session's user session and login, as this node held them before
/// forwarding a login step to a peer: what
/// [`SharedSessionStorage::adopt_forwarded_login`] compares the peer's result
/// against.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LoginSnapshot {
    session_id: Option<UserSessionId>,
    user_id: Option<Uuid>,
}

impl LoginSnapshot {
    pub fn of(session: &Session) -> Self {
        Self {
            session_id: session.get_session_id(),
            user_id: session.get_auth().map(|auth| auth.user_id()),
        }
    }
}

const SESSION_TOUCH_SESSION_KEY: &str = "touched_at";
const SESSION_TOUCH_DEBOUNCE_SECONDS: i64 = 60;

/// Dirties an active browser session at most once a minute, so the middleware
/// writes it back and the row's `Updated` stays ahead of [`SharedSessionStorage::gc`]
/// while the browser keeps making requests.
pub fn mark_session_active(session: &Session) {
    if session.is_empty() {
        return;
    }
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let touched = session.get::<i64>(SESSION_TOUCH_SESSION_KEY).unwrap_or(0);
    if now - touched >= SESSION_TOUCH_DEBOUNCE_SECONDS {
        session.set(SESSION_TOUCH_SESSION_KEY, now);
    }
}

impl SharedSessionStorage {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            db,
            recently_loaded: Arc::new(std::sync::Mutex::new(RecentlyLoaded::new())),
        }
    }

    fn record_loaded(&self, id: &str) {
        if let Ok(mut set) = self.recently_loaded.lock() {
            set.record(id);
        }
    }

    fn was_loaded(&self, id: &str) -> bool {
        self.recently_loaded
            .lock()
            .map_or(false, |set| set.contains(id))
    }

    /// Replaces `session`'s contents with the stored row.
    ///
    /// Forwarding a request to a peer leaves this node holding the copy of the
    /// browser session it loaded before the hop, and the session middleware
    /// writes that copy back at the end of the request — over whatever the peer
    /// stored meanwhile, such as the authorization from a login the peer just
    /// completed. Adopting the stored row makes that write-back a no-op.
    pub async fn adopt_stored(
        &self,
        stored_id: Option<String>,
        session: &Session,
    ) -> poem::Result<()> {
        let Some(id) = stored_id else {
            return Ok(());
        };
        let Some(entries) = self.load_session(&id).await? else {
            session.purge();
            return Ok(());
        };
        // Leaving the session untouched keeps its status `Unchanged`, so a
        // forwarded request the peer did not alter costs no write-back.
        if entries == session.entries() {
            return Ok(());
        }
        session.clear();
        for (key, value) in entries {
            session.set(&key, value);
        }
        Ok(())
    }

    /// [`Self::adopt_stored`] after a login step was forwarded to a peer, then
    /// rotates the storage id if the step logged the browser session in.
    ///
    /// The peer does not rotate the id for a forwarded request, and a cookie it
    /// sets never reaches the browser, so the rotation that retires the
    /// pre-login id has to happen here. It is decided on whether the login
    /// changed the session — its user session or its user — not on whether a
    /// login existed before the hop: a stale cookie that still carries an
    /// authorization is given a fresh session at the login entry point (see
    /// [`crate::session::SessionStore::handle_for_login`]) and then logged in
    /// under the same storage id, which must be rotated like any other login.
    pub async fn adopt_forwarded_login(
        &self,
        stored_id: Option<String>,
        session: &Session,
        before_hop: LoginSnapshot,
    ) -> poem::Result<()> {
        self.adopt_stored(stored_id.clone(), session).await?;
        let after_hop = LoginSnapshot::of(session);
        if after_hop.user_id.is_some() && after_hop != before_hop {
            self.rotate_session_id(stored_id, session).await?;
        }
        Ok(())
    }

    pub async fn gc(&self, max_age: Duration) -> Result<(), WarpgateError> {
        let now = OffsetDateTime::now_utc();
        let expired = Condition::any()
            .add(HttpSession::Column::Expires.lt(now))
            .add(HttpSession::Column::Updated.lt(now - max_age));
        let rows = HttpSession::Entity::find()
            .filter(expired.clone())
            .all(&self.db)
            .await?;
        for row in rows {
            if let Err(error) = self.remove_stored_row(&row.id, Some((now, max_age))).await {
                if self.is_busy(&error) {
                    // Contention with another writer that outlasted the busy
                    // timeout. Every further row would wait as long again, so
                    // stop here: the rest are still expired on the next sweep.
                    warn!(%error, id = %row.id, "Database busy, will retry removing expired browser sessions on the next sweep");
                    break;
                } else {
                    error!(%error, id = %row.id, "Could not remove an expired browser session");
                }
            }
        }
        Ok(())
    }

    // this keeps websocket sessions 'alive' without an HTTP request to refresh them
    pub async fn touch(&self, ids: &[UserSessionId]) -> Result<(), WarpgateError> {
        if ids.is_empty() {
            return Ok(());
        }
        HttpSession::Entity::update_many()
            .col_expr(
                HttpSession::Column::Updated,
                Expr::value(OffsetDateTime::now_utc()),
            )
            .filter(HttpSession::Column::UserSessionId.is_in(ids.iter().copied()))
            .exec(&self.db)
            .await?;
        Ok(())
    }

    /// Whether `error` is SQLite reporting lock contention (`SQLITE_BUSY` or
    /// `SQLITE_LOCKED`, including their extended codes).
    fn is_busy(&self, error: &WarpgateError) -> bool {
        if self.db.get_database_backend() != DbBackend::Sqlite {
            return false;
        }
        let mut source: Option<&(dyn std::error::Error + 'static)> = Some(error);
        while let Some(current) = source {
            if let Some(code) = current
                .downcast_ref::<sea_orm::sqlx::Error>()
                .and_then(|error| error.as_database_error())
                .and_then(|error| error.code())
                .and_then(|code| code.parse::<i32>().ok())
            {
                return matches!(code & 0xff, 5 | 6);
            }
            source = current.source();
        }
        false
    }

    fn row_is_expired(row: &HttpSession::Model, now: OffsetDateTime, max_age: Duration) -> bool {
        row.expires.is_some_and(|expires| expires < now) || row.updated < now - max_age
    }

    /// Removes one browser-session backing. The parent row serializes this with
    /// renewals and other removals; the login ends only when the removed row was
    /// its final backing.
    async fn remove_stored_row(
        &self,
        session_id: &str,
        only_if_expired: Option<(OffsetDateTime, Duration)>,
    ) -> Result<(), WarpgateError> {
        // The write lock taken below is only worth waiting for when there is
        // a row to remove: after `rotate_session_id`, poem removes the old id,
        // whose row is already gone. A row that disappears after this read is
        // caught by the reads inside the transaction.
        if self.db.get_database_backend() == DbBackend::Sqlite
            && HttpSession::Entity::find_by_id(session_id.to_owned())
                .one(&self.db)
                .await?
                .is_none()
        {
            return Ok(());
        }
        let transaction = self.db.begin().await?;
        // On SQLite, a transaction that has read and then writes cannot wait
        // for another writer: the upgrade fails at once with SQLITE_BUSY and
        // `busy_timeout` never applies. Making the first statement a write
        // takes the database's write lock up front, which does wait. This is
        // what `BEGIN IMMEDIATE` would do, but sea-orm 1.1 always begins with
        // a plain `BEGIN` and ignores `begin_with_config`'s options on SQLite.
        // The no-op update touches only the row being removed, and only on
        // SQLite: on PostgreSQL and MySQL it would lock this row before its
        // parent, the reverse of `update_session`'s order.
        if self.db.get_database_backend() == DbBackend::Sqlite {
            HttpSession::Entity::update_many()
                .col_expr(
                    HttpSession::Column::Id,
                    Expr::col(HttpSession::Column::Id).into(),
                )
                .filter(HttpSession::Column::Id.eq(session_id))
                .exec(&transaction)
                .await?;
        }
        let Some(initial) = HttpSession::Entity::find_by_id(session_id.to_owned())
            .one(&transaction)
            .await?
        else {
            transaction.commit().await?;
            return Ok(());
        };

        let user_session_id = initial.user_session_id;
        if let Some(id) = user_session_id {
            UserSession::lock_for_update(&transaction, id).await?;
        }

        // Re-read after taking the parent lock: a request that was already
        // updating this backing may have refreshed it before we acquired the
        // lock, in which case GC must leave it alone.
        let Some(current) = HttpSession::Entity::find_by_id(session_id.to_owned())
            .one(&transaction)
            .await?
        else {
            transaction.commit().await?;
            return Ok(());
        };
        if let Some((now, max_age)) = only_if_expired
            && !Self::row_is_expired(&current, now, max_age)
        {
            transaction.commit().await?;
            return Ok(());
        }

        HttpSession::Entity::delete_by_id(session_id.to_owned())
            .exec(&transaction)
            .await?;

        let ended = if let Some(id) = user_session_id {
            let remaining = HttpSession::Entity::find()
                .filter(HttpSession::Column::UserSessionId.eq(id))
                .count(&transaction)
                .await?;
            if remaining == 0 {
                Some(UserSession::mark_ended_in_transaction(&transaction, id).await?)
            } else {
                None
            }
        } else {
            None
        };

        transaction.commit().await?;
        if let Some(ended) = ended {
            ended.emit();
        }
        Ok(())
    }

    fn user_session_id_of(entries: &BTreeMap<String, Value>) -> Option<UserSessionId> {
        entries
            .get(SESSION_ID_SESSION_KEY)
            .and_then(|value| serde_json::from_value::<UserSessionId>(value.clone()).ok())
    }

    /// rotate the session's storage id, keeping its contents
    ///
    /// The stored row is deleted here rather than left to the renewal itself:
    /// [`SessionStorage::remove_session`] ends the user session a row backs,
    /// which is right when a browser session is being destroyed and wrong when
    /// it is being re-keyed. With the row already gone, the renewal's removal
    /// finds nothing to end and only writes the new one.
    pub async fn rotate_session_id(
        &self,
        stored_id: Option<String>,
        session: &Session,
    ) -> Result<(), WarpgateError> {
        if let Some(id) = stored_id {
            let user_session_id = session.get_session_id();
            let transaction = self.db.begin().await?;
            if let Some(user_session_id) = user_session_id {
                UserSession::lock_for_update(&transaction, user_session_id).await?;
            }
            HttpSession::Entity::delete_by_id(&id)
                .exec(&transaction)
                .await?;
            transaction.commit().await?;
        }
        session.renew();
        Ok(())
    }
}

impl SessionStorage for SharedSessionStorage {
    async fn load_session<'a>(
        &'a self,
        session_id: &'a str,
    ) -> poem::Result<Option<BTreeMap<String, Value>>> {
        let Some(model) = HttpSession::Entity::find_by_id(session_id.to_owned())
            .one(&self.db)
            .await
            .context("HTTP session not found")?
        else {
            return Ok(None);
        };

        if model
            .expires
            .is_some_and(|e| e <= OffsetDateTime::now_utc())
        {
            return Ok(None);
        }

        let entries: BTreeMap<String, Value> =
            serde_json::from_str(&model.data).map_err(InternalServerError)?;
        self.record_loaded(session_id);
        Ok(Some(entries))
    }

    /// Insert or update a session.
    async fn update_session<'a>(
        &'a self,
        session_id: &'a str,
        entries: &'a BTreeMap<String, Value>,
        expires: Option<Duration>,
    ) -> poem::Result<()> {
        let now = OffsetDateTime::now_utc();
        let data = serde_json::to_string(entries).map_err(InternalServerError)?;
        let user_session_id = Self::user_session_id_of(entries);
        let model = HttpSession::ActiveModel {
            id: Set(session_id.to_owned()),
            expires: Set(expires.map(|d| now + d)),
            data: Set(data),
            updated: Set(now),
            // Mirrored out of the entries so ending, revocation and reaping
            // query an indexed column instead of parsing JSON.
            user_session_id: Set(user_session_id),
        };
        let transaction = self.db.begin().await.map_err(InternalServerError)?;

        if let Some(id) = user_session_id {
            let parent = UserSession::lock_for_update(&transaction, id)
                .await
                .map_err(InternalServerError)?;
            if parent.is_none_or(|parent| parent.ended.is_some()) {
                transaction.commit().await.map_err(InternalServerError)?;
                return Ok(());
            }
        }

        if self.was_loaded(session_id) {
            // This id was served from storage, so its row existed; one that is
            // gone now was explicitly removed or rotated. Updating only
            // prevents a concurrent stale request from recreating the old
            // cookie id after the replacement has been authenticated.
            HttpSession::Entity::update_many()
                .set(model)
                .filter(HttpSession::Column::Id.eq(session_id))
                .exec(&transaction)
                .await
                .map_err(InternalServerError)?;
        } else {
            // `exec_without_returning` avoids the last-insert-id path, which
            // MySQL upserts of a non-auto-increment PK misbehave on.
            HttpSession::Entity::insert(model)
                .on_conflict(
                    OnConflict::column(HttpSession::Column::Id)
                        .update_columns([
                            HttpSession::Column::Expires,
                            HttpSession::Column::Data,
                            HttpSession::Column::Updated,
                            HttpSession::Column::UserSessionId,
                        ])
                        .to_owned(),
                )
                .exec_without_returning(&transaction)
                .await
                .map_err(InternalServerError)?;
        }
        transaction.commit().await.map_err(InternalServerError)?;
        Ok(())
    }

    /// Remove a session by session id. Idempotent: removing an absent id is Ok.
    async fn remove_session<'a>(&'a self, session_id: &'a str) -> poem::Result<()> {
        self.remove_stored_row(session_id, None)
            .await
            .map_err(InternalServerError)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use poem::session::SessionStatus;
    use sea_orm::Database;
    use warpgate_common_http::SessionAuthorization;

    use super::*;
    use crate::test_db::{HOLD, TempDb, file_db};

    async fn storage() -> SharedSessionStorage {
        warpgate_db_entities::Parameters::set_config_migration_values(
            warpgate_db_entities::Parameters::ConfigMigrationValues::default(),
        );
        let db = Database::connect("sqlite::memory:").await.unwrap();
        warpgate_db_migrations::migrate_database(&db).await.unwrap();
        SharedSessionStorage::new(db)
    }

    async fn file_storage(busy_timeout: Duration) -> (SharedSessionStorage, TempDb) {
        let (db, temp) = file_db(busy_timeout).await;
        (SharedSessionStorage::new(db), temp)
    }

    async fn hold_write_lock(
        storage: &SharedSessionStorage,
        hold: Duration,
    ) -> tokio::task::JoinHandle<()> {
        crate::test_db::hold_write_lock(&storage.db, hold).await
    }

    fn entries(auth: &str) -> BTreeMap<String, Value> {
        let mut m = BTreeMap::new();
        m.insert("auth".to_string(), Value::from(auth));
        m
    }

    fn expired_row(id: &str) -> HttpSession::ActiveModel {
        let past = OffsetDateTime::now_utc() - Duration::from_secs(60);
        HttpSession::ActiveModel {
            id: Set(id.to_string()),
            expires: Set(Some(past)),
            data: Set("{}".to_string()),
            updated: Set(past),
            user_session_id: Set(None),
        }
    }

    async fn insert_user_session(storage: &SharedSessionStorage) -> UserSessionId {
        let id = UserSessionId(Uuid::new_v4());
        UserSession::Entity::insert(UserSession::ActiveModel {
            id: Set(id),
            username: Set(Some("alice".into())),
            user_id: Set(Some(Uuid::new_v4())),
            remote_address: Set("127.0.0.1:443".into()),
            started: Set(OffsetDateTime::now_utc()),
            ended: Set(None),
            protocol: Set("HTTP".into()),
            node_id: Set(None),
            auth_state_node_id: Set(None),
        })
        .exec(&storage.db)
        .await
        .unwrap();
        id
    }

    fn entries_for_user_session(id: UserSessionId) -> BTreeMap<String, Value> {
        let mut data = entries("a");
        data.insert(
            SESSION_ID_SESSION_KEY.into(),
            serde_json::to_value(id).unwrap(),
        );
        data
    }

    #[tokio::test]
    async fn load_absent_is_none() {
        let s = storage().await;
        assert!(s.load_session("nope").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn roundtrip_returns_entries_verbatim() {
        let s = storage().await;
        s.update_session("id1", &entries("stamp"), Some(Duration::from_secs(3600)))
            .await
            .unwrap();
        let loaded = s.load_session("id1").await.unwrap().unwrap();
        assert_eq!(loaded, entries("stamp"));
    }

    #[tokio::test]
    async fn update_upserts() {
        let s = storage().await;
        s.update_session("id1", &entries("a"), Some(Duration::from_secs(3600)))
            .await
            .unwrap();
        s.update_session("id1", &entries("b"), Some(Duration::from_secs(3600)))
            .await
            .unwrap();
        let loaded = s.load_session("id1").await.unwrap().unwrap();
        assert_eq!(loaded.get("auth"), Some(&Value::from("b")));
    }

    #[tokio::test]
    async fn adopt_stored_replaces_the_local_copy() {
        let s = storage().await;
        s.update_session("id1", &entries("peer"), Some(Duration::from_secs(3600)))
            .await
            .unwrap();

        // What a forwarding node still holds: the copy it loaded before the hop.
        let session = Session::default();
        session.set("auth", "stale");
        session.set("dropped_by_peer", true);

        s.adopt_stored(Some("id1".into()), &session).await.unwrap();

        assert_eq!(session.get::<String>("auth").as_deref(), Some("peer"));
        assert_eq!(session.get::<bool>("dropped_by_peer"), None);
    }

    #[tokio::test]
    async fn adopt_stored_purges_a_session_the_peer_removed() {
        let s = storage().await;
        let session = Session::default();

        s.adopt_stored(Some("id1".into()), &session).await.unwrap();

        assert_eq!(session.status(), poem::session::SessionStatus::Purged);
    }

    const ALICE: Uuid = Uuid::from_u128(1);
    const BOB: Uuid = Uuid::from_u128(2);

    /// A browser session backing `id`, logged in as `user_id`.
    fn logged_in(id: UserSessionId, user_id: Uuid) -> Session {
        let session = Session::default();
        session.set(SESSION_ID_SESSION_KEY, id);
        session.set_auth(SessionAuthorization::User {
            user_id,
            username: user_id.to_string(),
        });
        session
    }

    /// Runs the forwarding node's side of a login step the peer answered by
    /// storing `stored` as the browser session `id1`: `session` is the copy
    /// the node loaded before the hop, and afterwards holds what it writes
    /// back.
    async fn adopt_after_hop(s: &SharedSessionStorage, stored: &Session, session: &Session) {
        s.update_session("id1", &stored.entries(), Some(Duration::from_secs(3600)))
            .await
            .unwrap();
        let before_hop = LoginSnapshot::of(session);
        s.adopt_forwarded_login(Some("id1".into()), session, before_hop)
            .await
            .unwrap();
    }

    async fn assert_rotated(s: &SharedSessionStorage, session: &Session) {
        assert_eq!(
            session.status(),
            SessionStatus::Renewed,
            "the storage id was kept"
        );
        assert!(s.load_session("id1").await.unwrap().is_none());
    }

    /// A stale cookie still logged in under a closed session, whose forwarded
    /// login replaced that session and logged the replacement in: the login
    /// existed before the hop, but it is a new one on a new session.
    #[tokio::test]
    async fn a_forwarded_login_on_a_replaced_session_rotates_the_id() {
        let s = storage().await;
        let replacement = insert_user_session(&s).await;
        let closed = UserSessionId(Uuid::new_v4());
        let session = logged_in(closed, ALICE);

        adopt_after_hop(&s, &logged_in(replacement, ALICE), &session).await;

        assert_rotated(&s, &session).await;
        assert_eq!(session.get_session_id(), Some(replacement));
    }

    /// The same browser session, logged in as someone else by the step.
    #[tokio::test]
    async fn a_forwarded_login_as_another_user_rotates_the_id() {
        let s = storage().await;
        let id = insert_user_session(&s).await;
        let session = logged_in(id, ALICE);

        adopt_after_hop(&s, &logged_in(id, BOB), &session).await;

        assert_rotated(&s, &session).await;
    }

    /// A first login, the case that never carried a login before the hop.
    #[tokio::test]
    async fn a_forwarded_first_login_rotates_the_id() {
        let s = storage().await;
        let id = insert_user_session(&s).await;
        let session = Session::default();
        session.set(SESSION_ID_SESSION_KEY, id);

        adopt_after_hop(&s, &logged_in(id, ALICE), &session).await;

        assert_rotated(&s, &session).await;
    }

    /// A step that left the login as it was, such as a state poll from a
    /// logged-in browser, keeps the id.
    #[tokio::test]
    async fn a_forwarded_step_that_changed_no_login_keeps_the_id() {
        let s = storage().await;
        let id = insert_user_session(&s).await;
        let session = logged_in(id, ALICE);

        adopt_after_hop(&s, &logged_in(id, ALICE), &session).await;

        assert_ne!(session.status(), SessionStatus::Renewed);
        assert!(s.load_session("id1").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn remove_is_idempotent() {
        let s = storage().await;
        s.update_session("id1", &entries("a"), Some(Duration::from_secs(3600)))
            .await
            .unwrap();
        s.remove_session("id1").await.unwrap();
        assert!(s.load_session("id1").await.unwrap().is_none());
        // Removing an already-absent id is not an error.
        s.remove_session("id1").await.unwrap();
    }

    #[tokio::test]
    async fn removing_http_session_ends_its_user_session() {
        let s = storage().await;
        let id = insert_user_session(&s).await;
        let data = entries_for_user_session(id);
        s.update_session("id1", &data, Some(Duration::from_secs(3600)))
            .await
            .unwrap();

        s.remove_session("id1").await.unwrap();

        assert!(
            UserSession::Entity::find_by_id(id)
                .one(&s.db)
                .await
                .unwrap()
                .unwrap()
                .ended
                .is_some()
        );
    }

    #[tokio::test]
    async fn removing_one_backing_keeps_a_still_backed_user_session_open() {
        let s = storage().await;
        let id = insert_user_session(&s).await;
        let data = entries_for_user_session(id);
        s.update_session("id1", &data, Some(Duration::from_secs(3600)))
            .await
            .unwrap();
        s.update_session("id2", &data, Some(Duration::from_secs(3600)))
            .await
            .unwrap();

        s.remove_session("id1").await.unwrap();

        assert!(s.load_session("id2").await.unwrap().is_some());
        assert!(
            UserSession::Entity::find_by_id(id)
                .one(&s.db)
                .await
                .unwrap()
                .unwrap()
                .ended
                .is_none()
        );
    }

    #[tokio::test]
    async fn rotation_cannot_be_undone_by_a_stale_loaded_request() {
        let s = storage().await;
        let id = insert_user_session(&s).await;
        let data = entries_for_user_session(id);
        s.update_session("id1", &data, Some(Duration::from_secs(3600)))
            .await
            .unwrap();
        let stale = s.load_session("id1").await.unwrap().unwrap();

        let rotating = Session::default();
        rotating.set(SESSION_ID_SESSION_KEY, id);
        s.rotate_session_id(Some("id1".into()), &rotating)
            .await
            .unwrap();
        s.update_session("id2", &data, Some(Duration::from_secs(3600)))
            .await
            .unwrap();

        s.update_session("id1", &stale, Some(Duration::from_secs(3600)))
            .await
            .unwrap();

        assert!(s.load_session("id1").await.unwrap().is_none());
        assert!(s.load_session("id2").await.unwrap().is_some());
        assert!(
            UserSession::Entity::find_by_id(id)
                .one(&s.db)
                .await
                .unwrap()
                .unwrap()
                .ended
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_loaded_rows_removal_survives_its_write_back() {
        let s = storage().await;
        s.update_session("id1", &entries("a"), Some(Duration::from_secs(3600)))
            .await
            .unwrap();
        let held = s.load_session("id1").await.unwrap().unwrap();

        s.remove_session("id1").await.unwrap();
        // The write-back of a request that loaded the row before its removal.
        s.update_session("id1", &held, Some(Duration::from_secs(3600)))
            .await
            .unwrap();

        assert!(s.load_session("id1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn expired_row_refused_on_read() {
        let s = storage().await;
        HttpSession::Entity::insert(expired_row("old"))
            .exec(&s.db)
            .await
            .unwrap();
        // Load-time check refuses it even before a GC sweep runs.
        assert!(s.load_session("old").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn gc_sweeps_expired() {
        let s = storage().await;
        HttpSession::Entity::insert(expired_row("old"))
            .exec(&s.db)
            .await
            .unwrap();
        s.update_session("live", &entries("a"), Some(Duration::from_secs(3600)))
            .await
            .unwrap();
        s.gc(Duration::from_secs(86400)).await.unwrap();
        assert!(
            HttpSession::Entity::find_by_id("old".to_string())
                .one(&s.db)
                .await
                .unwrap()
                .is_none()
        );
        assert!(s.load_session("live").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn remove_waits_for_a_concurrent_writer() {
        let (s, _temp) = file_storage(Duration::from_secs(30)).await;
        let id = insert_user_session(&s).await;
        let data = entries_for_user_session(id);
        s.update_session("id1", &data, Some(Duration::from_secs(3600)))
            .await
            .unwrap();

        let writer = hold_write_lock(&s, HOLD).await;
        let started = Instant::now();
        s.remove_session("id1").await.unwrap();
        assert!(started.elapsed() >= HOLD / 2, "removal did not contend");
        writer.await.unwrap();

        assert!(s.load_session("id1").await.unwrap().is_none());
        assert!(
            UserSession::Entity::find_by_id(id)
                .one(&s.db)
                .await
                .unwrap()
                .unwrap()
                .ended
                .is_some()
        );
    }

    #[tokio::test]
    async fn removing_an_absent_id_does_not_wait_for_a_concurrent_writer() {
        let (s, _temp) = file_storage(Duration::from_secs(30)).await;

        let writer = hold_write_lock(&s, HOLD).await;
        let started = Instant::now();
        s.remove_session("absent").await.unwrap();
        let elapsed = started.elapsed();
        writer.await.unwrap();

        assert!(elapsed < HOLD / 2, "removal waited {elapsed:?}");
    }

    #[tokio::test]
    async fn gc_waits_for_a_concurrent_writer() {
        let (s, _temp) = file_storage(Duration::from_secs(30)).await;
        HttpSession::Entity::insert(expired_row("orphan"))
            .exec(&s.db)
            .await
            .unwrap();
        let id = insert_user_session(&s).await;
        let mut backed = expired_row("backed");
        backed.user_session_id = Set(Some(id));
        HttpSession::Entity::insert(backed)
            .exec(&s.db)
            .await
            .unwrap();

        let writer = hold_write_lock(&s, HOLD).await;
        let started = Instant::now();
        s.gc(Duration::from_secs(86400)).await.unwrap();
        let elapsed = started.elapsed();
        writer.await.unwrap();

        for id in ["orphan", "backed"] {
            assert!(
                HttpSession::Entity::find_by_id(id.to_string())
                    .one(&s.db)
                    .await
                    .unwrap()
                    .is_none(),
                "{id} survived GC"
            );
        }
        assert!(elapsed >= HOLD / 2, "GC did not contend");
        assert!(
            UserSession::Entity::find_by_id(id)
                .one(&s.db)
                .await
                .unwrap()
                .unwrap()
                .ended
                .is_some()
        );
    }

    #[tokio::test]
    async fn gc_stops_at_the_first_busy_row() {
        // The lock is held for longer than three removals would take to time
        // out one after another.
        const BUSY_TIMEOUT: Duration = Duration::from_secs(1);
        let (s, _temp) = file_storage(BUSY_TIMEOUT).await;
        for id in ["a", "b", "c"] {
            HttpSession::Entity::insert(expired_row(id))
                .exec(&s.db)
                .await
                .unwrap();
        }

        let writer = hold_write_lock(&s, BUSY_TIMEOUT * 5).await;
        let started = Instant::now();
        s.gc(Duration::from_secs(86400)).await.unwrap();
        let elapsed = started.elapsed();
        writer.await.unwrap();

        assert!(elapsed < BUSY_TIMEOUT * 2, "GC kept going after a busy row: {elapsed:?}");
        for id in ["a", "b", "c"] {
            assert!(
                HttpSession::Entity::find_by_id(id.to_string())
                    .one(&s.db)
                    .await
                    .unwrap()
                    .is_some(),
                "{id} removed while the database was busy"
            );
        }
    }

    #[tokio::test]
    async fn contention_past_the_busy_timeout_is_reported_as_busy() {
        let (s, _temp) = file_storage(Duration::ZERO).await;
        s.update_session("id1", &entries("a"), Some(Duration::from_secs(3600)))
            .await
            .unwrap();

        let writer = hold_write_lock(&s, HOLD).await;
        let error = s.remove_stored_row("id1", None).await.unwrap_err();
        writer.await.unwrap();

        assert!(s.is_busy(&error), "{error}");
        assert!(!s.is_busy(&WarpgateError::SessionEnd));
    }

    #[tokio::test]
    async fn gc_age_fallback_sweeps_stale_null_expires() {
        let s = storage().await;
        let stale = OffsetDateTime::now_utc() - Duration::from_secs(3600);
        let null_row = |id: &str, updated| HttpSession::ActiveModel {
            id: Set(id.to_string()),
            expires: Set(None),
            data: Set("{}".to_string()),
            updated: Set(updated),
            user_session_id: Set(None),
        };
        HttpSession::Entity::insert(null_row("stale", stale))
            .exec(&s.db)
            .await
            .unwrap();
        HttpSession::Entity::insert(null_row("fresh", OffsetDateTime::now_utc()))
            .exec(&s.db)
            .await
            .unwrap();

        s.gc(Duration::from_secs(1800)).await.unwrap();

        // Untouched longer than the cap → reaped even with null expiry.
        assert!(s.load_session("stale").await.unwrap().is_none());
        // Recently written → kept.
        assert!(s.load_session("fresh").await.unwrap().is_some());
    }
}
