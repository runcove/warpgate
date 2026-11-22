//! The Ed25519 keys that sign session statements
//! ([`crate::session_statement`]).
//!
//! Up to three keys, one per [`StatementKeySlot`]: `active` signs, `next` is
//! published ahead of a promotion, `retiring` is published after one. The
//! private half is stored encrypted with the keyring, is never returned by
//! any API, never logged, and never part of a target's options. Without
//! `WARPGATE_ENCRYPTION_KEY` there is no statement key: none is generated,
//! none is published and nothing is signed.
//!
//! Rotation is host-only (`warpgate statement-keys`), publish first, then
//! sign: `add-next`, then (once every verifier has pinned it) `promote`, then
//! `retire` the old key. Each node reads the active key from the database at
//! most every few seconds ([`ACTIVE_KEY_CACHE_TTL`]), so a promotion needs no
//! signal.

use std::sync::{Arc, LazyLock, Mutex, PoisonError};
use std::time::{Duration, Instant};

use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::RngExt;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, EntityTrait, QueryFilter,
    QueryOrder, Set, TransactionTrait,
};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tracing::{info, warn};
use warpgate_common::encryption::env_keyring;
use warpgate_common::{StoredSecret, WarpgateError};
use warpgate_db_entities::StatementKey::{self, StatementKeySlot};

/// The only algorithm.
pub const STATEMENT_KEY_ALG: &str = "Ed25519";

/// The key id: SHA-256 of the raw 32-byte public key, base64url without
/// padding (43 characters).
pub fn kid_for(public: &VerifyingKey) -> String {
    BASE64URL_NOPAD.encode(&Sha256::digest(public.as_bytes()))
}

/// Whether this process can hold a statement key: only with an encryption
/// key configured.
pub fn statement_keys_enabled() -> bool {
    env_keyring().primary().is_some()
}

/// A published key: its id, its public half, and whether it signs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishedStatementKey {
    pub kid: String,
    /// base64url (no padding) of the raw 32-byte public key
    pub public_key: String,
    pub slot: StatementKeySlot,
    pub created_at: OffsetDateTime,
}

impl PublishedStatementKey {
    pub fn signing(&self) -> bool {
        self.slot == StatementKeySlot::Active
    }
}

impl From<StatementKey::Model> for PublishedStatementKey {
    fn from(model: StatementKey::Model) -> Self {
        Self {
            kid: model.kid,
            public_key: model.public_key,
            slot: model.slot,
            created_at: model.created_at,
        }
    }
}

/// The key that signs, decrypted. Its `Debug` names only the key id.
pub struct ActiveStatementKey {
    pub kid: String,
    pub key: SigningKey,
}

impl ActiveStatementKey {
    /// The key for a 32-byte seed, under its own id.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let key = SigningKey::from_bytes(seed);
        Self {
            kid: kid_for(&key.verifying_key()),
            key,
        }
    }
}

impl std::fmt::Debug for ActiveStatementKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<statement key {}>", self.kid)
    }
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum StatementKeyError {
    #[error("statement keys need WARPGATE_ENCRYPTION_KEY to be set")]
    NoEncryptionKey,
    #[error("a next key already exists ({0}); promote or retire it first")]
    NextExists(String),
    #[error("a key with id {0} already exists")]
    DuplicateKid(String),
    #[error("no key with id {0}")]
    UnknownKid(String),
    #[error("key {0} is not the next key")]
    NotNext(String),
    #[error("a retiring key still exists ({0}); retire it first")]
    RetiringExists(String),
    #[error("key {0} is the active key and signs; promote another key first")]
    RetireActive(String),
    #[error("database: {0}")]
    Database(String),
    #[error("encryption: {0}")]
    Encryption(String),
}

impl From<sea_orm::DbErr> for StatementKeyError {
    fn from(error: sea_orm::DbErr) -> Self {
        Self::Database(error.to_string())
    }
}

/// A new key pair, its id, and the stored (encrypted) seed.
fn generate() -> Result<(String, String, StoredSecret), StatementKeyError> {
    let mut seed = [0u8; 32];
    rand::rng().fill(&mut seed[..]);
    let key = SigningKey::from_bytes(&seed);
    let public = key.verifying_key();
    let secret = StoredSecret::encrypted(BASE64URL_NOPAD.encode(&seed))
        .map_err(|e| StatementKeyError::Encryption(e.to_string()))?;
    seed.fill(0);
    Ok((
        kid_for(&public),
        BASE64URL_NOPAD.encode(public.as_bytes()),
        secret,
    ))
}

async fn insert(
    db: &impl ConnectionTrait,
    slot: StatementKeySlot,
) -> Result<String, StatementKeyError> {
    let (kid, public_key, secret_key) = generate()?;
    if StatementKey::Entity::find_by_id(kid.clone())
        .one(db)
        .await?
        .is_some()
    {
        return Err(StatementKeyError::DuplicateKid(kid));
    }
    StatementKey::ActiveModel {
        kid: Set(kid.clone()),
        public_key: Set(public_key),
        secret_key: Set(secret_key),
        slot: Set(slot),
        created_at: Set(OffsetDateTime::now_utc()),
    }
    .insert(db)
    .await?;
    Ok(kid)
}

async fn in_slot(
    db: &impl ConnectionTrait,
    slot: StatementKeySlot,
) -> Result<Option<StatementKey::Model>, StatementKeyError> {
    Ok(StatementKey::Entity::find()
        .filter(StatementKey::Column::Slot.eq(slot))
        .one(db)
        .await?)
}

/// At startup: generate the active key if there is none and an encryption
/// key is configured. Returns the active key's id, if there is one. Two
/// nodes racing here are kept to one active key by the slot's unique index;
/// the loser's insert fails and it reads the winner's.
pub async fn ensure_statement_key(
    db: &DatabaseConnection,
) -> Result<Option<String>, WarpgateError> {
    ensure_statement_key_with(db, statement_keys_enabled()).await
}

pub(crate) async fn ensure_statement_key_with(
    db: &DatabaseConnection,
    enabled: bool,
) -> Result<Option<String>, WarpgateError> {
    if !enabled {
        return Ok(None);
    }
    if let Some(active) = in_slot(db, StatementKeySlot::Active)
        .await
        .map_err(|e| WarpgateError::InconsistentState(e.to_string()))?
    {
        return Ok(Some(active.kid));
    }
    match insert(db, StatementKeySlot::Active).await {
        Ok(kid) => {
            ACTIVE_KEY_CACHE.clear();
            info!(%kid, "Generated the session statement key");
            Ok(Some(kid))
        }
        Err(error) => {
            // Another node may have won the race: take its key.
            let winner = in_slot(db, StatementKeySlot::Active)
                .await
                .map_err(|e| WarpgateError::InconsistentState(e.to_string()))?;
            match winner {
                Some(active) => Ok(Some(active.kid)),
                None => Err(WarpgateError::InconsistentState(error.to_string())),
            }
        }
    }
}

/// The published keys: empty without an encryption key.
pub async fn published_statement_keys(
    db: &DatabaseConnection,
) -> Result<Vec<PublishedStatementKey>, WarpgateError> {
    published_statement_keys_with(db, statement_keys_enabled()).await
}

pub(crate) async fn published_statement_keys_with(
    db: &DatabaseConnection,
    enabled: bool,
) -> Result<Vec<PublishedStatementKey>, WarpgateError> {
    if !enabled {
        return Ok(vec![]);
    }
    Ok(StatementKey::Entity::find()
        .order_by_asc(StatementKey::Column::CreatedAt)
        .order_by_asc(StatementKey::Column::Kid)
        .all(db)
        .await?
        .into_iter()
        .map(Into::into)
        .collect())
}

/// How long a decrypted signing key is reused before the database is read
/// again. A change made by another process (the `statement-keys` command)
/// shows within this; one made in this process drops the cache at once. A
/// promoted-away key is still published as retiring for at least this long, so
/// a statement it signs in the window still verifies.
const ACTIVE_KEY_CACHE_TTL: Duration = Duration::from_secs(5);

/// The decrypted active key, kept for [`ACTIVE_KEY_CACHE_TTL`].
#[derive(Default)]
struct ActiveKeyCache(Mutex<Option<(Instant, Arc<ActiveStatementKey>)>>);

impl ActiveKeyCache {
    fn get(&self, ttl: Duration) -> Option<Arc<ActiveStatementKey>> {
        let guard = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        guard
            .as_ref()
            .filter(|(at, _)| at.elapsed() < ttl)
            .map(|(_, key)| key.clone())
    }

    fn put(&self, key: Arc<ActiveStatementKey>) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Some((Instant::now(), key));
    }

    fn clear(&self) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }
}

static ACTIVE_KEY_CACHE: LazyLock<ActiveKeyCache> = LazyLock::new(ActiveKeyCache::default);

/// The key that signs, decrypted once and reused for a few seconds, not read
/// per request. `None` without an encryption key, without an active key, or
/// when it cannot be decrypted (then a warning; the statement is left out and
/// the target fails closed). Only a key is cached, never an absence.
pub async fn active_statement_key(
    db: &DatabaseConnection,
) -> Result<Option<Arc<ActiveStatementKey>>, WarpgateError> {
    cached_active_statement_key(
        &ACTIVE_KEY_CACHE,
        db,
        statement_keys_enabled(),
        ACTIVE_KEY_CACHE_TTL,
    )
    .await
}

async fn cached_active_statement_key(
    cache: &ActiveKeyCache,
    db: &DatabaseConnection,
    enabled: bool,
    ttl: Duration,
) -> Result<Option<Arc<ActiveStatementKey>>, WarpgateError> {
    if !enabled {
        return Ok(None);
    }
    if let Some(key) = cache.get(ttl) {
        return Ok(Some(key));
    }
    let key = active_statement_key_with(db, enabled).await?.map(Arc::new);
    if let Some(key) = &key {
        cache.put(key.clone());
    }
    Ok(key)
}

pub(crate) async fn active_statement_key_with(
    db: &DatabaseConnection,
    enabled: bool,
) -> Result<Option<ActiveStatementKey>, WarpgateError> {
    if !enabled {
        return Ok(None);
    }
    let Some(row) = StatementKey::Entity::find()
        .filter(StatementKey::Column::Slot.eq(StatementKeySlot::Active))
        .one(db)
        .await?
    else {
        return Ok(None);
    };
    let key = row
        .secret_key
        .reveal()
        .ok()
        .and_then(|seed| BASE64URL_NOPAD.decode(seed.expose_secret().as_bytes()).ok())
        .and_then(|seed| <[u8; 32]>::try_from(seed.as_slice()).ok())
        .map(|seed| SigningKey::from_bytes(&seed));
    let Some(key) = key else {
        warn!(kid = %row.kid, "The session statement key cannot be decrypted; no statements are sent");
        return Ok(None);
    };
    if kid_for(&key.verifying_key()) != row.kid {
        warn!(kid = %row.kid, "The session statement key does not match its id; no statements are sent");
        return Ok(None);
    }
    Ok(Some(ActiveStatementKey { kid: row.kid, key }))
}

/// `statement-keys add-next`: publish a new key that does not sign yet.
pub async fn add_next_statement_key(db: &DatabaseConnection) -> Result<String, StatementKeyError> {
    add_next_with(db, statement_keys_enabled()).await
}

pub(crate) async fn add_next_with(
    db: &DatabaseConnection,
    enabled: bool,
) -> Result<String, StatementKeyError> {
    if !enabled {
        return Err(StatementKeyError::NoEncryptionKey);
    }
    let txn = db.begin().await?;
    if let Some(next) = in_slot(&txn, StatementKeySlot::Next).await? {
        return Err(StatementKeyError::NextExists(next.kid));
    }
    let kid = insert(&txn, StatementKeySlot::Next).await?;
    txn.commit().await?;
    Ok(kid)
}

/// `statement-keys promote <kid>`: the next key signs; the active one
/// becomes retiring.
pub async fn promote_statement_key(
    db: &DatabaseConnection,
    kid: &str,
) -> Result<(), StatementKeyError> {
    let txn = db.begin().await?;
    let Some(target) = StatementKey::Entity::find_by_id(kid.to_owned())
        .one(&txn)
        .await?
    else {
        return Err(StatementKeyError::UnknownKid(kid.into()));
    };
    if target.slot != StatementKeySlot::Next {
        return Err(StatementKeyError::NotNext(kid.into()));
    }
    if let Some(retiring) = in_slot(&txn, StatementKeySlot::Retiring).await? {
        return Err(StatementKeyError::RetiringExists(retiring.kid));
    }
    // The unique slot index forbids two rows in one slot at any point, so
    // the moves go one at a time: active -> retiring, then next -> active.
    if let Some(active) = in_slot(&txn, StatementKeySlot::Active).await? {
        let mut active: StatementKey::ActiveModel = active.into();
        active.slot = Set(StatementKeySlot::Retiring);
        active.update(&txn).await?;
    }
    let mut target: StatementKey::ActiveModel = target.into();
    target.slot = Set(StatementKeySlot::Active);
    target.update(&txn).await?;
    txn.commit().await?;
    ACTIVE_KEY_CACHE.clear();
    Ok(())
}

/// `statement-keys retire <kid>`: remove a next or retiring key. The active
/// key cannot be removed.
pub async fn retire_statement_key(
    db: &DatabaseConnection,
    kid: &str,
) -> Result<(), StatementKeyError> {
    let txn = db.begin().await?;
    let Some(row) = StatementKey::Entity::find_by_id(kid.to_owned())
        .one(&txn)
        .await?
    else {
        return Err(StatementKeyError::UnknownKid(kid.into()));
    };
    if row.slot == StatementKeySlot::Active {
        return Err(StatementKeyError::RetireActive(kid.into()));
    }
    StatementKey::Entity::delete_by_id(kid.to_owned())
        .exec(&txn)
        .await?;
    txn.commit().await?;
    ACTIVE_KEY_CACHE.clear();
    Ok(())
}

/// Every key, whatever the encryption state, for `statement-keys list`.
pub async fn list_statement_keys(
    db: &DatabaseConnection,
) -> Result<Vec<PublishedStatementKey>, WarpgateError> {
    published_statement_keys_with(db, true).await
}

#[cfg(test)]
mod tests {
    use sea_orm::Database;

    use super::*;

    async fn memory_db() -> DatabaseConnection {
        warpgate_db_entities::Parameters::set_config_migration_values(
            warpgate_db_entities::Parameters::ConfigMigrationValues::default(),
        );
        let db = Database::connect("sqlite::memory:").await.unwrap();
        warpgate_db_migrations::migrate_database(&db).await.unwrap();
        db
    }

    fn slots(keys: &[PublishedStatementKey]) -> Vec<(&str, &'static str)> {
        keys.iter()
            .map(|k| (k.kid.as_str(), k.slot.name()))
            .collect()
    }

    #[tokio::test]
    async fn without_an_encryption_key_there_is_no_key_none_published_and_none_signs() {
        let db = memory_db().await;
        assert_eq!(ensure_statement_key_with(&db, false).await.unwrap(), None);
        assert!(
            StatementKey::Entity::find()
                .all(&db)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            published_statement_keys_with(&db, false)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            active_statement_key_with(&db, false)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            add_next_with(&db, false).await.unwrap_err(),
            StatementKeyError::NoEncryptionKey
        );

        // A key made while one was configured is not published once it is gone.
        ensure_statement_key_with(&db, true).await.unwrap();
        assert!(
            published_statement_keys_with(&db, false)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            active_statement_key_with(&db, false)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn the_startup_key_is_made_once_and_its_id_is_the_hash_of_its_public_key() {
        let db = memory_db().await;
        let kid = ensure_statement_key_with(&db, true).await.unwrap().unwrap();
        assert_eq!(
            ensure_statement_key_with(&db, true)
                .await
                .unwrap()
                .as_deref(),
            Some(kid.as_str())
        );
        let published = published_statement_keys_with(&db, true).await.unwrap();
        assert_eq!(slots(&published), [(kid.as_str(), "active")]);
        assert_eq!(kid.len(), 43);

        let public: [u8; 32] = BASE64URL_NOPAD
            .decode(published[0].public_key.as_bytes())
            .unwrap()
            .try_into()
            .unwrap();
        let public = VerifyingKey::from_bytes(&public).unwrap();
        assert_eq!(kid_for(&public), kid);

        let active = active_statement_key_with(&db, true).await.unwrap().unwrap();
        assert_eq!(active.kid, kid);
        assert_eq!(active.key.verifying_key(), public);
        assert_eq!(format!("{active:?}"), format!("<statement key {kid}>"));
    }

    #[tokio::test]
    async fn the_stored_private_key_never_shows_in_debug_output() {
        let db = memory_db().await;
        ensure_statement_key_with(&db, true).await.unwrap();
        let row = StatementKey::Entity::find()
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        let seed = row.secret_key.reveal().unwrap().expose_secret().clone();
        let debug = format!("{row:?}");
        assert!(!debug.contains(&seed), "{debug}");
        assert!(debug.contains("<secret>"), "{debug}");
    }

    #[tokio::test]
    async fn publish_first_then_sign_then_retire() {
        let db = memory_db().await;
        let first = ensure_statement_key_with(&db, true).await.unwrap().unwrap();

        let next = add_next_with(&db, true).await.unwrap();
        assert_eq!(
            add_next_with(&db, true).await.unwrap_err(),
            StatementKeyError::NextExists(next.clone())
        );
        let keys = published_statement_keys_with(&db, true).await.unwrap();
        let mut got = slots(&keys);
        got.sort_unstable();
        let mut want = vec![(first.as_str(), "active"), (next.as_str(), "next")];
        want.sort_unstable();
        assert_eq!(got, want);
        // Published, not signing.
        assert_eq!(
            active_statement_key_with(&db, true)
                .await
                .unwrap()
                .unwrap()
                .kid,
            first
        );

        assert_eq!(
            promote_statement_key(&db, &first).await.unwrap_err(),
            StatementKeyError::NotNext(first.clone())
        );
        assert_eq!(
            promote_statement_key(&db, "nope").await.unwrap_err(),
            StatementKeyError::UnknownKid("nope".into())
        );
        promote_statement_key(&db, &next).await.unwrap();
        assert_eq!(
            active_statement_key_with(&db, true)
                .await
                .unwrap()
                .unwrap()
                .kid,
            next
        );
        let keys = published_statement_keys_with(&db, true).await.unwrap();
        assert!(
            keys.iter()
                .any(|k| k.kid == first && k.slot == StatementKeySlot::Retiring)
        );
        assert_eq!(keys.iter().filter(|k| k.signing()).count(), 1);

        // A second rotation waits for the retiring key to go.
        let third = add_next_with(&db, true).await.unwrap();
        assert_eq!(
            promote_statement_key(&db, &third).await.unwrap_err(),
            StatementKeyError::RetiringExists(first.clone())
        );

        assert_eq!(
            retire_statement_key(&db, &next).await.unwrap_err(),
            StatementKeyError::RetireActive(next.clone())
        );
        retire_statement_key(&db, &first).await.unwrap();
        retire_statement_key(&db, &third).await.unwrap();
        let keys = published_statement_keys_with(&db, true).await.unwrap();
        assert_eq!(slots(&keys), [(next.as_str(), "active")]);
    }

    #[tokio::test]
    async fn add_next_never_signs_until_promoted() {
        let db = memory_db().await;
        let kid = add_next_with(&db, true).await.unwrap();
        assert!(
            active_statement_key_with(&db, true)
                .await
                .unwrap()
                .is_none()
        );
        promote_statement_key(&db, &kid).await.unwrap();
        assert_eq!(
            active_statement_key_with(&db, true)
                .await
                .unwrap()
                .unwrap()
                .kid,
            kid
        );
    }

    /// The decrypted key is reused inside the cache's lifetime and read again
    /// after it, so a promotion made elsewhere shows once it has passed; an
    /// absent key is never cached.
    #[tokio::test]
    async fn the_active_key_is_cached_and_refreshed() {
        let db = memory_db().await;
        let cache = ActiveKeyCache::default();
        let long = Duration::from_secs(3600);
        assert!(
            cached_active_statement_key(&cache, &db, true, long)
                .await
                .unwrap()
                .is_none()
        );
        let first = ensure_statement_key_with(&db, true).await.unwrap().unwrap();
        let a = cached_active_statement_key(&cache, &db, true, long)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(a.kid, first);

        let next = add_next_with(&db, true).await.unwrap();
        promote_statement_key(&db, &next).await.unwrap();
        // Inside the lifetime: the cached key, with no database read.
        let b = cached_active_statement_key(&cache, &db, true, long)
            .await
            .unwrap()
            .unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        // Past it: the promoted key.
        let c = cached_active_statement_key(&cache, &db, true, Duration::ZERO)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(c.kid, next);
        cache.clear();
        assert!(cache.get(long).is_none());
    }
}
