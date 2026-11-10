//! Step-up SSO freshness helpers for per-credential periodic re-auth.
//!
//! Protocol handlers consult these helpers to decide whether a given
//! credential row must force an SSO / `WebUserApproval` step-up before
//! accepting the session. Freshness is evaluated per credential row so that
//! e.g. pubkey A on laptop 1 and pubkey B on laptop 2 hold independent clocks.
//!
//! Scope:
//! - SSH pubkey helpers (`get_pubkey_last_sso_at` /
//!   `update_pubkey_last_sso_at`) against `credentials_public_key`.
//! - HTTP sessions are stamped on the Poem session claim instead of a DB row
//!   (see `warpgate-protocol-http::step_up`).
use std::time::Duration;

use russh::keys::{HashAlg, PublicKey};
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};
use time::OffsetDateTime;
use tracing::{info, warn};
use uuid::Uuid;
use warpgate_common::{StepUpExemptUser, StepUpIntervalConfig, WarpgateError};
use warpgate_db_entities as entities;

/// Decide whether a credential's last SSO handshake is still "fresh" for the
/// configured step-up interval.
///
/// - `None` -> never handshaked -> not fresh (forces step-up).
/// - `Some(ts)` within `interval` (inclusive at `now - interval`) -> fresh.
/// - `Some(ts)` older than `interval` -> not fresh.
///
/// `now` is taken as a parameter so callers (and tests) pin a reference
/// instant; callers in production pass `OffsetDateTime::now_utc()`.
#[must_use]
pub fn is_fresh(
    last_sso_at: Option<OffsetDateTime>,
    interval: Duration,
    now: OffsetDateTime,
) -> bool {
    let Some(last) = last_sso_at else {
        return false;
    };
    let Ok(interval_td) = time::Duration::try_from(interval) else {
        // Implausibly large Duration: treat the credential as stale so we
        // force a step-up rather than silently passing.
        return false;
    };
    now - last <= interval_td
}

/// Where an open, key-authenticated connection stands against its step-up window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepUpWindow {
    /// Step-up is off for the protocol: the connection is not time-limited.
    NotApplicable,
    /// The window is still open for this long.
    Remaining(Duration),
    /// The window has passed (or the key was never stamped): close.
    Expired,
}

/// Evaluate an open connection's step-up window.
///
/// `interval` is the value read from the live config at evaluation time, so a
/// shorter interval closes sooner and a longer or removed one extends or
/// cancels. `last_sso_at` is re-read each time, so a fresh SSO for the key
/// extends the deadline. The boundary matches [`is_fresh`]: still open at
/// exactly `last_sso_at + interval`.
#[must_use]
pub fn step_up_window(
    last_sso_at: Option<OffsetDateTime>,
    interval: Option<Duration>,
    now: OffsetDateTime,
) -> StepUpWindow {
    let Some(interval) = interval else {
        return StepUpWindow::NotApplicable;
    };
    if !is_fresh(last_sso_at, interval, now) {
        return StepUpWindow::Expired;
    }
    // `is_fresh` was true, so `last_sso_at` is `Some` and the sum is in range.
    let Some(last) = last_sso_at else {
        return StepUpWindow::Expired;
    };
    let Ok(interval_td) = time::Duration::try_from(interval) else {
        return StepUpWindow::Expired;
    };
    // An unrepresentable deadline is so far off the window is effectively open;
    // report a day so the caller re-reads soon anyway.
    let Some(deadline) = last.checked_add(interval_td) else {
        return StepUpWindow::Remaining(Duration::from_secs(86_400));
    };
    Duration::try_from(deadline - now).map_or(StepUpWindow::Expired, StepUpWindow::Remaining)
}

/// Read the `last_sso_at` column for the given pubkey credential row.
///
/// Returns `Ok(None)` if the row exists but was never stamped, or if the row
/// no longer exists (defensive - a missing row cannot be fresh).
pub async fn get_pubkey_last_sso_at(
    db: &DatabaseConnection,
    pubkey_id: Uuid,
) -> Result<Option<OffsetDateTime>, WarpgateError> {
    let Some(row) = entities::PublicKeyCredential::Entity::find_by_id(pubkey_id)
        .one(db)
        .await?
    else {
        return Ok(None);
    };
    Ok(row.last_sso_at)
}

/// Stamp `last_sso_at` on the given pubkey credential row.
///
/// Idempotent and forward-only: later stamps always overwrite earlier ones.
/// Uses a single atomic UPDATE ... WHERE id = ? - one round trip, safe
/// against concurrent validate/stamp races. Returns the number of rows
/// affected; if the row vanished between validate and stamp (user deleted
/// the pubkey) the UPDATE affects zero rows. That's logged at debug and
/// treated as a benign no-op so the auth flow doesn't fail hard on a race.
pub async fn update_pubkey_last_sso_at(
    db: &DatabaseConnection,
    pubkey_id: Uuid,
    now: OffsetDateTime,
) -> Result<u64, WarpgateError> {
    let result = entities::PublicKeyCredential::Entity::update_many()
        .set(entities::PublicKeyCredential::ActiveModel {
            last_sso_at: Set(Some(now)),
            ..Default::default()
        })
        .filter(entities::PublicKeyCredential::Column::Id.eq(pubkey_id))
        .exec(db)
        .await?;

    if result.rows_affected == 0 {
        tracing::debug!(
            %pubkey_id,
            "update_pubkey_last_sso_at: row vanished between validate and stamp, no-op"
        );
    }
    Ok(result.rows_affected)
}

/// Why a listed user's `exempt_users` entry did not apply to a sign-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepUpExemptionIgnored {
    HasSsoCredential,
    HasPasswordCredential,
    KeyNotListed,
    TargetNotListed,
}

impl StepUpExemptionIgnored {
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::HasSsoCredential => "the user has an SSO credential",
            Self::HasPasswordCredential => "the user has a password credential",
            Self::KeyNotListed => "the sign-in key is not one of the listed keys",
            Self::TargetNotListed => "the target is not one of the listed targets",
        }
    }
}

/// How `step_up_interval.exempt_users` applies to one SSH public-key sign-in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepUpExemption {
    /// The user is not listed.
    NotListed,
    /// The sign-in skips the step-up check. Holds the OpenSSH SHA256
    /// fingerprints of the key rows it matched, as read for this decision.
    Applies(Vec<String>),
    /// The user is listed but the entry does not cover this sign-in.
    Ignored(StepUpExemptionIgnored),
}

impl StepUpExemption {
    #[must_use]
    pub const fn applies(&self) -> bool {
        matches!(self, Self::Applies(_))
    }
}

/// Decide whether an SSH public-key sign-in skips the step-up check because
/// of `step_up_interval.exempt_users`, and log the outcome (one info line when
/// it applies, one warning when a listed user's entry does not).
///
/// An entry applies only if all of these hold:
/// - the username equals the entry's `user` exactly;
/// - the user has no SSO credential and no password credential (read from the
///   same tables the MFA checks in `Services` use);
/// - every public key row the sign-in matched has an OpenSSH SHA256
///   fingerprint listed in the entry's `keys`, so a key added to the user
///   later is not covered;
/// - the entry has no `targets`, or `target_name` is one of them. An empty
///   `target_name` (no target chosen yet) is not one of them.
///
/// A database error is returned, never read as an exemption.
pub async fn ssh_step_up_exemption(
    db: &DatabaseConnection,
    step_up: &StepUpIntervalConfig,
    user_id: Uuid,
    username: &str,
    matched_pubkey_ids: &[Uuid],
    target_name: &str,
) -> Result<StepUpExemption, WarpgateError> {
    let entries: Vec<&StepUpExemptUser> = step_up.exempt_entries_for(username).collect();
    if entries.is_empty() {
        return Ok(StepUpExemption::NotListed);
    }

    match listed_user_outcome(db, &entries, user_id, matched_pubkey_ids, target_name).await? {
        Ok(fingerprints) => {
            let target = if target_name.is_empty() {
                "unknown"
            } else {
                target_name
            };
            info!(
                username = %username,
                key_fingerprint = %fingerprints.join(","),
                target = %target,
                "SSH sign-in allowed by step-up exemption"
            );
            Ok(StepUpExemption::Applies(fingerprints))
        }
        Err(ignored) => {
            warn!(
                username = %username,
                "step-up exemption ignored: {}",
                ignored.reason()
            );
            Ok(StepUpExemption::Ignored(ignored))
        }
    }
}

/// The sign-in key fingerprints when the exemption applies, otherwise why not.
async fn listed_user_outcome(
    db: &DatabaseConnection,
    entries: &[&StepUpExemptUser],
    user_id: Uuid,
    matched_pubkey_ids: &[Uuid],
    target_name: &str,
) -> Result<Result<Vec<String>, StepUpExemptionIgnored>, WarpgateError> {
    let (has_sso, has_password) = sso_and_password_credentials(db, user_id).await?;
    if has_sso {
        return Ok(Err(StepUpExemptionIgnored::HasSsoCredential));
    }
    if has_password {
        return Ok(Err(StepUpExemptionIgnored::HasPasswordCredential));
    }

    let Some(fingerprints) = matched_key_fingerprints(db, user_id, matched_pubkey_ids).await?
    else {
        return Ok(Err(StepUpExemptionIgnored::KeyNotListed));
    };
    if !entries
        .iter()
        .any(|entry| entry_covers_keys(entry, &fingerprints))
    {
        return Ok(Err(StepUpExemptionIgnored::KeyNotListed));
    }
    if entries.iter().any(|entry| {
        entry_covers_keys(entry, &fingerprints) && entry_covers_target(entry, target_name)
    }) {
        Ok(Ok(fingerprints))
    } else {
        Ok(Err(StepUpExemptionIgnored::TargetNotListed))
    }
}

/// Whether the user has an SSO credential and whether it has a password
/// credential (the two kinds that make an `exempt_users` entry not apply).
async fn sso_and_password_credentials(
    db: &DatabaseConnection,
    user_id: Uuid,
) -> Result<(bool, bool), WarpgateError> {
    let has_sso = entities::SsoCredential::Entity::find()
        .filter(entities::SsoCredential::Column::UserId.eq(user_id))
        .one(db)
        .await?
        .is_some();
    let has_password = entities::PasswordCredential::Entity::find()
        .filter(entities::PasswordCredential::Column::UserId.eq(user_id))
        .one(db)
        .await?
        .is_some();
    Ok((has_sso, has_password))
}

/// What changed in the database under a connection admitted through
/// `exempt_users`, so that the grant it was admitted on no longer holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExemptCredentialChange {
    /// The user now has an SSO credential.
    SsoCredentialAdded,
    /// The user now has a password credential.
    PasswordCredentialAdded,
    /// A key the connection signed in with was deleted, replaced by another
    /// key, or no longer shows the fingerprint it was admitted with.
    KeyChanged,
}

impl ExemptCredentialChange {
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::SsoCredentialAdded => "the user gained an SSO credential",
            Self::PasswordCredentialAdded => "the user gained a password credential",
            Self::KeyChanged => "a key the connection signed in with was removed or replaced",
        }
    }
}

/// Re-read from the database what an exemption was granted on: the user has
/// still no SSO or password credential, and the public key rows the sign-in
/// matched still exist, still belong to the user and still show the
/// fingerprints the grant recorded.
///
/// `Ok(None)` means the grant still holds. A database error is returned and
/// is never read as "still holds".
pub async fn exempt_credential_change(
    db: &DatabaseConnection,
    user_id: Uuid,
    pubkey_ids: &[Uuid],
    granted_fingerprints: &[String],
) -> Result<Option<ExemptCredentialChange>, WarpgateError> {
    let (has_sso, has_password) = sso_and_password_credentials(db, user_id).await?;
    if has_sso {
        return Ok(Some(ExemptCredentialChange::SsoCredentialAdded));
    }
    if has_password {
        return Ok(Some(ExemptCredentialChange::PasswordCredentialAdded));
    }
    let current = matched_key_fingerprints(db, user_id, pubkey_ids).await?;
    if current.as_deref() == Some(granted_fingerprints) && !granted_fingerprints.is_empty() {
        Ok(None)
    } else {
        Ok(Some(ExemptCredentialChange::KeyChanged))
    }
}

fn entry_covers_keys(entry: &StepUpExemptUser, fingerprints: &[String]) -> bool {
    fingerprints.iter().all(|fp| entry.keys.contains(fp))
}

fn entry_covers_target(entry: &StepUpExemptUser, target_name: &str) -> bool {
    entry
        .targets
        .as_ref()
        .is_none_or(|targets| targets.iter().any(|t| t == target_name))
}

/// Whether a connection admitted through `exempt_users` is still covered by
/// the live config: step-up is still configured for SSH, and an entry names
/// exactly this user, lists every key it signed in with and (when it has
/// `targets`) the target. Used to end such connections after a config reload.
#[must_use]
pub fn exemption_still_listed(
    step_up: Option<&StepUpIntervalConfig>,
    username: &str,
    fingerprints: &[String],
    target_name: &str,
) -> bool {
    let Some(step_up) = step_up else {
        return false;
    };
    !fingerprints.is_empty()
        && step_up.exempt_entries_for(username).any(|entry| {
            entry_covers_keys(entry, fingerprints) && entry_covers_target(entry, target_name)
        })
}

/// Log one warning for each `exempt_users` entry whose user has an SSO or
/// password credential (such an entry never applies). Meant to run once at
/// startup, when the database is available. A user that does not exist yet is
/// not reported.
pub async fn warn_exempt_users_with_credentials(
    db: &DatabaseConnection,
    step_up: &StepUpIntervalConfig,
) -> Result<usize, WarpgateError> {
    let mut warned = 0;
    let mut seen = std::collections::HashSet::new();
    for entry in &step_up.exempt_users {
        if !seen.insert(entry.user.as_str()) {
            continue;
        }
        let Some(user) = entities::User::Entity::find()
            .filter(entities::User::Column::Username.eq(entry.user.as_str()))
            .one(db)
            .await?
        else {
            continue;
        };
        let (has_sso, has_password) = sso_and_password_credentials(db, user.id).await?;
        if has_sso || has_password {
            warn!(
                username = %entry.user,
                has_sso,
                has_password,
                "step_up_interval.exempt_users lists a user with an SSO or password credential; the entry will not be applied"
            );
            warned += 1;
        }
    }
    Ok(warned)
}

/// The OpenSSH SHA256 fingerprint of each given public key row of the user.
///
/// `None` when there is no row to show a key for: no ids, a row that is gone
/// or belongs to someone else, or a stored key that does not parse.
async fn matched_key_fingerprints(
    db: &DatabaseConnection,
    user_id: Uuid,
    pubkey_ids: &[Uuid],
) -> Result<Option<Vec<String>>, WarpgateError> {
    if pubkey_ids.is_empty() {
        return Ok(None);
    }
    let mut fingerprints = Vec::with_capacity(pubkey_ids.len());
    for pubkey_id in pubkey_ids {
        let Some(row) = entities::PublicKeyCredential::Entity::find_by_id(*pubkey_id)
            .one(db)
            .await?
        else {
            return Ok(None);
        };
        if row.user_id != user_id {
            return Ok(None);
        }
        let Ok(key) = PublicKey::from_openssh(&row.openssh_public_key) else {
            return Ok(None);
        };
        fingerprints.push(key.fingerprint(HashAlg::Sha256).to_string());
    }
    Ok(Some(fingerprints))
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use sea_orm::{ActiveModelTrait, ConnectionTrait, Database};
    use warpgate_db_entities::Parameters::{ConfigMigrationValues, set_config_migration_values};
    use warpgate_db_migrations::migrate_database;

    use super::*;

    fn hours(h: u64) -> Duration {
        Duration::from_secs(h * 3600)
    }

    fn at(base: OffsetDateTime, offset_seconds: i64) -> OffsetDateTime {
        base + time::Duration::seconds(offset_seconds)
    }

    #[test]
    fn unit_is_fresh_none_never_handshaked_is_stale() {
        let now = OffsetDateTime::now_utc();
        assert!(!is_fresh(None, hours(12), now));
    }

    #[test]
    fn unit_is_fresh_recent_stamp_is_fresh() {
        let now = OffsetDateTime::now_utc();
        let last = at(now, -3600); // 1h ago
        assert!(is_fresh(Some(last), hours(12), now));
    }

    #[test]
    fn unit_is_fresh_old_stamp_is_stale() {
        let now = OffsetDateTime::now_utc();
        let last = at(now, -13 * 3600); // 13h ago
        assert!(!is_fresh(Some(last), hours(12), now));
    }

    #[test]
    fn unit_is_fresh_exact_boundary_is_fresh() {
        // At exactly interval ago: still fresh (inclusive boundary).
        let now = OffsetDateTime::now_utc();
        let last = at(now, -12 * 3600);
        assert!(is_fresh(Some(last), hours(12), now));
    }

    #[test]
    fn unit_is_fresh_one_second_past_boundary_is_stale() {
        let now = OffsetDateTime::now_utc();
        let last = at(now, -(12 * 3600 + 1));
        assert!(!is_fresh(Some(last), hours(12), now));
    }

    #[test]
    fn unit_is_fresh_one_ns_past_boundary_is_stale() {
        // Documented behaviour: the boundary is inclusive at `now - interval`
        // (see unit_is_fresh_exact_boundary_is_fresh). One nanosecond older
        // than that is therefore stale - there is no sub-second grace period.
        let now = OffsetDateTime::now_utc();
        let last = now - time::Duration::hours(12) - time::Duration::nanoseconds(1);
        assert!(!is_fresh(Some(last), hours(12), now));
    }

    #[test]
    fn unit_step_up_window_off_is_not_applicable() {
        let now = OffsetDateTime::now_utc();
        assert_eq!(
            step_up_window(Some(at(now, -3600)), None, now),
            StepUpWindow::NotApplicable
        );
        assert_eq!(step_up_window(None, None, now), StepUpWindow::NotApplicable);
    }

    #[test]
    fn unit_step_up_window_is_last_sso_plus_interval() {
        let now = OffsetDateTime::now_utc();
        assert_eq!(
            step_up_window(Some(at(now, -3600)), Some(hours(12)), now),
            StepUpWindow::Remaining(hours(11))
        );
    }

    #[test]
    fn unit_step_up_window_closes_when_the_window_passes() {
        let now = OffsetDateTime::now_utc();
        assert_eq!(
            step_up_window(Some(at(now, -(12 * 3600 + 1))), Some(hours(12)), now),
            StepUpWindow::Expired
        );
        assert_eq!(
            step_up_window(Some(at(now, -12 * 3600)), Some(hours(12)), now),
            StepUpWindow::Remaining(Duration::ZERO)
        );
    }

    #[test]
    fn unit_step_up_window_never_stamped_is_expired() {
        let now = OffsetDateTime::now_utc();
        assert_eq!(
            step_up_window(None, Some(hours(12)), now),
            StepUpWindow::Expired
        );
    }

    #[test]
    fn unit_step_up_window_follows_an_interval_change() {
        let now = OffsetDateTime::now_utc();
        let last = Some(at(now, -2 * 3600));
        assert_eq!(
            step_up_window(last, Some(hours(12)), now),
            StepUpWindow::Remaining(hours(10))
        );
        // Shorter interval: the same connection is now past its window.
        assert_eq!(
            step_up_window(last, Some(hours(1)), now),
            StepUpWindow::Expired
        );
        // Longer interval extends it; removing it cancels the limit.
        assert_eq!(
            step_up_window(last, Some(hours(24)), now),
            StepUpWindow::Remaining(hours(22))
        );
        assert_eq!(step_up_window(last, None, now), StepUpWindow::NotApplicable);
    }

    #[test]
    fn unit_step_up_window_fresh_sso_extends_the_deadline() {
        let now = OffsetDateTime::now_utc();
        let old = Some(at(now, -(11 * 3600 + 3000)));
        let refreshed = Some(now);
        assert_eq!(
            step_up_window(old, Some(hours(12)), now),
            StepUpWindow::Remaining(Duration::from_secs(600))
        );
        assert_eq!(
            step_up_window(refreshed, Some(hours(12)), now),
            StepUpWindow::Remaining(hours(12))
        );
    }

    #[test]
    fn unit_is_fresh_clock_skew_future_stamp_is_fresh() {
        // Defensive: if the stored stamp somehow lies in the future (clock
        // skew, timezone corruption), don't force an extra SSO prompt.
        // now - last is negative, which is <= interval_td -> fresh.
        let now = OffsetDateTime::now_utc();
        let last = at(now, 60); // 1 min in the future
        assert!(is_fresh(Some(last), hours(12), now));
    }

    async fn setup_db() -> DatabaseConnection {
        set_config_migration_values(ConfigMigrationValues::default());
        let conn = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&conn).await.unwrap();
        conn
    }

    async fn insert_user_and_pubkey(db: &DatabaseConnection) -> Uuid {
        let user_id = Uuid::new_v4();
        entities::User::ActiveModel {
            id: Set(user_id),
            username: Set("alice".into()),
            description: Set(String::new()),
            credential_policy: Set(serde_json::json!({})),
            rate_limit_bytes_per_second: Set(None),
            ldap_server_id: Set(None),
            ldap_object_uuid: Set(None),
            allowed_ip_ranges: Set(serde_json::Value::Null),
        }
        .insert(db)
        .await
        .unwrap();

        let pubkey_id = Uuid::new_v4();
        entities::PublicKeyCredential::ActiveModel {
            id: Set(pubkey_id),
            user_id: Set(user_id),
            label: Set("test".into()),
            date_added: Set(None),
            last_used: Set(None),
            last_sso_at: Set(None),
            openssh_public_key: Set("ssh-ed25519 AAAA".into()),
        }
        .insert(db)
        .await
        .unwrap();

        pubkey_id
    }

    #[tokio::test]
    async fn unit_get_pubkey_last_sso_at_returns_none_when_never_stamped() {
        let db = setup_db().await;
        let pubkey_id = insert_user_and_pubkey(&db).await;

        let got = get_pubkey_last_sso_at(&db, pubkey_id).await.unwrap();
        assert_eq!(got, None);
    }

    #[tokio::test]
    async fn unit_get_pubkey_last_sso_at_returns_none_for_missing_row() {
        let db = setup_db().await;
        let missing = Uuid::new_v4();

        let got = get_pubkey_last_sso_at(&db, missing).await.unwrap();
        assert_eq!(got, None);
    }

    #[tokio::test]
    async fn unit_update_pubkey_last_sso_at_roundtrip() {
        let db = setup_db().await;
        let pubkey_id = insert_user_and_pubkey(&db).await;

        let now = OffsetDateTime::now_utc();
        let rows_affected = update_pubkey_last_sso_at(&db, pubkey_id, now)
            .await
            .unwrap();
        assert_eq!(rows_affected, 1, "expected exactly one row updated");

        let got = get_pubkey_last_sso_at(&db, pubkey_id).await.unwrap();

        // Sub-second precision can get truncated by SQLite; compare at
        // whole-second granularity.
        let got = got.expect("expected Some(ts)");
        assert_eq!(got.unix_timestamp(), now.unix_timestamp());
    }

    #[tokio::test]
    async fn unit_update_pubkey_last_sso_at_missing_row_returns_zero() {
        // Defensive: row may have been deleted between validate and stamp.
        // The atomic UPDATE simply matches nothing - rows_affected == 0 and
        // we don't error, so the auth flow doesn't fail hard on a race.
        let db = setup_db().await;
        let missing = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();

        let rows_affected = update_pubkey_last_sso_at(&db, missing, now).await.unwrap();
        assert_eq!(rows_affected, 0);
    }

    // --- `step_up_interval.exempt_users` -----------------------------------

    const KEY_A: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPu/YbG0OTn/9QBTFDjJBQQhHk5XIRPXKYWNHm21np1q";
    const FP_A: &str = "SHA256:dCsd+OZuerpGdJl7d6JN1z8Qe4jKnWrhUHtPhQ2Ghtg";
    const KEY_B: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINlugWu1+DBB3PR2myFjhALc5Jug2vLAzEBjnb0SUe9o";
    const FP_B: &str = "SHA256:AhPclk0CCWxTYKmTC3eRTLDlONSTMyVg6sOgAoV+Kwc";

    /// A service user that has no credentials yet; the name is unique per
    /// test so log lines can be told apart in the shared capture.
    async fn service_user(db: &DatabaseConnection) -> (Uuid, String) {
        let user_id = Uuid::new_v4();
        let username = format!("qa-{user_id}");
        entities::User::ActiveModel {
            id: Set(user_id),
            username: Set(username.clone()),
            description: Set(String::new()),
            credential_policy: Set(serde_json::json!({})),
            rate_limit_bytes_per_second: Set(None),
            ldap_server_id: Set(None),
            ldap_object_uuid: Set(None),
            allowed_ip_ranges: Set(serde_json::Value::Null),
        }
        .insert(db)
        .await
        .unwrap();
        (user_id, username)
    }

    async fn add_key(db: &DatabaseConnection, user_id: Uuid, openssh: &str) -> Uuid {
        let id = Uuid::new_v4();
        entities::PublicKeyCredential::ActiveModel {
            id: Set(id),
            user_id: Set(user_id),
            label: Set("test".into()),
            date_added: Set(None),
            last_used: Set(None),
            last_sso_at: Set(None),
            openssh_public_key: Set(openssh.into()),
        }
        .insert(db)
        .await
        .unwrap();
        id
    }

    async fn add_password(db: &DatabaseConnection, user_id: Uuid) {
        entities::PasswordCredential::ActiveModel {
            id: Set(Uuid::new_v4()),
            user_id: Set(user_id),
            argon_hash: Set("not-a-real-hash".into()),
        }
        .insert(db)
        .await
        .unwrap();
    }

    async fn add_sso(db: &DatabaseConnection, user_id: Uuid) {
        entities::SsoCredential::ActiveModel {
            id: Set(Uuid::new_v4()),
            user_id: Set(user_id),
            provider: Set(None),
            email: Set("qa@example.com".into()),
        }
        .insert(db)
        .await
        .unwrap();
    }

    fn applies(fingerprints: &[&str]) -> StepUpExemption {
        StepUpExemption::Applies(fingerprints.iter().map(|f| (*f).to_owned()).collect())
    }

    fn exempt_entry(user: &str, keys: &[&str], targets: Option<&[&str]>) -> StepUpExemptUser {
        StepUpExemptUser {
            user: user.into(),
            keys: keys.iter().map(|k| (*k).to_owned()).collect(),
            targets: targets.map(|t| t.iter().map(|t| (*t).to_owned()).collect()),
        }
    }

    fn exempt_config(entries: Vec<StepUpExemptUser>) -> StepUpIntervalConfig {
        StepUpIntervalConfig {
            ssh: Some(hours(12)),
            exempt_users: entries,
            ..Default::default()
        }
    }

    /// Log lines this test binary captured for one username.
    fn logged_for(username: &str) -> Vec<std::collections::HashMap<&'static str, String>> {
        crate::approvals::tests::audit_events()
            .lock()
            .unwrap()
            .iter()
            .filter(|values| values.get("username").map(String::as_str) == Some(username))
            .cloned()
            .collect()
    }

    fn message_of<'a>(values: &'a std::collections::HashMap<&'static str, String>) -> &'a str {
        values.get("message").map_or("", String::as_str)
    }

    #[tokio::test]
    async fn unit_exempt_user_with_only_a_listed_key_passes_and_is_logged() {
        let db = setup_db().await;
        let (user_id, username) = service_user(&db).await;
        let key = add_key(&db, user_id, KEY_A).await;
        let config = exempt_config(vec![exempt_entry(&username, &[FP_A], None)]);
        crate::approvals::tests::audit_events();

        let got = ssh_step_up_exemption(&db, &config, user_id, &username, &[key], "prod")
            .await
            .unwrap();

        assert_eq!(got, applies(&[FP_A]));
        assert!(got.applies());
        let logged = logged_for(&username);
        assert_eq!(logged.len(), 1, "exactly one line: {logged:?}");
        assert!(
            message_of(&logged[0]).contains("step-up exemption"),
            "{logged:?}"
        );
        assert_eq!(
            logged[0].get("key_fingerprint").map(String::as_str),
            Some(FP_A)
        );
        assert_eq!(logged[0].get("target").map(String::as_str), Some("prod"));
    }

    #[tokio::test]
    async fn unit_exempt_user_with_a_password_credential_is_not_exempt() {
        let db = setup_db().await;
        let (user_id, username) = service_user(&db).await;
        let key = add_key(&db, user_id, KEY_A).await;
        add_password(&db, user_id).await;
        let config = exempt_config(vec![exempt_entry(&username, &[FP_A], None)]);
        crate::approvals::tests::audit_events();

        let got = ssh_step_up_exemption(&db, &config, user_id, &username, &[key], "prod")
            .await
            .unwrap();

        assert_eq!(
            got,
            StepUpExemption::Ignored(StepUpExemptionIgnored::HasPasswordCredential)
        );
        let logged = logged_for(&username);
        assert_eq!(logged.len(), 1, "exactly one line: {logged:?}");
        assert!(
            message_of(&logged[0]).contains("step-up exemption ignored")
                && message_of(&logged[0]).contains("password credential"),
            "{logged:?}"
        );
    }

    #[tokio::test]
    async fn unit_exempt_user_with_an_sso_credential_is_not_exempt() {
        let db = setup_db().await;
        let (user_id, username) = service_user(&db).await;
        let key = add_key(&db, user_id, KEY_A).await;
        add_sso(&db, user_id).await;
        let config = exempt_config(vec![exempt_entry(&username, &[FP_A], None)]);
        crate::approvals::tests::audit_events();

        let got = ssh_step_up_exemption(&db, &config, user_id, &username, &[key], "prod")
            .await
            .unwrap();

        assert_eq!(
            got,
            StepUpExemption::Ignored(StepUpExemptionIgnored::HasSsoCredential)
        );
        let logged = logged_for(&username);
        assert_eq!(logged.len(), 1, "exactly one line: {logged:?}");
        assert!(
            message_of(&logged[0]).contains("step-up exemption ignored")
                && message_of(&logged[0]).contains("SSO credential"),
            "{logged:?}"
        );
    }

    #[tokio::test]
    async fn unit_user_not_on_the_list_is_not_exempt_and_nothing_is_logged() {
        let db = setup_db().await;
        let (user_id, username) = service_user(&db).await;
        let key = add_key(&db, user_id, KEY_A).await;
        let config = exempt_config(vec![exempt_entry("someone-else", &[FP_A], None)]);
        crate::approvals::tests::audit_events();

        let got = ssh_step_up_exemption(&db, &config, user_id, &username, &[key], "prod")
            .await
            .unwrap();
        assert_eq!(got, StepUpExemption::NotListed);
        assert!(logged_for(&username).is_empty());

        // Off by default: an empty list exempts nobody.
        let got = ssh_step_up_exemption(
            &db,
            &exempt_config(vec![]),
            user_id,
            &username,
            &[key],
            "prod",
        )
        .await
        .unwrap();
        assert_eq!(got, StepUpExemption::NotListed);
    }

    #[tokio::test]
    async fn unit_username_must_match_exactly() {
        let db = setup_db().await;
        let (user_id, username) = service_user(&db).await;
        let key = add_key(&db, user_id, KEY_A).await;
        for listed in [
            username.to_uppercase(),
            format!("{username} "),
            format!("{username}2"),
        ] {
            let config = exempt_config(vec![exempt_entry(&listed, &[FP_A], None)]);
            let got = ssh_step_up_exemption(&db, &config, user_id, &username, &[key], "prod")
                .await
                .unwrap();
            assert_eq!(got, StepUpExemption::NotListed, "listed as {listed:?}");
        }
    }

    #[tokio::test]
    async fn unit_a_key_that_is_not_listed_is_not_exempt() {
        let db = setup_db().await;
        let (user_id, username) = service_user(&db).await;
        let listed = add_key(&db, user_id, KEY_A).await;
        let config = exempt_config(vec![exempt_entry(&username, &[FP_A], None)]);

        // Signing in with a key the entry does not list.
        let other = add_key(&db, user_id, KEY_B).await;
        let got = ssh_step_up_exemption(&db, &config, user_id, &username, &[other], "prod")
            .await
            .unwrap();
        assert_eq!(
            got,
            StepUpExemption::Ignored(StepUpExemptionIgnored::KeyNotListed)
        );

        // A key added after the entry was written is covered by nothing, even
        // when it signs in next to the listed one.
        let got = ssh_step_up_exemption(&db, &config, user_id, &username, &[listed, other], "prod")
            .await
            .unwrap();
        assert_eq!(
            got,
            StepUpExemption::Ignored(StepUpExemptionIgnored::KeyNotListed)
        );

        // The listed one alone still passes.
        let got = ssh_step_up_exemption(&db, &config, user_id, &username, &[listed], "prod")
            .await
            .unwrap();
        assert_eq!(got, applies(&[FP_A]));
    }

    #[tokio::test]
    async fn unit_replacing_a_listed_key_with_another_stops_the_exemption() {
        // The admin endpoints rewrite a key row in place, keeping its id.
        let db = setup_db().await;
        let (user_id, username) = service_user(&db).await;
        let key = add_key(&db, user_id, KEY_A).await;
        let config = exempt_config(vec![exempt_entry(&username, &[FP_A], None)]);
        entities::PublicKeyCredential::Entity::update_many()
            .set(entities::PublicKeyCredential::ActiveModel {
                openssh_public_key: Set(KEY_B.into()),
                ..Default::default()
            })
            .filter(entities::PublicKeyCredential::Column::Id.eq(key))
            .exec(&db)
            .await
            .unwrap();

        let got = ssh_step_up_exemption(&db, &config, user_id, &username, &[key], "prod")
            .await
            .unwrap();
        assert_eq!(
            got,
            StepUpExemption::Ignored(StepUpExemptionIgnored::KeyNotListed)
        );
    }

    #[tokio::test]
    async fn unit_no_matched_key_or_an_unreadable_one_is_not_exempt() {
        let db = setup_db().await;
        let (user_id, username) = service_user(&db).await;
        let config = exempt_config(vec![exempt_entry(&username, &[FP_A], None)]);
        let ignored = StepUpExemption::Ignored(StepUpExemptionIgnored::KeyNotListed);

        let got = ssh_step_up_exemption(&db, &config, user_id, &username, &[], "prod")
            .await
            .unwrap();
        assert_eq!(got, ignored, "no matched key row");

        let got =
            ssh_step_up_exemption(&db, &config, user_id, &username, &[Uuid::new_v4()], "prod")
                .await
                .unwrap();
        assert_eq!(got, ignored, "key row that is gone");

        let garbled = add_key(&db, user_id, "ssh-ed25519 AAAA").await;
        let got = ssh_step_up_exemption(&db, &config, user_id, &username, &[garbled], "prod")
            .await
            .unwrap();
        assert_eq!(got, ignored, "stored key that does not parse");

        // Someone else's key row is not this user's key.
        let (other_user, _) = service_user(&db).await;
        let theirs = add_key(&db, other_user, KEY_A).await;
        let got = ssh_step_up_exemption(&db, &config, user_id, &username, &[theirs], "prod")
            .await
            .unwrap();
        assert_eq!(got, ignored, "key row of another user");
    }

    #[tokio::test]
    async fn unit_targets_limit_where_the_exemption_applies() {
        let db = setup_db().await;
        let (user_id, username) = service_user(&db).await;
        let key = add_key(&db, user_id, KEY_A).await;
        let config = exempt_config(vec![exempt_entry(
            &username,
            &[FP_A],
            Some(&["staging", "build-1"]),
        )]);
        let check = |target: &'static str| {
            let (db, config, username) = (&db, &config, &username);
            async move {
                ssh_step_up_exemption(db, config, user_id, username, &[key], target)
                    .await
                    .unwrap()
            }
        };

        assert_eq!(check("staging").await, applies(&[FP_A]));
        assert_eq!(check("build-1").await, applies(&[FP_A]));
        let refused = StepUpExemption::Ignored(StepUpExemptionIgnored::TargetNotListed);
        assert_eq!(check("prod").await, refused);
        assert_eq!(check("Staging").await, refused, "names are exact");
        assert_eq!(check("staging2").await, refused);
        assert_eq!(check("").await, refused, "no target chosen yet");
    }

    #[tokio::test]
    async fn unit_without_targets_every_target_is_covered() {
        let db = setup_db().await;
        let (user_id, username) = service_user(&db).await;
        let key = add_key(&db, user_id, KEY_A).await;
        let config = exempt_config(vec![exempt_entry(&username, &[FP_A], None)]);
        for target in ["prod", "staging", ""] {
            let got = ssh_step_up_exemption(&db, &config, user_id, &username, &[key], target)
                .await
                .unwrap();
            assert_eq!(got, applies(&[FP_A]), "target {target:?}");
        }
    }

    #[tokio::test]
    async fn unit_applies_returns_the_fingerprints_of_every_matched_key_in_order() {
        let db = setup_db().await;
        let (user_id, username) = service_user(&db).await;
        let key_a = add_key(&db, user_id, KEY_A).await;
        let key_b = add_key(&db, user_id, KEY_B).await;
        let config = exempt_config(vec![exempt_entry(&username, &[FP_A, FP_B], None)]);

        let got = ssh_step_up_exemption(&db, &config, user_id, &username, &[key_b, key_a], "prod")
            .await
            .unwrap();
        assert_eq!(got, applies(&[FP_B, FP_A]));
    }

    #[tokio::test]
    async fn unit_two_entries_for_one_user_apply_on_their_own() {
        let db = setup_db().await;
        let (user_id, username) = service_user(&db).await;
        let key_a = add_key(&db, user_id, KEY_A).await;
        let key_b = add_key(&db, user_id, KEY_B).await;
        let config = exempt_config(vec![
            exempt_entry(&username, &[FP_A], Some(&["staging"])),
            exempt_entry(&username, &[FP_B], None),
        ]);
        let run = |key: Uuid, target: &'static str| {
            let (db, config, username) = (&db, &config, &username);
            async move {
                ssh_step_up_exemption(db, config, user_id, username, &[key], target)
                    .await
                    .unwrap()
            }
        };

        assert_eq!(run(key_a, "staging").await, applies(&[FP_A]));
        assert_eq!(run(key_b, "prod").await, applies(&[FP_B]));
        assert_eq!(
            run(key_a, "prod").await,
            StepUpExemption::Ignored(StepUpExemptionIgnored::TargetNotListed)
        );
    }

    #[tokio::test]
    async fn unit_a_database_error_is_an_error_not_an_exemption() {
        let db = setup_db().await;
        let (user_id, username) = service_user(&db).await;
        let key = add_key(&db, user_id, KEY_A).await;
        let config = exempt_config(vec![exempt_entry(&username, &[FP_A], None)]);
        db.execute_unprepared("DROP TABLE credentials_sso")
            .await
            .unwrap();

        let got = ssh_step_up_exemption(&db, &config, user_id, &username, &[key], "prod").await;
        assert!(got.is_err(), "{got:?}");
    }

    #[tokio::test]
    async fn unit_credential_change_none_while_the_grant_still_holds() {
        let db = setup_db().await;
        let (user_id, _) = service_user(&db).await;
        let key = add_key(&db, user_id, KEY_A).await;
        let fps = vec![FP_A.to_owned()];

        let got = exempt_credential_change(&db, user_id, &[key], &fps)
            .await
            .unwrap();
        assert_eq!(got, None);

        // A key added to the user later is not this sign-in's key.
        add_key(&db, user_id, KEY_B).await;
        let got = exempt_credential_change(&db, user_id, &[key], &fps)
            .await
            .unwrap();
        assert_eq!(got, None);
    }

    #[tokio::test]
    async fn unit_credential_change_deleting_the_key_row() {
        let db = setup_db().await;
        let (user_id, _) = service_user(&db).await;
        let key = add_key(&db, user_id, KEY_A).await;
        entities::PublicKeyCredential::Entity::delete_by_id(key)
            .exec(&db)
            .await
            .unwrap();

        let got = exempt_credential_change(&db, user_id, &[key], &[FP_A.to_owned()])
            .await
            .unwrap();
        assert_eq!(got, Some(ExemptCredentialChange::KeyChanged));
    }

    #[tokio::test]
    async fn unit_credential_change_replacing_the_key() {
        let db = setup_db().await;
        let (user_id, _) = service_user(&db).await;
        let key = add_key(&db, user_id, KEY_A).await;
        let fps = vec![FP_A.to_owned()];

        // Rewritten in place, keeping its id (what the admin endpoints do).
        entities::PublicKeyCredential::Entity::update_many()
            .set(entities::PublicKeyCredential::ActiveModel {
                openssh_public_key: Set(KEY_B.into()),
                ..Default::default()
            })
            .filter(entities::PublicKeyCredential::Column::Id.eq(key))
            .exec(&db)
            .await
            .unwrap();
        let got = exempt_credential_change(&db, user_id, &[key], &fps)
            .await
            .unwrap();
        assert_eq!(got, Some(ExemptCredentialChange::KeyChanged));

        // A row that now belongs to someone else, or no longer parses.
        let (other_user, _) = service_user(&db).await;
        let theirs = add_key(&db, other_user, KEY_A).await;
        let got = exempt_credential_change(&db, user_id, &[theirs], &fps)
            .await
            .unwrap();
        assert_eq!(got, Some(ExemptCredentialChange::KeyChanged));
        let garbled = add_key(&db, user_id, "ssh-ed25519 AAAA").await;
        let got = exempt_credential_change(&db, user_id, &[garbled], &fps)
            .await
            .unwrap();
        assert_eq!(got, Some(ExemptCredentialChange::KeyChanged));
    }

    #[tokio::test]
    async fn unit_credential_change_nothing_recorded_never_holds() {
        let db = setup_db().await;
        let (user_id, _) = service_user(&db).await;
        let key = add_key(&db, user_id, KEY_A).await;

        for (ids, fps) in [(vec![], vec![]), (vec![key], vec![])] {
            let got = exempt_credential_change(&db, user_id, &ids, &fps)
                .await
                .unwrap();
            assert_eq!(got, Some(ExemptCredentialChange::KeyChanged));
        }
    }

    #[tokio::test]
    async fn unit_credential_change_password_or_sso_added() {
        let db = setup_db().await;
        let (pw, _) = service_user(&db).await;
        let pw_key = add_key(&db, pw, KEY_A).await;
        let (sso, _) = service_user(&db).await;
        let sso_key = add_key(&db, sso, KEY_A).await;
        let fps = vec![FP_A.to_owned()];
        assert_eq!(
            exempt_credential_change(&db, pw, &[pw_key], &fps)
                .await
                .unwrap(),
            None
        );

        add_password(&db, pw).await;
        add_sso(&db, sso).await;

        assert_eq!(
            exempt_credential_change(&db, pw, &[pw_key], &fps)
                .await
                .unwrap(),
            Some(ExemptCredentialChange::PasswordCredentialAdded)
        );
        assert_eq!(
            exempt_credential_change(&db, sso, &[sso_key], &fps)
                .await
                .unwrap(),
            Some(ExemptCredentialChange::SsoCredentialAdded)
        );
    }

    #[tokio::test]
    async fn unit_credential_change_a_database_error_is_an_error() {
        let db = setup_db().await;
        let (user_id, _) = service_user(&db).await;
        let key = add_key(&db, user_id, KEY_A).await;
        db.execute_unprepared("DROP TABLE credentials_public_key")
            .await
            .unwrap();
        let got = exempt_credential_change(&db, user_id, &[key], &[FP_A.to_owned()]).await;
        assert!(got.is_err(), "{got:?}");
    }

    #[test]
    fn unit_exemption_still_listed_follows_the_live_config() {
        let fps = vec![FP_A.to_owned()];
        let cfg = exempt_config(vec![exempt_entry("qa", &[FP_A], Some(&["staging"]))]);
        assert!(exemption_still_listed(Some(&cfg), "qa", &fps, "staging"));
        // user removed or renamed
        assert!(!exemption_still_listed(Some(&cfg), "qa2", &fps, "staging"));
        assert!(!exemption_still_listed(
            Some(&exempt_config(vec![])),
            "qa",
            &fps,
            "staging"
        ));
        // key no longer listed, or one more key in use than is listed
        let other = exempt_config(vec![exempt_entry("qa", &[FP_B], Some(&["staging"]))]);
        assert!(!exemption_still_listed(Some(&other), "qa", &fps, "staging"));
        let both = vec![FP_A.to_owned(), FP_B.to_owned()];
        assert!(!exemption_still_listed(Some(&cfg), "qa", &both, "staging"));
        // target no longer listed
        assert!(!exemption_still_listed(Some(&cfg), "qa", &fps, "prod"));
        // step-up config gone, or no key recorded
        assert!(!exemption_still_listed(None, "qa", &fps, "staging"));
        assert!(!exemption_still_listed(Some(&cfg), "qa", &[], "staging"));
    }

    #[tokio::test]
    async fn unit_startup_check_reports_listed_users_with_sso_or_password() {
        let db = setup_db().await;
        let (clean, clean_name) = service_user(&db).await;
        add_key(&db, clean, KEY_A).await;
        let (pw, pw_name) = service_user(&db).await;
        add_password(&db, pw).await;
        let (sso, sso_name) = service_user(&db).await;
        add_sso(&db, sso).await;
        let (_unlisted, _) = service_user(&db).await;
        let config = exempt_config(vec![
            exempt_entry(&clean_name, &[FP_A], None),
            exempt_entry(&pw_name, &[FP_A], None),
            exempt_entry(&sso_name, &[FP_A], None),
            exempt_entry("no-such-user", &[FP_A], None),
        ]);
        assert_eq!(
            warn_exempt_users_with_credentials(&db, &config)
                .await
                .unwrap(),
            2
        );
        assert_eq!(
            warn_exempt_users_with_credentials(&db, &exempt_config(vec![]))
                .await
                .unwrap(),
            0
        );
    }
}
