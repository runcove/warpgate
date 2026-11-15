//! HTTP per-session step-up SSO freshness gate.
//!
//! Stage "A2 — HTTP per-session step-up auth" of the periodic step-up SSO
//! re-auth design (A1 SSH pubkey, A2 HTTP session, A3 Kubernetes cert).
//!
//! After a successful HTTP auth, check when the current Poem session last did
//! an SSO handshake. If stale (older than `step_up_interval.http` or never),
//! log the browser session out and force fresh SSO before serving
//! authenticated pages. On successful SSO completion, the SSO return handler stamps
//! `last_sso_at` on the session.
//!
//! Scope (strict): User sessions only. Ticket auth / anonymous / admin-token
//! / user-token paths pass through untouched (step-up is SSO-gated, and those
//! paths have no SSO semantics).
//!
//! # Exempt-path invariant (critical)
//!
//! This gate only fires for routes wrapped in [`crate::common::page_auth`] or
//! [`crate::common::endpoint_auth`]. A set of routes MUST NOT be wrapped,
//! else a step-up clear-auth → redirect to login loops indefinitely (the
//! login flow itself would be re-auth-gated and clear its own session before
//! it can complete):
//!
//!   - `/@warpgate/api/sso/*` — SSO redirect start + IdP return callback
//!     (`api::sso_provider_detail`, `api::sso_provider_list`).
//!   - `/@warpgate/api/auth/*` — password / OTP login + logout
//!     (`api::auth::login`, `api::auth::otpLogin`, `api::auth::logout`).
//!   - `/@warpgate/api/info` — unauthenticated version / branding probe
//!     used by the login SPA before a session exists (`api::info::get_info`).
//!   - `/@warpgate/assets/*` — embedded JS / CSS / HTML static assets for
//!     the gateway + admin SPAs.
//!   - `/@warpgate` and `/@warpgate/` — gateway SPA shell
//!     (`src/gateway/index.html`, served as a plain embedded file).
//!   - `/@warpgate/api/playground`, `/@warpgate/api/openapi.json` — OpenAPI
//!     UI + spec.
//!
//! Route registration lives in the crate root (`at_warpgate_endpoints` in
//! `lib.rs`). If
//! you add an SSO, auth, info, or static-asset route there, do NOT attach
//! `page_auth` or `endpoint_auth` to it, and do not nest it under a parent
//! that wraps it. The intended wrapped surface is user-facing authenticated
//! content only: `/@warpgate/admin` (page), `/@warpgate/admin/api` (XHR),
//! the web-auth-requests SSE stream, and the catchall `/` target-proxy
//! route.
use std::time::Duration;

use poem::session::Session;
use sea_orm::ConnectionTrait;
use time::OffsetDateTime;
use warpgate_common::WarpgateError;
use warpgate_common_http::SessionAuthorization;
use warpgate_core::auth::step_up::is_fresh;
use warpgate_db_entities::HttpSsoStamp;

use crate::common::SessionExt;

/// Session claim key under which we persist the last SSO handshake timestamp
/// for the HTTP surface. Stored as `i64` unix seconds to sidestep
/// serialization of `OffsetDateTime` through Poem's session encoder (which
/// serializes claims via serde_json; plain integers round-trip cleanly across
/// cookie + memory storage backends without timezone / format concerns).
pub const LAST_SSO_AT_SESSION_KEY: &str = "last_sso_at";

/// Convenience accessors for the HTTP step-up clock on a Poem session.
pub trait StepUpSessionExt {
    /// Read the stamped `last_sso_at` off the session, if present and
    /// parseable as a valid `OffsetDateTime`.
    fn get_last_sso_at(&self) -> Option<OffsetDateTime>;

    /// Stamp `last_sso_at` on the session to `now`. Called from the SSO
    /// return handler after `authorize_session`.
    fn set_last_sso_at(&self, now: OffsetDateTime);

    /// Clear the stamp. Used when forcing re-SSO so the new login starts
    /// from a clean slate.
    fn clear_last_sso_at(&self);
}

impl StepUpSessionExt for Session {
    fn get_last_sso_at(&self) -> Option<OffsetDateTime> {
        let secs: i64 = self.get(LAST_SSO_AT_SESSION_KEY)?;
        OffsetDateTime::from_unix_timestamp(secs).ok()
    }

    fn set_last_sso_at(&self, now: OffsetDateTime) {
        self.set(LAST_SSO_AT_SESSION_KEY, now.unix_timestamp());
    }

    fn clear_last_sso_at(&self) {
        self.remove(LAST_SSO_AT_SESSION_KEY);
    }
}

/// Stamps a completed SSO sign-in at `now` on the browser session, and raises
/// its user session's shared stamp ([`HttpSsoStamp`]) to the same second: a
/// target-host session of that user session carrying an earlier stamp is
/// then refused ([`is_superseded`]). The SSO return's only way to stamp.
pub(crate) async fn stamp_sso<C: ConnectionTrait>(
    session: &Session,
    db: &C,
    now: OffsetDateTime,
) -> Result<(), WarpgateError> {
    // The session keeps whole seconds; the shared stamp must compare equal.
    let now = OffsetDateTime::from_unix_timestamp(now.unix_timestamp()).unwrap_or(now);
    session.set_last_sso_at(now);
    raise_shared_stamp(session, db, Some(now)).await
}

/// Raises the shared stamp of `session`'s user session to `stamp`, if both
/// are known; a later shared stamp stays.
pub(crate) async fn raise_shared_stamp<C: ConnectionTrait>(
    session: &Session,
    db: &C,
    stamp: Option<OffsetDateTime>,
) -> Result<(), WarpgateError> {
    match (session.get_session_id(), stamp) {
        (Some(id), Some(stamp)) => HttpSsoStamp::raise(db, id.0, stamp).await,
        _ => Ok(()),
    }
}

/// Whether this target-host session's sign-in was superseded: its user
/// session signed in again by SSO (a step-up) after the sign-in the session
/// carries, or carries none while the user session has one. Such a session
/// never counts again. A session with no user session, or a user session
/// with no recorded SSO sign-in, is not superseded.
pub(crate) async fn is_superseded<C: ConnectionTrait>(
    session: &Session,
    db: &C,
) -> Result<bool, WarpgateError> {
    let Some(id) = session.get_session_id() else {
        return Ok(false);
    };
    let Some(latest) = HttpSsoStamp::latest(db, id.0).await? else {
        return Ok(false);
    };
    Ok(session
        .get_last_sso_at()
        .is_none_or(|carried| carried < latest))
}

/// Pure freshness decision for an HTTP session.
///
/// Returns `true` iff this request should be forced through a fresh SSO
/// handshake before serving content:
///
/// - `interval.is_none()` → feature disabled for HTTP → never stale.
/// - `auth` is not `SessionAuthorization::User` (anonymous, ticket) → pass
///   through; step-up does not apply (tickets have their own TTL and
///   lifecycle; anonymous has no auth to refresh).
/// - User session with fresh stamp within `interval` → not stale.
/// - User session with stale or missing stamp → stale, force re-SSO.
///
/// Delegates the freshness math to [`warpgate_core::auth::step_up::is_fresh`]
/// so that SSH (A1) and HTTP (A2) share a single boundary semantics (inclusive
/// at `now - interval`, future stamps treated as fresh for clock-skew
/// resilience).
#[must_use]
pub fn is_session_step_up_stale(
    auth: Option<&SessionAuthorization>,
    last_sso_at: Option<OffsetDateTime>,
    interval: Option<Duration>,
    now: OffsetDateTime,
) -> bool {
    let Some(interval) = interval else {
        return false;
    };
    match auth {
        Some(SessionAuthorization::User { .. }) => !is_fresh(last_sso_at, interval, now),
        Some(SessionAuthorization::Ticket { .. }) | None => false,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use time::OffsetDateTime;
    use uuid::Uuid;
    use warpgate_common_http::SessionAuthorization;

    use super::is_session_step_up_stale;

    fn user_auth() -> SessionAuthorization {
        SessionAuthorization::User {
            user_id: Uuid::nil(),
            username: "alice".into(),
        }
    }

    fn ticket_auth() -> SessionAuthorization {
        SessionAuthorization::Ticket {
            user_id: Uuid::nil(),
            username: "alice".into(),
            target_id: Uuid::nil(),
            ticket_id: None,
        }
    }

    fn now() -> OffsetDateTime {
        // Arbitrary fixed instant so tests don't drift with wall clock.
        OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap()
    }

    #[test]
    fn unit_http_step_up_disabled_passes() {
        // No interval configured: feature off, nothing is stale.
        assert!(!is_session_step_up_stale(
            Some(&user_auth()),
            None,
            None,
            now()
        ));
    }

    #[test]
    fn unit_http_step_up_anonymous_session_passes() {
        // No session auth at all (unauthenticated public endpoints): no
        // step-up check applies. Auth check is elsewhere.
        assert!(!is_session_step_up_stale(
            None,
            None,
            Some(Duration::from_secs(12 * 3600)),
            now()
        ));
    }

    #[test]
    fn unit_http_step_up_ticket_session_passes() {
        // Ticket-authed sessions are exempt per spec: they hold their own
        // TTL / use counter and are not subject to SSO step-up.
        assert!(!is_session_step_up_stale(
            Some(&ticket_auth()),
            None,
            Some(Duration::from_secs(12 * 3600)),
            now()
        ));
    }

    #[test]
    fn unit_http_step_up_user_fresh_stamp_passes() {
        let stamped = now() - time::Duration::minutes(30);
        assert!(!is_session_step_up_stale(
            Some(&user_auth()),
            Some(stamped),
            Some(Duration::from_secs(12 * 3600)),
            now()
        ));
    }

    #[test]
    fn unit_http_step_up_user_stale_stamp_is_stale() {
        let stamped = now() - time::Duration::hours(13);
        assert!(is_session_step_up_stale(
            Some(&user_auth()),
            Some(stamped),
            Some(Duration::from_secs(12 * 3600)),
            now()
        ));
    }

    #[test]
    fn unit_http_step_up_user_cold_start_is_stale() {
        // User session authorized but no SSO stamp on session (e.g. first
        // visit after password-only login, which does not stamp). Forces
        // re-SSO.
        assert!(is_session_step_up_stale(
            Some(&user_auth()),
            None,
            Some(Duration::from_secs(12 * 3600)),
            now()
        ));
    }

    #[test]
    fn unit_http_step_up_user_exact_boundary_is_fresh() {
        // A stamp exactly one interval ago must count as fresh (inclusive
        // boundary — matches SSH A1 semantics via shared `is_fresh`).
        let interval = Duration::from_secs(12 * 3600);
        let stamped = now() - interval;
        assert!(!is_session_step_up_stale(
            Some(&user_auth()),
            Some(stamped),
            Some(interval),
            now()
        ));
    }

    #[test]
    fn unit_http_step_up_user_one_second_past_boundary_is_stale() {
        let interval = Duration::from_secs(12 * 3600);
        let stamped = now() - interval - time::Duration::seconds(1);
        assert!(is_session_step_up_stale(
            Some(&user_auth()),
            Some(stamped),
            Some(interval),
            now()
        ));
    }

    mod shared_stamp {
        //! The SSO return stamps through [`super::super::stamp_sso`] (driving
        //! the return itself needs an IdP's token exchange, so it is not run
        //! here): two SSO sign-ins on one session raise the user session's
        //! shared stamp each time, and a user session with no SSO sign-in
        //! recorded supersedes nothing.
        use poem::session::Session;
        use time::OffsetDateTime;
        use uuid::Uuid;
        use warpgate_db_entities::HttpSsoStamp;

        use super::super::{StepUpSessionExt, is_superseded, stamp_sso};
        use crate::session::SESSION_ID_SESSION_KEY;
        use crate::test_db::{insert_open_user_session, memory_db};

        #[tokio::test]
        async fn each_sso_sign_in_raises_the_shared_stamp() {
            let db = memory_db().await;
            let id = insert_open_user_session(&db, Uuid::new_v4()).await;
            let session = Session::default();
            session.set(SESSION_ID_SESSION_KEY, id);
            let first = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
            let second = first + time::Duration::minutes(5);

            stamp_sso(&session, &db, first).await.unwrap();
            assert_eq!(HttpSsoStamp::latest(&db, id.0).await.unwrap(), Some(first));
            // A target-host session handed off with the first stamp.
            let bound = Session::default();
            bound.set(SESSION_ID_SESSION_KEY, id);
            bound.set_last_sso_at(first);
            assert!(!is_superseded(&bound, &db).await.unwrap());

            stamp_sso(&session, &db, second).await.unwrap();
            assert_eq!(HttpSsoStamp::latest(&db, id.0).await.unwrap(), Some(second));
            assert_eq!(session.get_last_sso_at(), Some(second));
            assert!(is_superseded(&bound, &db).await.unwrap());
        }

        /// A user session with no SSO sign-in recorded (only the SSO return
        /// calls `stamp_sso`) supersedes none of its target-host sessions,
        /// stamped or not.
        #[tokio::test]
        async fn a_user_session_without_an_sso_stamp_supersedes_nothing() {
            let db = memory_db().await;
            let id = insert_open_user_session(&db, Uuid::new_v4()).await;
            let bound = Session::default();
            bound.set(SESSION_ID_SESSION_KEY, id);
            assert!(!is_superseded(&bound, &db).await.unwrap());
            bound.set_last_sso_at(OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap());
            assert!(!is_superseded(&bound, &db).await.unwrap());
            assert_eq!(HttpSsoStamp::latest(&db, id.0).await.unwrap(), None);
        }
    }
}
