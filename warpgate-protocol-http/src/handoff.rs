//! The one-time handoff that gives a browser a session on a host bound to an
//! HTTP target (a "bound host").
//!
//! Sign-in happens on the control-plane host only, and its session cookie is
//! host-only, so a bound host never receives it. A browser without a session
//! on a bound host gets one this way:
//!
//! 1. The bound host ([`open`]) records the target, its binding, the page to
//!    return to and the hash of a fresh nonce, gives the browser the nonce in
//!    the HttpOnly [`crate::common::HANDOFF_COOKIE_NAME`] cookie, and sends it to the
//!    control plane's [`START_PATH`] with the challenge.
//! 2. The control plane, once the browser is signed in there and the user may
//!    use the target, mints a token for the challenge ([`mint`]) and sends the
//!    browser back to the bound host's [`REDEEM_PATH`] with it. A challenge
//!    the server did not issue, or one already used, mints nothing.
//! 3. The bound host deletes the handoff by the token's hash before checking
//!    anything ([`redeem`]), then requires the same binding and the nonce
//!    cookie the challenge was issued with. Only then does it give the
//!    browser a session that counts on that host only.
//!
//! The nonce ties the token to the browser that started the handoff: a link
//! carrying someone else's challenge or token completes nothing in a victim's
//! browser, which holds no matching nonce.
//!
//! Challenge and token travel in a URL's query: both are single-use and
//! short-lived, the redirects that carry them say `Referrer-Policy:
//! no-referrer`, and the request log and the proxy never see the token
//! ([`HANDOFF_TOKEN_PARAM`] is scrubbed like the ticket parameter).

use std::time::Duration;

use sea_orm::{ConnectionTrait, TransactionTrait};
use time::OffsetDateTime;
use uuid::Uuid;
use warpgate_common::WarpgateError;
use warpgate_common::helpers::hash::{generate_ticket_secret, hash_secret};
use warpgate_common::same_binding_hostname;
use warpgate_db_entities::HttpHandoff;

pub use crate::common::HANDOFF_COOKIE_NAME;

/// The control plane's mint route, under `/@warpgate`.
pub const START_PATH: &str = "/api/handoff/start";
/// The bound host's redeem route, under `/@warpgate`.
pub const REDEEM_PATH: &str = "/api/handoff";
/// The query parameter carrying the challenge to [`START_PATH`].
pub const HANDOFF_CHALLENGE_PARAM: &str = "challenge";
/// The query parameter carrying the token to [`REDEEM_PATH`].
pub const HANDOFF_TOKEN_PARAM: &str = "warpgate-handoff";

/// How long an opened handoff waits for the control plane. A sign-in there
/// that takes longer leaves the browser on a refusal; opening the page again
/// starts a new handoff, which then completes without a second sign-in. The
/// nonce cookie lives as long.
pub const OPEN_LIFETIME: Duration = Duration::from_secs(120);
/// How long a minted token can be redeemed: one redirect.
pub const TOKEN_LIFETIME: Duration = Duration::from_secs(60);

/// An opened handoff: the challenge goes to the control plane in the URL, the
/// nonce to the browser in the [`crate::common::HANDOFF_COOKIE_NAME`] cookie.
pub struct Opened {
    pub challenge: String,
    pub nonce: String,
}

/// Records a handoff for the target `target_id` bound to `binding`, returning
/// to `next` (a path on that host) once redeemed.
pub async fn open<C: ConnectionTrait>(
    db: &C,
    target_id: Uuid,
    binding: &str,
    next: &str,
    now: OffsetDateTime,
) -> Result<Opened, WarpgateError> {
    let challenge = generate_ticket_secret().expose_secret().clone();
    let nonce = generate_ticket_secret().expose_secret().clone();
    HttpHandoff::open(
        db,
        HttpHandoff::Opening {
            challenge_hash: hash_secret(&challenge),
            nonce_hash: hash_secret(&nonce),
            hostname: binding.to_owned(),
            target_id,
            next: next.to_owned(),
            expires: now + OPEN_LIFETIME,
        },
    )
    .await?;
    Ok(Opened { challenge, nonce })
}

/// The opened, unminted handoff this challenge names, for the control plane to
/// check the user's access to its target before [`mint`].
pub async fn opened<C: ConnectionTrait>(
    db: &C,
    challenge: &str,
    now: OffsetDateTime,
) -> Result<Option<HttpHandoff::Model>, WarpgateError> {
    HttpHandoff::opened(db, &hash_secret(challenge), now).await
}

/// Mints the token for this challenge, for the user signed in on the control
/// plane under `user_session_id`. `None` when the challenge is unknown,
/// expired or already minted.
pub async fn mint<C: ConnectionTrait>(
    db: &C,
    challenge: &str,
    user_id: Uuid,
    user_session_id: Uuid,
    now: OffsetDateTime,
) -> Result<Option<String>, WarpgateError> {
    let token = generate_ticket_secret().expose_secret().clone();
    let minted = HttpHandoff::mint(
        db,
        &hash_secret(challenge),
        HttpHandoff::Minting {
            token_hash: hash_secret(&token),
            user_id,
            user_session_id,
            expires: now + TOKEN_LIFETIME,
        },
        now,
    )
    .await?;
    Ok(minted.then_some(token))
}

/// A minted handoff the bound host accepted ([`redeem`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redeemed {
    pub user_id: Uuid,
    pub user_session_id: Uuid,
    pub target_id: Uuid,
    pub hostname: String,
    pub next: String,
}

/// Why a bound host refused a handoff token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedeemRefusal {
    /// Unknown, expired or already used.
    UnknownToken,
    /// Minted for another host or target.
    WrongHost,
    /// The browser holds no nonce cookie, or not the one this handoff was
    /// opened with.
    WrongNonce,
}

/// Redeems `token` on the host bound to `target_id` at `hostname`, for a
/// browser holding `nonce` in its handoff cookie. The handoff is deleted
/// first, so a refused token cannot be tried again.
pub async fn redeem<C: ConnectionTrait + TransactionTrait>(
    db: &C,
    token: &str,
    target_id: Uuid,
    hostname: &str,
    nonce: Option<&str>,
    now: OffsetDateTime,
) -> Result<Result<Redeemed, RedeemRefusal>, WarpgateError> {
    let Some(row) = HttpHandoff::take(db, &hash_secret(token), now).await? else {
        return Ok(Err(RedeemRefusal::UnknownToken));
    };
    if row.target_id != target_id || !same_binding_hostname(&row.hostname, hostname) {
        return Ok(Err(RedeemRefusal::WrongHost));
    }
    let nonce_matches = nonce.is_some_and(|nonce| {
        subtle::ConstantTimeEq::ct_eq(hash_secret(nonce).as_bytes(), row.nonce_hash.as_bytes())
            .into()
    });
    if !nonce_matches {
        return Ok(Err(RedeemRefusal::WrongNonce));
    }
    let (Some(user_id), Some(user_session_id)) = (row.user_id, row.user_session_id) else {
        return Ok(Err(RedeemRefusal::UnknownToken));
    };
    Ok(Ok(Redeemed {
        user_id,
        user_session_id,
        target_id: row.target_id,
        hostname: row.hostname,
        next: row.next,
    }))
}

/// Deletes expired handoffs; run with the session sweep.
pub async fn purge_expired<C: ConnectionTrait>(
    db: &C,
    now: OffsetDateTime,
) -> Result<u64, WarpgateError> {
    HttpHandoff::purge_expired(db, now).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_db::memory_db;

    const HOST: &str = "vm1.warp.example";

    fn at(seconds: i64) -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(1_800_000_000 + seconds)
    }

    struct Flow {
        target: Uuid,
        user: Uuid,
        session: Uuid,
        nonce: String,
        token: String,
    }

    async fn minted(db: &sea_orm::DatabaseConnection) -> Flow {
        let target = Uuid::new_v4();
        let user = Uuid::new_v4();
        let session = Uuid::new_v4();
        let opened = open(db, target, HOST, "/page?x=1", at(0)).await.unwrap();
        let row = super::opened(db, &opened.challenge, at(1))
            .await
            .unwrap()
            .unwrap();
        assert_eq!((row.target_id, row.hostname.as_str()), (target, HOST));
        let token = mint(db, &opened.challenge, user, session, at(2))
            .await
            .unwrap()
            .unwrap();
        Flow {
            target,
            user,
            session,
            nonce: opened.nonce,
            token,
        }
    }

    #[tokio::test]
    async fn unit_handoff_flow_redeems_once() {
        let db = memory_db().await;
        let flow = minted(&db).await;
        let redeemed = redeem(
            &db,
            &flow.token,
            flow.target,
            HOST,
            Some(&flow.nonce),
            at(3),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            redeemed,
            Redeemed {
                user_id: flow.user,
                user_session_id: flow.session,
                target_id: flow.target,
                hostname: HOST.into(),
                next: "/page?x=1".into(),
            }
        );
        // Replay.
        assert_eq!(
            redeem(
                &db,
                &flow.token,
                flow.target,
                HOST,
                Some(&flow.nonce),
                at(4)
            )
            .await
            .unwrap(),
            Err(RedeemRefusal::UnknownToken)
        );
    }

    #[tokio::test]
    async fn unit_handoff_host_compare_ignores_port_case_and_trailing_dot() {
        let db = memory_db().await;
        let flow = minted(&db).await;
        assert!(
            redeem(
                &db,
                &flow.token,
                flow.target,
                "VM1.warp.example.:443",
                Some(&flow.nonce),
                at(3)
            )
            .await
            .unwrap()
            .is_ok()
        );
    }

    /// Every refusal deletes the handoff, so the right browser cannot try again.
    #[tokio::test]
    async fn unit_handoff_refusals_delete_the_handoff() {
        let db = memory_db().await;
        type Case = fn(&Flow) -> (Uuid, &'static str, Option<String>, RedeemRefusal);
        let cases: [Case; 4] = [
            |f| {
                (
                    f.target,
                    "vm2.warp.example",
                    Some(f.nonce.clone()),
                    RedeemRefusal::WrongHost,
                )
            },
            |f| {
                (
                    Uuid::new_v4(),
                    HOST,
                    Some(f.nonce.clone()),
                    RedeemRefusal::WrongHost,
                )
            },
            |f| (f.target, HOST, None, RedeemRefusal::WrongNonce),
            |f| {
                (
                    f.target,
                    HOST,
                    Some(format!("{}x", f.nonce)),
                    RedeemRefusal::WrongNonce,
                )
            },
        ];
        for case in cases {
            let flow = minted(&db).await;
            let (target, host, nonce, refusal) = case(&flow);
            assert_eq!(
                redeem(&db, &flow.token, target, host, nonce.as_deref(), at(3))
                    .await
                    .unwrap(),
                Err(refusal)
            );
            assert_eq!(
                redeem(
                    &db,
                    &flow.token,
                    flow.target,
                    HOST,
                    Some(&flow.nonce),
                    at(3)
                )
                .await
                .unwrap(),
                Err(RedeemRefusal::UnknownToken)
            );
        }
    }

    #[tokio::test]
    async fn unit_handoff_token_expires() {
        let db = memory_db().await;
        let flow = minted(&db).await;
        let late = at(2) + TOKEN_LIFETIME;
        assert_eq!(
            redeem(&db, &flow.token, flow.target, HOST, Some(&flow.nonce), late)
                .await
                .unwrap(),
            Err(RedeemRefusal::UnknownToken)
        );
    }

    #[tokio::test]
    async fn unit_handoff_challenge_mints_once_and_only_if_issued() {
        let db = memory_db().await;
        let opened = open(&db, Uuid::new_v4(), HOST, "/", at(0)).await.unwrap();
        let (user, session) = (Uuid::new_v4(), Uuid::new_v4());
        assert!(
            mint(&db, "not-issued", user, session, at(1))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            super::opened(&db, "not-issued", at(1))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            mint(&db, &opened.challenge, user, session, at(1))
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            super::opened(&db, &opened.challenge, at(1))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            mint(&db, &opened.challenge, user, session, at(1))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn unit_handoff_challenge_expires_and_is_purged() {
        let db = memory_db().await;
        let opened = open(&db, Uuid::new_v4(), HOST, "/", at(0)).await.unwrap();
        let late = at(0) + OPEN_LIFETIME;
        assert!(
            super::opened(&db, &opened.challenge, late)
                .await
                .unwrap()
                .is_none()
        );
        let (user, session) = (Uuid::new_v4(), Uuid::new_v4());
        assert!(
            mint(&db, &opened.challenge, user, session, late)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(purge_expired(&db, late).await.unwrap(), 1);
    }

    /// The database holds hashes only.
    #[tokio::test]
    async fn unit_handoff_stores_no_secret() {
        use sea_orm::EntityTrait;
        let db = memory_db().await;
        let opened = open(&db, Uuid::new_v4(), HOST, "/", at(0)).await.unwrap();
        let token = mint(
            &db,
            &opened.challenge,
            Uuid::new_v4(),
            Uuid::new_v4(),
            at(1),
        )
        .await
        .unwrap()
        .unwrap();
        let row = HttpHandoff::Entity::find().one(&db).await.unwrap().unwrap();
        let stored = format!("{row:?}");
        for secret in [&opened.challenge, &opened.nonce, &token] {
            assert!(!stored.contains(secret.as_str()));
        }
    }
}
