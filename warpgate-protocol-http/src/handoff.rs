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

use std::sync::Arc;
use std::time::Duration;

use http::StatusCode;
use poem::error::NotFoundError;
use poem::session::Session;
use poem::web::Data;
use poem::web::cookie::CookieJar;
use poem::{FromRequest, Request, Response};
use sea_orm::{ConnectionTrait, EntityTrait, TransactionTrait};
use time::OffsetDateTime;
use tokio::sync::Mutex;
use uuid::Uuid;
use warpgate_common::helpers::hash::{generate_ticket_secret, hash_secret};
use warpgate_common::same_binding_hostname;
use warpgate_common::{UserSessionId, WarpgateError};
use warpgate_common_http::auth::{
    AuthenticatedRequestContext, RequestAuthorization, SessionAuthorization,
    UnauthenticatedRequestContext,
};
use warpgate_common_http::ext::is_navigation_request;
use warpgate_core::ConfigProvider;
use warpgate_core::authorize_for_target;
use warpgate_core::live_streams::host_binding;
use warpgate_db_entities::HttpHandoff;

use crate::catchall::{bound_to_host, get_target_by_request_host};
use crate::common::{
    BoundSessionAuthorization, GatewayPages, HANDOFF_COOKIE_NAME, SessionExt, SessionRotation,
    bound_host_return_url, force_step_up, gateway_pages_for, gateway_redirect,
    http_step_up_interval,
};
use crate::middleware::target_bound_to_request_host;
use crate::session::{SESSION_ID_SESSION_KEY, SessionStore};
use crate::step_up::{StepUpSessionExt, is_session_step_up_stale};

/// The control plane's mint route, under `/@warpgate`.
pub const START_PATH: &str = "/handoff/start";
/// The bound host's redeem route, under `/@warpgate`.
pub const REDEEM_PATH: &str = "/handoff";
/// The query parameter carrying the challenge to [`START_PATH`] (redacted
/// from logs there, as the token is everywhere).
pub const HANDOFF_CHALLENGE_PARAM: &str =
    warpgate_common_http::ticket_query::HANDOFF_CHALLENGE_QUERY_PARAM;
/// The query parameter carrying the token to [`REDEEM_PATH`].
pub const HANDOFF_TOKEN_PARAM: &str = warpgate_common_http::ticket_query::HANDOFF_QUERY_PARAM;

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
/// plane under `user_session_id`, whose browser session last did an SSO
/// handshake at `last_sso_at`. `None` when the challenge is unknown, expired
/// or already minted.
pub async fn mint<C: ConnectionTrait>(
    db: &C,
    challenge: &str,
    user_id: Uuid,
    user_session_id: Uuid,
    last_sso_at: Option<OffsetDateTime>,
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
            last_sso_at,
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
    /// The control-plane session's SSO stamp at mint, carried to the bound
    /// host's session so its step-up gate measures the same sign-in.
    pub last_sso_at: Option<OffsetDateTime>,
    pub target_id: Uuid,
    pub hostname: String,
    pub next: String,
}

/// Why a bound host refused a handoff token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedeemRefusal {
    /// Unknown, expired or already used.
    UnknownToken,
    /// Minted for another host or target.
    WrongHost,
    /// The browser holds no nonce cookie, or not the one this handoff was
    /// opened with (another tab's handoff may have replaced it). `next` is
    /// the page on this host the handoff was opened for.
    WrongNonce { next: String },
}

impl RedeemRefusal {
    /// Whether the refused token was this host's to spend: a handoff row
    /// was found and deleted. A token that was never issued, or has already
    /// been spent, proves nothing about the browser holding it, so it
    /// changes nothing there.
    const fn spent_a_handoff(&self) -> bool {
        !matches!(self, Self::UnknownToken)
    }

    /// The refusal's name for the log, without the page it carries.
    const fn reason(&self) -> &'static str {
        match self {
            Self::UnknownToken => "UnknownToken",
            Self::WrongHost => "WrongHost",
            Self::WrongNonce { .. } => "WrongNonce",
        }
    }
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
        return Ok(Err(RedeemRefusal::WrongNonce { next: row.next }));
    }
    let (Some(user_id), Some(user_session_id)) = (row.user_id, row.user_session_id) else {
        return Ok(Err(RedeemRefusal::UnknownToken));
    };
    Ok(Ok(Redeemed {
        user_id,
        user_session_id,
        last_sso_at: row.last_sso_at,
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

/// The control plane's [`START_PATH`]: mints a token for the challenge in the
/// query and sends the browser back to the bound host's [`REDEEM_PATH`].
///
/// Only a top-level navigation signed in by session (not a ticket or token)
/// gets a token, and only for an opened handoff whose target is still bound
/// to the handoff's hostname and which the user may use. A browser not
/// signed in is sent to sign in, then back here.
#[poem::handler]
pub async fn start_endpoint(req: &Request, session: &Session) -> poem::Result<Response> {
    let ctx = Data::<&UnauthenticatedRequestContext>::from_request_without_body(req).await?;
    if !matches!(gateway_pages_for(req).await, GatewayPages::Here) {
        return Err(NotFoundError.into());
    }
    if !is_navigation_request(req) {
        return Ok(refusal(StatusCode::FORBIDDEN));
    }
    let Some(challenge) = query_value(req, HANDOFF_CHALLENGE_PARAM) else {
        return Ok(refusal(StatusCode::BAD_REQUEST));
    };
    let signed_in = req
        .data::<AuthenticatedRequestContext>()
        .and_then(|actx| match &actx.auth {
            RequestAuthorization::Session(SessionAuthorization::User { user_id, .. }) => {
                actx.auth.as_full_user().map(|full| (*user_id, full))
            }
            _ => None,
        });
    let Some((user_id, full)) = signed_in else {
        if req.data::<AuthenticatedRequestContext>().is_some() {
            // A ticket, an API token or a cluster peer: never a handoff.
            return Ok(refusal(StatusCode::FORBIDDEN));
        }
        return Ok(gateway_redirect(req));
    };
    let Some(user_session_id) = session.get_session_id() else {
        return Ok(refusal(StatusCode::FORBIDDEN));
    };
    let services = ctx.services();
    let now = OffsetDateTime::now_utc();
    let Some(row) = opened(&services.db, &challenge, now).await? else {
        return Ok(refusal(StatusCode::FORBIDDEN));
    };
    // A stale control-plane sign-in mints nothing: the browser signs in
    // again, as on any control-plane page, and comes back here.
    let last_sso_at = session.get_last_sso_at();
    if is_session_step_up_stale(
        Some(&SessionAuthorization::User {
            user_id,
            username: String::new(),
        }),
        last_sso_at,
        http_step_up_interval(services).await,
        now,
    ) {
        force_step_up(req, session).await?;
        return Ok(gateway_redirect(req));
    }
    let target = get_target_by_request_host(services, &row.hostname)
        .await?
        .filter(|target| target.id == row.target_id && bound_to_host(target, &row.hostname));
    let Some(target) = target else {
        return Err(NotFoundError.into());
    };
    let identity = full.identity(crate::common::PROTOCOL_NAME);
    if authorize_for_target(&*services.config_provider, &identity, target)
        .await?
        .is_none()
    {
        return Err(NotFoundError.into());
    }
    let Some(token) = mint(
        &services.db,
        &challenge,
        user_id,
        user_session_id.0,
        last_sso_at,
        now,
    )
    .await?
    else {
        return Ok(refusal(StatusCode::FORBIDDEN));
    };
    let mut redeem = url::form_urlencoded::Serializer::new(format!("/@warpgate{REDEEM_PATH}?"));
    redeem.append_pair(HANDOFF_TOKEN_PARAM, &token);
    let Some(location) = bound_host_return_url("https", &row.hostname, &redeem.finish()) else {
        return Err(NotFoundError.into());
    };
    Ok(see_other(&location).finish())
}

/// The bound host's [`REDEEM_PATH`]: turns the token in the query into a
/// session that counts on this host for its target only
/// ([`crate::common::BoundSessionAuthorization`]), then sends the browser to
/// the page it started from.
///
/// A refused token that spent a handoff (one found and deleted) clears the
/// nonce cookie and purges this host's browser session. One that spent
/// nothing (never issued, already used, or no token at all: any site can
/// send a browser here) changes nothing. Either way the browser is sent to
/// the page the handoff was opened for when that is known, or this host's
/// root, where a browser without a session opens a new handoff: so a tab
/// whose nonce cookie another tab's handoff replaced simply tries again.
#[poem::handler]
pub async fn redeem_endpoint(req: &Request, session: &Session) -> poem::Result<Response> {
    let ctx = Data::<&UnauthenticatedRequestContext>::from_request_without_body(req).await?;
    let target = target_bound_to_request_host(&ctx, req).await?;
    let Some((target, binding)) =
        target.and_then(|target| host_binding(&target.options).map(|binding| (target, binding)))
    else {
        return Err(NotFoundError.into());
    };
    let nonce = <&CookieJar>::from_request_without_body(req)
        .await?
        .get(HANDOFF_COOKIE_NAME)
        .map(|cookie| cookie.value_str().to_owned());
    let redeemed = match query_value(req, HANDOFF_TOKEN_PARAM) {
        Some(token) => {
            let services = ctx.services();
            redeem(
                &services.db,
                &token,
                target.id,
                &binding,
                nonce.as_deref(),
                OffsetDateTime::now_utc(),
            )
            .await?
        }
        None => Err(RedeemRefusal::UnknownToken),
    };
    let (outcome, spent, next) = match redeemed {
        Ok(redeemed) => {
            let next = redeemed.next.clone();
            let outcome = complete_redeem(req, &ctx, session, &target, &binding, redeemed).await;
            (outcome, true, Some(next))
        }
        Err(refusal) => {
            let spent = refusal.spent_a_handoff();
            let next = match &refusal {
                RedeemRefusal::WrongNonce { next } => Some(next.clone()),
                _ => None,
            };
            (Err(refusal.reason().to_owned()), spent, next)
        }
    };
    let mut response = match outcome {
        Ok(response) => response,
        Err(reason) => {
            tracing::warn!(target = %target.name, %reason, "Refused a target-host handoff");
            if spent {
                session.purge();
            }
            let retry = next
                .and_then(|next| bound_host_return_url("https", &binding, &next))
                .or_else(|| bound_host_return_url("https", &binding, "/"));
            match retry {
                Some(location) => see_other(&location).finish(),
                None => refusal(StatusCode::FORBIDDEN),
            }
        }
    };
    if !spent {
        return Ok(response);
    }
    response.headers_mut().append(
        http::header::SET_COOKIE,
        http::HeaderValue::from_str(&format!(
            "{HANDOFF_COOKIE_NAME}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0"
        ))
        .map_err(poem::error::InternalServerError)?,
    );
    Ok(response)
}

/// The checks and the session change after [`redeem`] accepted a token.
async fn complete_redeem(
    req: &Request,
    ctx: &UnauthenticatedRequestContext,
    session: &Session,
    target: &warpgate_common::Target,
    binding: &str,
    redeemed: Redeemed,
) -> Result<Response, String> {
    let services = ctx.services();
    let user = warpgate_db_entities::User::Entity::find_by_id(redeemed.user_id)
        .one(&services.db)
        .await
        .map_err(|error| error.to_string())?
        .ok_or("UnknownUser")?;
    // A fresh browser session id, carrying nothing from before.
    session.clear();
    if let Some(rotation) = SessionRotation::for_request(req)
        .await
        .map_err(|error| error.to_string())?
    {
        rotation
            .apply(session)
            .await
            .map_err(|error| error.to_string())?;
    }
    session.set(
        SESSION_ID_SESSION_KEY,
        UserSessionId(redeemed.user_session_id),
    );
    if let Some(last_sso_at) = redeemed.last_sso_at {
        session.set_last_sso_at(last_sso_at);
    }
    session.set_bound_auth(BoundSessionAuthorization {
        user_id: user.id,
        username: user.username,
        target_id: target.id,
        hostname: binding.to_owned(),
    });
    // The user session must still be open, an HTTP one, and this user's.
    let store = Data::<&Arc<Mutex<SessionStore>>>::from_request_without_body(req)
        .await
        .map_err(|error| error.to_string())?;
    store
        .lock()
        .await
        .handle_for_request(req, ctx)
        .await
        .map_err(|_| "UserSessionGone")?;
    if !services
        .config_provider
        .authorize_target_by_id(redeemed.user_id, target.id)
        .await
        .map_err(|error| error.to_string())?
    {
        return Err("TargetAccess".to_owned());
    }
    let location = bound_host_return_url("https", binding, &redeemed.next).ok_or("BadNext")?;
    Ok(see_other(&location).finish())
}

/// The first value of the query parameter `name`.
fn query_value(req: &Request, name: &str) -> Option<String> {
    url::form_urlencoded::parse(req.uri().query()?.as_bytes())
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
        .filter(|value| !value.is_empty())
}

/// A 303 to `location` that leaks neither the address it came from nor a
/// cached copy of itself.
fn see_other(location: &str) -> poem::ResponseBuilder {
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(http::header::LOCATION, location)
        .header(http::header::REFERRER_POLICY, "no-referrer")
        .header(http::header::CACHE_CONTROL, "no-store")
}

fn refusal(status: StatusCode) -> Response {
    Response::builder()
        .status(status)
        .header(http::header::CACHE_CONTROL, "no-store")
        .finish()
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
        let token = mint(db, &opened.challenge, user, session, Some(at(-5)), at(2))
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
                last_sso_at: Some(at(-5)),
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
            |f| {
                (
                    f.target,
                    HOST,
                    None,
                    RedeemRefusal::WrongNonce {
                        next: "/page?x=1".into(),
                    },
                )
            },
            |f| {
                (
                    f.target,
                    HOST,
                    Some(format!("{}x", f.nonce)),
                    RedeemRefusal::WrongNonce {
                        next: "/page?x=1".into(),
                    },
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
            mint(&db, "not-issued", user, session, None, at(1))
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
            mint(&db, &opened.challenge, user, session, None, at(1))
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
            mint(&db, &opened.challenge, user, session, None, at(1))
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
            mint(&db, &opened.challenge, user, session, None, late)
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
            None,
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

    mod endpoint {
        //! The redeem route behind the session middleware production uses.
        use poem::session::ServerSession;
        use poem::test::{TestClient, TestResponse};
        use poem::{EndpointExt, Route, get, handler};
        use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait, Set};
        use warpgate_db_entities::Target::TargetKind;
        use warpgate_db_entities::{HttpSession, Target};

        use super::*;
        use crate::common::{SESSION_COOKIE_NAME, session_cookie_config};
        use crate::session_storage::SharedSessionStorage;
        use crate::test_db::services;

        /// Gives the browser a session holding something.
        #[handler]
        fn seed(session: &Session) {
            session.set("seeded", true);
        }

        async fn bound_target(db: &DatabaseConnection) -> Uuid {
            let id = Uuid::new_v4();
            Target::ActiveModel {
                id: Set(id),
                name: Set(format!("target-{id}")),
                description: Set(String::new()),
                kind: Set(TargetKind::Http),
                options: Set(serde_json::json!({
                    "http": {"url": "http://h", "external_host": HOST}
                })),
                rate_limit_bytes_per_second: Set(None),
                group_id: Set(None),
                ticket_max_duration_seconds: Set(None),
                ticket_requests_disabled: Set(false),
                ticket_require_approval: Set(false),
                ticket_max_uses: Set(None),
                require_approval: Set(false),
            }
            .insert(db)
            .await
            .unwrap();
            id
        }

        async fn app(db: DatabaseConnection) -> impl poem::Endpoint {
            let ctx = UnauthenticatedRequestContext::new(services(db.clone()).await).await;
            Route::new()
                .at("/seed", get(seed))
                .at(format!("/@warpgate{REDEEM_PATH}"), get(redeem_endpoint))
                .data(SessionStore::new())
                .data(ctx)
                .with(ServerSession::new(
                    session_cookie_config(),
                    SharedSessionStorage::new(db),
                ))
        }

        fn session_cookie(resp: &TestResponse) -> String {
            resp.0
                .headers()
                .get_all("set-cookie")
                .iter()
                .filter_map(|value| value.to_str().ok())
                .filter_map(|value| value.split(';').next())
                .find(|pair| pair.starts_with(&format!("{SESSION_COOKIE_NAME}=")))
                .expect("a session cookie")
                .to_owned()
        }

        fn clears_the_nonce(resp: &TestResponse) -> bool {
            resp.0
                .headers()
                .get_all("set-cookie")
                .iter()
                .filter_map(|value| value.to_str().ok())
                .any(|value| value.starts_with(&format!("{HANDOFF_COOKIE_NAME}=;")))
        }

        async fn stored(db: &DatabaseConnection, cookie: &str) -> bool {
            let (_, id) = cookie.split_once('=').unwrap();
            HttpSession::Entity::find_by_id(id.to_owned())
                .one(db)
                .await
                .unwrap()
                .is_some()
        }

        /// Any site can send a browser to the redeem route with a token that
        /// was never issued: that changes nothing in the browser, and sends
        /// it to open a handoff of its own.
        #[tokio::test]
        async fn an_unknown_token_leaves_the_browser_session_alone() {
            let db = memory_db().await;
            bound_target(&db).await;
            let cli = TestClient::new(app(db.clone()).await);
            let cookie = session_cookie(&cli.get("/seed").header("host", HOST).send().await);

            for path in [
                format!("/@warpgate{REDEEM_PATH}?{HANDOFF_TOKEN_PARAM}=junk"),
                format!("/@warpgate{REDEEM_PATH}"),
            ] {
                let resp = cli
                    .get(&path)
                    .header("host", HOST)
                    .header("cookie", &cookie)
                    .send()
                    .await;
                resp.assert_status(StatusCode::SEE_OTHER);
                resp.assert_header("location", format!("https://{HOST}/"));
                assert!(!clears_the_nonce(&resp), "{path}");
                assert!(stored(&db, &cookie).await, "{path} dropped the session");
            }
        }

        /// A real token redeemed without its nonce (another tab's handoff
        /// replaced the cookie) is spent: the browser session goes, and the
        /// browser is sent back to its page to open a new handoff.
        #[tokio::test]
        async fn a_spent_token_without_its_nonce_retries_from_the_page() {
            let db = memory_db().await;
            let target = bound_target(&db).await;
            let cli = TestClient::new(app(db.clone()).await);
            let cookie = session_cookie(&cli.get("/seed").header("host", HOST).send().await);
            let now = OffsetDateTime::now_utc();
            let opened = open(&db, target, HOST, "/page?x=1", now).await.unwrap();
            let token = mint(
                &db,
                &opened.challenge,
                Uuid::new_v4(),
                Uuid::new_v4(),
                None,
                now,
            )
            .await
            .unwrap()
            .unwrap();

            let resp = cli
                .get(format!(
                    "/@warpgate{REDEEM_PATH}?{HANDOFF_TOKEN_PARAM}={token}"
                ))
                .header("host", HOST)
                .header("cookie", format!("{cookie}; {HANDOFF_COOKIE_NAME}=other"))
                .send()
                .await;
            resp.assert_status(StatusCode::SEE_OTHER);
            resp.assert_header("location", format!("https://{HOST}/page?x=1"));
            assert!(clears_the_nonce(&resp));
            assert!(!stored(&db, &cookie).await, "the session survived");
        }
    }
}
