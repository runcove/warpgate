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
//! no-referrer`. Log lines hold no query value
//! (`warpgate_common_http::logging::redacted_uri`), so neither appears in
//! the request log, and the proxy strips [`HANDOFF_TOKEN_PARAM`] as it
//! strips the ticket parameter, so the target never sees the token.

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use governor::{DefaultKeyedRateLimiter, Quota};
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
use warpgate_common::{UserSessionId, WarpgateError, same_binding_hostname};
use warpgate_common_http::auth::{
    AuthenticatedRequestContext, RequestAuthorization, SessionAuthorization,
    UnauthenticatedRequestContext,
};
use warpgate_common_http::ext::is_navigation_request;
use warpgate_common_http::logging::get_client_ip_addr;
use warpgate_common_http::ticket_query::without_ticket_query_param;
use warpgate_core::live_streams::host_binding;
use warpgate_core::{ConfigProvider, authorize_for_target};
use warpgate_db_entities::HttpHandoff;

use crate::api::sso_provider_list::is_safe_redirect_target;
use crate::catchall::{bound_to_host, get_target_by_request_host};
use crate::common::{
    BoundSessionAuthorization, GatewayPages, HANDOFF_COOKIE_NAME, SessionExt, SessionRotation,
    bound_host_return_url, force_step_up, gateway_pages_for, gateway_redirect,
    http_step_up_interval, is_https_navigation, open_handoff,
};
use crate::middleware::target_bound_to_request_host;
use crate::session::{SESSION_ID_SESSION_KEY, SessionStore};
use crate::step_up::{StepUpSessionExt, is_session_step_up_stale};

/// The bound host's begin route, under `/@warpgate`: starts a handoff for
/// a page on that host named in [`BEGIN_NEXT_PARAM`] ([`begin_endpoint`]).
pub const BEGIN_PATH: &str = "/handoff/begin";
/// The query parameter naming the page on the bound host to return to after
/// [`BEGIN_PATH`]'s handoff.
pub const BEGIN_NEXT_PARAM: &str = "next";
/// The control plane's mint route, under `/@warpgate`.
pub const START_PATH: &str = "/handoff/start";
/// The bound host's redeem route, under `/@warpgate`.
pub const REDEEM_PATH: &str = "/handoff";
/// The query parameter carrying the challenge to [`START_PATH`]. Log lines
/// never hold its value, as they hold no query value
/// (`warpgate_common_http::logging::redacted_uri`).
pub const HANDOFF_CHALLENGE_PARAM: &str =
    warpgate_common_http::ticket_query::HANDOFF_CHALLENGE_QUERY_PARAM;
/// The query parameter carrying the token to [`REDEEM_PATH`].
pub const HANDOFF_TOKEN_PARAM: &str = warpgate_common_http::ticket_query::HANDOFF_QUERY_PARAM;
/// The query parameter a refused handoff adds to the page it sends the
/// browser back to, so the handoff that page opens is known to be a retry.
/// A retry that is refused too ends on a 403 instead of another retry: a
/// browser that blocks this host's cookies never holds the nonce. Removed
/// again from the page a handoff completes on.
pub const HANDOFF_RETRY_PARAM: &str = "warpgate-handoff-retry";

/// How long an opened handoff waits for the control plane. A sign-in there
/// that takes longer leaves the browser on a refusal saying so
/// ([`start_endpoint`]); opening the page again
/// starts a new handoff, which then completes without a second sign-in. The
/// nonce cookie lives as long.
pub const OPEN_LIFETIME: Duration = Duration::from_secs(120);
/// How long a minted token can be redeemed: one redirect.
pub const TOKEN_LIFETIME: Duration = Duration::from_secs(60);

/// The most handoffs the store holds, expired ones not yet purged included.
/// At the ceiling [`open`] records none and the browser is refused
/// ([`busy`]); stored handoffs are never evicted to make room, so a flood
/// cannot push out the handoff of a browser already on its way.
pub const MAX_STORED: u64 = 10_000;

/// The most handoffs the store holds for any one target, and so its one
/// host: a flood of handoffs opened on a single host is refused there
/// ([`busy`]) long before it fills the store for every other host.
pub const MAX_STORED_PER_TARGET: u64 = MAX_STORED / 10;

/// How many handoff steps of each kind one source address may take a minute
/// (opening on a bound host, starting on the control plane, redeeming), as
/// a burst that refills at the same rate. Each sign-in on a new host takes
/// one of each.
const PER_ADDRESS_PER_MINUTE: NonZeroU32 = NonZeroU32::MIN.saturating_add(59);

/// A rate-limited step of the handoff.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) enum Step {
    Open,
    Start,
    Redeem,
}

/// The per-source-address limit on each [`Step`], in memory on each node.
/// An IPv6 address counts by its /64 prefix, which one client typically holds
/// whole ([`rate_limit_address`]). A request whose address is unknown counts
/// against one shared bucket.
pub(crate) struct RateLimit(DefaultKeyedRateLimiter<(Step, Option<IpAddr>)>);

/// The address a request is rate-limited as: an IPv4 address (an IPv4-mapped
/// IPv6 one included) as it is, an IPv6 address as its /64 prefix.
fn rate_limit_address(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => IpAddr::V6(std::net::Ipv6Addr::from_bits(
            v6.to_bits() & !u128::from(u64::MAX),
        )),
    }
}

impl RateLimit {
    pub(crate) fn per_minute(per_minute: NonZeroU32) -> Self {
        Self(DefaultKeyedRateLimiter::keyed(Quota::per_minute(
            per_minute,
        )))
    }

    /// Whether `ip` may take one more `step` now.
    pub(crate) fn allows(&self, step: Step, ip: Option<IpAddr>) -> bool {
        self.0
            .check_key(&(step, ip.map(rate_limit_address)))
            .is_ok()
    }
}

static RATE_LIMIT: LazyLock<RateLimit> =
    LazyLock::new(|| RateLimit::per_minute(PER_ADDRESS_PER_MINUTE));

/// Whether this request's source address may take one more `step`, from the
/// [`RateLimit`] in the request's data if there is one (tests), else the
/// node's own.
pub(crate) async fn within_rate_limit(
    req: &Request,
    services: &warpgate_core::Services,
    step: Step,
) -> bool {
    let ip = get_client_ip_addr(req, services).await;
    let limit = req
        .data::<Arc<RateLimit>>()
        .map_or(&*RATE_LIMIT, |limit| &**limit);
    let allowed = limit.allows(step, ip);
    if !allowed {
        tracing::info!(?step, client_ip = ?ip, "Refused a target-host handoff step: rate limited");
    }
    allowed
}

/// Forgets the addresses whose limit has refilled; run with the session
/// sweep.
pub fn vacuum_rate_limit() {
    RATE_LIMIT.0.retain_recent();
    RATE_LIMIT.0.shrink_to_fit();
}

/// The refusal of a handoff step past its rate limit.
pub(crate) fn rate_limited() -> Response {
    plain(
        StatusCode::TOO_MANY_REQUESTS,
        "Too many sign-in attempts from this address. Wait a minute, then reload the page.\n",
    )
}

/// The refusal of a handoff when the store is at [`MAX_STORED`].
pub(crate) fn busy() -> Response {
    plain(
        StatusCode::SERVICE_UNAVAILABLE,
        "Signing in to this site is not possible right now. Try again in a few minutes.\n",
    )
}

fn plain(status: StatusCode, body: &'static str) -> Response {
    Response::builder()
        .status(status)
        .header(http::header::CACHE_CONTROL, "no-store")
        .content_type("text/plain; charset=utf-8")
        .body(body)
}

/// An opened handoff: the challenge goes to the control plane in the URL, the
/// nonce to the browser in the [`crate::common::HANDOFF_COOKIE_NAME`] cookie.
pub struct Opened {
    pub challenge: String,
    pub nonce: String,
}

/// Records a handoff for the target `target_id` bound to `binding`, returning
/// to `next` (a path on that host) once redeemed. `None`, recording nothing,
/// when the store already holds [`MAX_STORED`] handoffs, or
/// [`MAX_STORED_PER_TARGET`] for this target.
pub async fn open<C: ConnectionTrait>(
    db: &C,
    target_id: Uuid,
    binding: &str,
    next: &str,
    now: OffsetDateTime,
) -> Result<Option<Opened>, WarpgateError> {
    let ceiling = Ceiling {
        stored: MAX_STORED,
        per_target: MAX_STORED_PER_TARGET,
    };
    open_below(db, ceiling, target_id, binding, next, now).await
}

/// The most handoffs [`open_below`] lets the store hold, in all and for one
/// target.
#[derive(Clone, Copy)]
struct Ceiling {
    stored: u64,
    per_target: u64,
}

/// [`open`] below `ceiling`. Counted, then inserted: nodes opening handoffs
/// at the same moment can each pass the counts, so the store can go past
/// either ceiling by as many handoffs as are opened at once.
async fn open_below<C: ConnectionTrait>(
    db: &C,
    ceiling: Ceiling,
    target_id: Uuid,
    binding: &str,
    next: &str,
    now: OffsetDateTime,
) -> Result<Option<Opened>, WarpgateError> {
    let stored = HttpHandoff::count(db).await?;
    if stored >= ceiling.stored {
        tracing::warn!(
            stored,
            max_stored = ceiling.stored,
            "Refused to open a target-host handoff: the handoff store is full"
        );
        return Ok(None);
    }
    let for_target = HttpHandoff::count_for_target(db, target_id).await?;
    if for_target >= ceiling.per_target {
        tracing::warn!(
            %target_id,
            stored = for_target,
            max_stored = ceiling.per_target,
            "Refused to open a target-host handoff: this target's share of the handoff store is full"
        );
        return Ok(None);
    }
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
    Ok(Some(Opened { challenge, nonce }))
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

/// Whether `req` is not a framed or embedded load: its `Sec-Fetch-Dest`, when
/// the browser sends one, is `document`. A browser too old to send it passes,
/// as it does the `Sec-Fetch-Mode` check of [`is_navigation_request`].
fn is_top_level_document(req: &Request) -> bool {
    req.headers()
        .get("sec-fetch-dest")
        .is_none_or(|dest| dest == "document")
}

/// The bound host's [`BEGIN_PATH`]: starts a sign-in from a host bound to a
/// target, which no navigation there starts by itself when the target is
/// public. It opens the same handoff an unauthenticated navigation on that
/// host opens ([`crate::common::open_handoff`]), to return to the page in
/// [`BEGIN_NEXT_PARAM`], and changes nothing else: no session is written or
/// ended.
///
/// The host the handoff returns to is the target's configured binding
/// (`host_binding`), never one taken from the request: the request's host
/// only picks the target, as on every route. `next` must be a site-relative
/// path by the one check the SSO paths use
/// ([`crate::api::sso_provider_list::is_safe_redirect_target`]), and loses
/// any ticket in its query. Off a bound host this route is not found; a
/// request that is not a top-level HTTPS navigation is refused (403), as is
/// a missing or unsafe `next` (400).
#[poem::handler]
pub async fn begin_endpoint(req: &Request) -> poem::Result<Response> {
    let GatewayPages::ControlPlane {
        control_plane,
        binding,
        target_id,
    } = gateway_pages_for(req).await
    else {
        return Err(NotFoundError.into());
    };
    if !is_https_navigation(req) || !is_top_level_document(req) {
        return Ok(refusal(StatusCode::FORBIDDEN));
    }
    let next = query_value(req, BEGIN_NEXT_PARAM)
        .filter(|next| is_safe_redirect_target(next))
        .map(|next| without_ticket_query_param(&next));
    let Some(next) = next else {
        return Ok(refusal(StatusCode::BAD_REQUEST));
    };
    open_handoff(req, &control_plane, target_id, &binding, &next)
        .await
        .ok_or_else(|| poem::Error::from_status(StatusCode::INTERNAL_SERVER_ERROR))
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
    if !within_rate_limit(req, ctx.services(), Step::Start).await {
        return Ok(rate_limited());
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
        return Ok(sign_in_too_slow());
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
    // The shared stamp a target-host session is checked against: raised
    // here too, for a sign-in stamped before it was recorded.
    crate::step_up::raise_shared_stamp(session, &services.db, last_sso_at).await?;
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
        return Ok(sign_in_too_slow());
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
/// A token refused by [`redeem`] that spent a handoff (one found and
/// deleted) clears the nonce cookie and leaves this host's browser session
/// as it is: any site can send a browser here with a token it minted for
/// itself, for this host or another, so that refusal proves nothing about
/// the session the browser already holds here. One that spent nothing
/// (never issued, already used, or no token at all) changes nothing. A
/// token [`redeem`] accepted, this browser's own handoff, is still refused
/// if its user, the user's access to the target or its user session is gone
/// by now, and that refusal never leaves a session stored for it: one for
/// a gone user or target access is refused before the browser session is
/// touched, and one for a gone user session, checked once the new session
/// is written, purges this host's browser session ([`complete_redeem`]).
/// Either refusal clears the nonce cookie. In every case the browser is
/// sent to the page the handoff was opened for when that is known, or this
/// host's root, where a browser without a session opens a new handoff: so
/// a tab whose nonce cookie another tab's handoff replaced simply tries
/// again.
/// That retry is marked ([`HANDOFF_RETRY_PARAM`]); a refusal of a handoff
/// opened for a marked page gets a 403 saying sign-in needs cookies. A
/// browser that spent nothing and already holds a session for this target on
/// this host is not retried: it goes back to the page unmarked. The marker
/// never reaches the target (the proxy strips it from the query).
#[poem::handler]
pub async fn redeem_endpoint(req: &Request, session: &Session) -> poem::Result<Response> {
    let ctx = Data::<&UnauthenticatedRequestContext>::from_request_without_body(req).await?;
    let target = target_bound_to_request_host(&ctx, req).await?;
    let Some((target, binding)) =
        target.and_then(|target| host_binding(&target.options).map(|binding| (target, binding)))
    else {
        return Err(NotFoundError.into());
    };
    if !within_rate_limit(req, ctx.services(), Step::Redeem).await {
        return Ok(rate_limited());
    }
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
            let next = next.unwrap_or_else(|| "/".to_owned());
            // A browser that already holds a session for this target on this
            // host has nothing to retry: it goes back to the page unmarked.
            let signed_in_here = session.get_bound_auth().is_some_and(|bound| {
                bound.counts_on(Some((target.id, &binding)), &http::Method::GET, "/")
            });
            let retry = if signed_in_here {
                bound_host_return_url("https", &binding, &without_retry_marker(&next))
            } else {
                (!has_retry_marker(&next))
                    .then(|| bound_host_return_url("https", &binding, &with_retry_marker(&next)))
                    .flatten()
            };
            match retry {
                Some(location) => see_other(&location).finish(),
                None => cookies_needed(),
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
///
/// The user and the target access are checked before the session is
/// touched. The user session can only be checked on the session the token
/// names, so it is checked after that is written; if it, or anything after
/// the first write, fails, the browser session is purged, so a refusal
/// never leaves a stored session carrying the bound authorization.
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
    if !services
        .config_provider
        .authorize_target_by_id(redeemed.user_id, target.id)
        .await
        .map_err(|error| error.to_string())?
    {
        return Err("TargetAccess".to_owned());
    }
    let outcome = bind_session(req, ctx, session, target, binding, redeemed, user).await;
    if outcome.is_err() {
        session.purge();
    }
    outcome
}

/// The session change of [`complete_redeem`], and the user-session check
/// that needs it.
async fn bind_session(
    req: &Request,
    ctx: &UnauthenticatedRequestContext,
    session: &Session,
    target: &warpgate_common::Target,
    binding: &str,
    redeemed: Redeemed,
    user: warpgate_db_entities::User::Model,
) -> Result<Response, String> {
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
    let location = bound_host_return_url("https", binding, &without_retry_marker(&redeemed.next))
        .ok_or("BadNext")?;
    Ok(see_other(&location).finish())
}

/// Whether `next`, a page on a bound host, carries [`HANDOFF_RETRY_PARAM`]:
/// the handoff opened for it was already a retry.
fn has_retry_marker(next: &str) -> bool {
    next.split_once('?').is_some_and(|(_, query)| {
        url::form_urlencoded::parse(query.as_bytes()).any(|(key, _)| key == HANDOFF_RETRY_PARAM)
    })
}

/// `next` with [`HANDOFF_RETRY_PARAM`] added to its query.
fn with_retry_marker(next: &str) -> String {
    let separator = if next.contains('?') { '&' } else { '?' };
    format!("{next}{separator}{HANDOFF_RETRY_PARAM}=1")
}

/// `next` without [`HANDOFF_RETRY_PARAM`]; the rest of its query is kept
/// exactly.
fn without_retry_marker(next: &str) -> String {
    let Some((path, query)) = next.split_once('?') else {
        return next.to_owned();
    };
    let query = query
        .split('&')
        .filter(|pair| {
            url::form_urlencoded::parse(pair.as_bytes())
                .next()
                .is_none_or(|(key, _)| key != HANDOFF_RETRY_PARAM)
        })
        .collect::<Vec<_>>()
        .join("&");
    if query.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{query}")
    }
}

/// The refusal of a retried handoff that failed again: a browser that keeps
/// no cookie for this host would otherwise go round forever.
fn cookies_needed() -> Response {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header(http::header::CACHE_CONTROL, "no-store")
        .content_type("text/plain; charset=utf-8")
        .body(COOKIES_NEEDED)
}

const COOKIES_NEEDED: &str =
    "Signing in to this site needs cookies. Allow cookies for this host, then reload the page.\n";

/// The refusal of a handoff that is gone by the time the control plane would
/// mint it: most often a sign-in that took longer than [`OPEN_LIFETIME`].
/// Opening the page again starts a new handoff.
fn sign_in_too_slow() -> Response {
    plain(StatusCode::FORBIDDEN, SIGN_IN_TOO_SLOW)
}

const SIGN_IN_TOO_SLOW: &str =
    "Signing in took too long. Open the page you were going to again to continue.\n";

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
        let opened = open(db, target, HOST, "/page?x=1", at(0))
            .await
            .unwrap()
            .unwrap();
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
        let opened = open(&db, Uuid::new_v4(), HOST, "/", at(0))
            .await
            .unwrap()
            .unwrap();
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
        let opened = open(&db, Uuid::new_v4(), HOST, "/", at(0))
            .await
            .unwrap()
            .unwrap();
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
        let opened = open(&db, Uuid::new_v4(), HOST, "/", at(0))
            .await
            .unwrap()
            .unwrap();
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

    /// A ceiling of `stored` handoffs in all, with no lower one per target.
    fn total(stored: u64) -> Ceiling {
        Ceiling {
            stored,
            per_target: stored,
        }
    }

    /// One target at its share of the store is refused a handoff and none is
    /// recorded, while other targets still open theirs; once its expired
    /// handoffs are purged it opens again.
    #[tokio::test]
    async fn unit_handoff_one_target_cannot_fill_the_store() {
        let db = memory_db().await;
        let ceiling = Ceiling {
            stored: 10,
            per_target: 2,
        };
        let flooded = Uuid::new_v4();
        let other = Uuid::new_v4();
        for _ in 0..2 {
            assert!(
                open_below(&db, ceiling, flooded, HOST, "/", at(0))
                    .await
                    .unwrap()
                    .is_some()
            );
        }
        assert!(
            open_below(&db, ceiling, flooded, HOST, "/", at(1))
                .await
                .unwrap()
                .is_none(),
            "a target past its share opened a handoff"
        );
        assert_eq!(HttpHandoff::count(&db).await.unwrap(), 2);
        assert!(
            open_below(&db, ceiling, other, "vm2.warp.example", "/", at(1))
                .await
                .unwrap()
                .is_some(),
            "another target was refused"
        );

        let late = at(OPEN_LIFETIME.as_secs() as i64 + 2);
        purge_expired(&db, late).await.unwrap();
        assert!(
            open_below(&db, ceiling, flooded, HOST, "/", late)
                .await
                .unwrap()
                .is_some()
        );
    }

    /// At the ceiling a handoff is refused and none is recorded, and every
    /// stored handoff stays usable: nothing is evicted to make room. Once
    /// the expired ones are purged, handoffs open again.
    #[tokio::test]
    async fn unit_handoff_store_ceiling_refuses_and_evicts_nothing() {
        let db = memory_db().await;
        let target = Uuid::new_v4();
        let mut kept = vec![];
        for _ in 0..3 {
            let opened = open_below(&db, total(3), target, HOST, "/", at(0))
                .await
                .unwrap();
            kept.push(opened.expect("below the ceiling").challenge);
        }
        assert!(
            open_below(&db, total(3), target, HOST, "/", at(1))
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(HttpHandoff::count(&db).await.unwrap(), 3);
        for challenge in &kept {
            assert!(
                opened(&db, challenge, at(1)).await.unwrap().is_some(),
                "a stored handoff was evicted"
            );
        }
        let token = mint(&db, &kept[0], Uuid::new_v4(), Uuid::new_v4(), None, at(1))
            .await
            .unwrap();
        assert!(token.is_some(), "a handoff at the ceiling no longer mints");

        let late = at(OPEN_LIFETIME.as_secs() as i64 + 1);
        purge_expired(&db, late).await.unwrap();
        assert!(
            open_below(&db, total(3), target, HOST, "/", late)
                .await
                .unwrap()
                .is_some()
        );
    }

    /// Each source address has its own limit for each step, and the
    /// unknown address one shared limit.
    #[test]
    fn unit_handoff_rate_limit_is_per_address_and_step() {
        let limit = RateLimit::per_minute(NonZeroU32::new(2).unwrap());
        let a: Option<IpAddr> = Some("192.0.2.1".parse().unwrap());
        let b: Option<IpAddr> = Some("192.0.2.2".parse().unwrap());
        assert!(limit.allows(Step::Open, a));
        assert!(limit.allows(Step::Open, a));
        assert!(!limit.allows(Step::Open, a));
        assert!(limit.allows(Step::Redeem, a));
        assert!(limit.allows(Step::Start, a));
        assert!(limit.allows(Step::Open, b));
        assert!(limit.allows(Step::Open, None));
        assert!(limit.allows(Step::Open, None));
        assert!(!limit.allows(Step::Open, None));
        assert!(!limit.allows(Step::Open, a));
    }

    /// An IPv6 client counts by its /64: every address in one /64 shares a
    /// limit, the next /64 has its own, and an IPv4-mapped address counts as
    /// its IPv4 address.
    #[test]
    fn unit_handoff_rate_limit_counts_ipv6_by_its_64() {
        let limit = RateLimit::per_minute(NonZeroU32::new(2).unwrap());
        let ip = |s: &str| Some(s.parse::<IpAddr>().unwrap());
        assert!(limit.allows(Step::Open, ip("2001:db8:1:2::1")));
        assert!(limit.allows(Step::Open, ip("2001:db8:1:2:ffff:ffff:ffff:ffff")));
        assert!(!limit.allows(Step::Open, ip("2001:db8:1:2:abcd::9")));
        assert!(limit.allows(Step::Open, ip("2001:db8:1:3::1")));

        assert!(limit.allows(Step::Open, ip("192.0.2.7")));
        assert!(limit.allows(Step::Open, ip("::ffff:192.0.2.7")));
        assert!(!limit.allows(Step::Open, ip("192.0.2.7")));
        assert!(limit.allows(Step::Open, ip("192.0.2.8")));
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

        /// Gives the browser a target-host session for the target in the
        /// query, on [`HOST`], under an open user session.
        #[handler]
        async fn seed_bound(req: &Request, session: &Session) {
            let ctx = req.data::<UnauthenticatedRequestContext>().unwrap();
            let target_id = query_value(req, "target").unwrap().parse().unwrap();
            let user_id = Uuid::new_v4();
            let user_session_id = UserSessionId(Uuid::new_v4());
            warpgate_db_entities::UserSession::ActiveModel {
                id: Set(user_session_id),
                username: Set(Some("user".into())),
                user_id: Set(Some(user_id)),
                remote_address: Set("127.0.0.1:443".into()),
                started: Set(OffsetDateTime::now_utc()),
                ended: Set(None),
                protocol: Set("HTTP".into()),
                node_id: Set(None),
                auth_state_node_id: Set(None),
            }
            .insert(&ctx.services().db)
            .await
            .unwrap();
            session.set(SESSION_ID_SESSION_KEY, user_session_id);
            session.set_bound_auth(BoundSessionAuthorization {
                user_id,
                username: "user".into(),
                target_id,
                hostname: HOST.into(),
            });
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
                .at("/seed-bound", get(seed_bound))
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
                resp.assert_header(
                    "location",
                    format!("https://{HOST}/?{HANDOFF_RETRY_PARAM}=1"),
                );
                assert!(!clears_the_nonce(&resp), "{path}");
                assert!(stored(&db, &cookie).await, "{path} dropped the session");
            }
        }

        /// Past its rate limit a source address gets a plain 429 from the
        /// redeem route, which then spends and changes nothing.
        #[tokio::test]
        async fn redeem_past_the_rate_limit_is_refused() {
            let db = memory_db().await;
            let target = bound_target(&db).await;
            let limit = Arc::new(RateLimit::per_minute(NonZeroU32::new(1).unwrap()));
            let cli = TestClient::new(app(db.clone()).await.data(limit));
            let path = format!("/@warpgate{REDEEM_PATH}?{HANDOFF_TOKEN_PARAM}=junk");
            let resp = cli.get(&path).header("host", HOST).send().await;
            resp.assert_status(StatusCode::SEE_OTHER);

            let token = token_for(&db, target, "/page").await;
            let resp = cli
                .get(format!(
                    "/@warpgate{REDEEM_PATH}?{HANDOFF_TOKEN_PARAM}={token}"
                ))
                .header("host", HOST)
                .send()
                .await;
            resp.assert_status(StatusCode::TOO_MANY_REQUESTS);
            resp.assert_header("cache-control", "no-store");
            assert!(!clears_the_nonce(&resp));
            assert_eq!(
                HttpHandoff::count(&db).await.unwrap(),
                1,
                "a refused redeem spent the handoff"
            );
        }

        /// A junk token in a browser already signed in on this host for its
        /// target sends it back to the page with no retry marker: there is
        /// nothing to retry, and the marker would reach the target and the
        /// browser's history.
        #[tokio::test]
        async fn an_unknown_token_with_a_session_here_goes_back_unmarked() {
            let db = memory_db().await;
            let target = bound_target(&db).await;
            let cli = TestClient::new(app(db.clone()).await);
            let cookie = session_cookie(
                &cli.get(format!("/seed-bound?target={target}"))
                    .header("host", HOST)
                    .send()
                    .await,
            );

            let resp = cli
                .get(format!(
                    "/@warpgate{REDEEM_PATH}?{HANDOFF_TOKEN_PARAM}=junk"
                ))
                .header("host", HOST)
                .header("cookie", &cookie)
                .send()
                .await;
            resp.assert_status(StatusCode::SEE_OTHER);
            resp.assert_header("location", format!("https://{HOST}/"));
            assert!(stored(&db, &cookie).await, "the session was dropped");

            // A session for another target counts for nothing here.
            let other = Uuid::new_v4();
            let cookie = session_cookie(
                &cli.get(format!("/seed-bound?target={other}"))
                    .header("host", HOST)
                    .send()
                    .await,
            );
            let resp = cli
                .get(format!(
                    "/@warpgate{REDEEM_PATH}?{HANDOFF_TOKEN_PARAM}=junk"
                ))
                .header("host", HOST)
                .header("cookie", &cookie)
                .send()
                .await;
            resp.assert_header(
                "location",
                format!("https://{HOST}/?{HANDOFF_RETRY_PARAM}=1"),
            );
        }

        /// A real token redeemed without its nonce (another tab's handoff
        /// replaced the cookie, or another site sent the browser here with a
        /// token of its own) is spent: it is never accepted again, not even
        /// with its nonce. The browser session here is kept, and the browser
        /// is sent back to the page to open a new handoff.
        #[tokio::test]
        async fn a_token_without_its_nonce_is_spent_and_keeps_the_browser_session() {
            let db = memory_db().await;
            let target = bound_target(&db).await;
            let cli = TestClient::new(app(db.clone()).await);
            let cookie = session_cookie(&cli.get("/seed").header("host", HOST).send().await);
            assert!(stored(&db, &cookie).await);
            let now = OffsetDateTime::now_utc();
            let opened = open(&db, target, HOST, "/page?x=1", now)
                .await
                .unwrap()
                .unwrap();
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
            let redeem = format!("/@warpgate{REDEEM_PATH}?{HANDOFF_TOKEN_PARAM}={token}");

            let resp = cli
                .get(&redeem)
                .header("host", HOST)
                .header("cookie", format!("{cookie}; {HANDOFF_COOKIE_NAME}=other"))
                .send()
                .await;
            resp.assert_status(StatusCode::SEE_OTHER);
            resp.assert_header(
                "location",
                format!("https://{HOST}/page?x=1&{HANDOFF_RETRY_PARAM}=1"),
            );
            assert!(clears_the_nonce(&resp));
            assert!(
                stored(&db, &cookie).await,
                "the browser session was dropped"
            );

            // Spent: with its own nonce it is now an unknown token.
            let resp = cli
                .get(&redeem)
                .header("host", HOST)
                .header(
                    "cookie",
                    format!("{cookie}; {HANDOFF_COOKIE_NAME}={}", opened.nonce),
                )
                .send()
                .await;
            resp.assert_status(StatusCode::SEE_OTHER);
            resp.assert_header(
                "location",
                format!("https://{HOST}/?{HANDOFF_RETRY_PARAM}=1"),
            );
            assert!(!clears_the_nonce(&resp));
            assert!(
                stored(&db, &cookie).await,
                "the browser session was dropped"
            );
        }

        /// A browser already signed in here for this target, sent here with
        /// someone else's token, keeps its session and goes back to the page
        /// unmarked.
        #[tokio::test]
        async fn a_signed_in_browser_given_a_foreign_token_stays_signed_in() {
            let db = memory_db().await;
            let target = bound_target(&db).await;
            let cli = TestClient::new(app(db.clone()).await);
            let cookie = session_cookie(
                &cli.get(format!("/seed-bound?target={target}"))
                    .header("host", HOST)
                    .send()
                    .await,
            );
            let token = token_for(&db, target, "/page?x=1").await;

            let resp = cli
                .get(format!(
                    "/@warpgate{REDEEM_PATH}?{HANDOFF_TOKEN_PARAM}={token}"
                ))
                .header("host", HOST)
                .header("cookie", &cookie)
                .send()
                .await;
            resp.assert_status(StatusCode::SEE_OTHER);
            resp.assert_header("location", format!("https://{HOST}/page?x=1"));
            assert!(
                stored(&db, &cookie).await,
                "the browser session was dropped"
            );
        }

        /// A token minted for another host is refused and spent, and the
        /// browser session here stays: any site can mint one for its own
        /// target and send a browser here with it.
        #[tokio::test]
        async fn a_token_for_another_host_is_spent_and_keeps_the_browser_session() {
            let db = memory_db().await;
            let target = bound_target(&db).await;
            let cli = TestClient::new(app(db.clone()).await);
            let cookie = session_cookie(
                &cli.get(format!("/seed-bound?target={target}"))
                    .header("host", HOST)
                    .send()
                    .await,
            );
            let now = OffsetDateTime::now_utc();
            let opened = open(&db, Uuid::new_v4(), "other.example.com", "/", now)
                .await
                .unwrap()
                .unwrap();
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
            let redeem = format!("/@warpgate{REDEEM_PATH}?{HANDOFF_TOKEN_PARAM}={token}");

            let resp = cli
                .get(&redeem)
                .header("host", HOST)
                .header(
                    "cookie",
                    format!("{cookie}; {HANDOFF_COOKIE_NAME}={}", opened.nonce),
                )
                .send()
                .await;
            resp.assert_status(StatusCode::SEE_OTHER);
            assert!(clears_the_nonce(&resp), "the token was not spent");
            assert!(
                stored(&db, &cookie).await,
                "the browser session was dropped"
            );
            assert_eq!(
                HttpHandoff::take(&db, &hash_secret(&token), now)
                    .await
                    .unwrap(),
                None,
                "the token is still there"
            );
        }

        /// Mints a token for a handoff opened for `next`.
        async fn token_for(db: &DatabaseConnection, target: Uuid, next: &str) -> String {
            let now = OffsetDateTime::now_utc();
            let opened = open(db, target, HOST, next, now).await.unwrap().unwrap();
            mint(
                db,
                &opened.challenge,
                Uuid::new_v4(),
                Uuid::new_v4(),
                None,
                now,
            )
            .await
            .unwrap()
            .unwrap()
        }

        /// A browser that keeps no cookie for this host never holds the
        /// nonce: its first refusal retries once, marked, and the refusal of
        /// that retry is a 403 saying sign-in needs cookies, not another
        /// round.
        #[tokio::test]
        async fn a_browser_without_cookies_retries_once_then_is_told_why() {
            let db = memory_db().await;
            let target = bound_target(&db).await;
            let cli = TestClient::new(app(db.clone()).await);

            let token = token_for(&db, target, "/page").await;
            let resp = cli
                .get(format!(
                    "/@warpgate{REDEEM_PATH}?{HANDOFF_TOKEN_PARAM}={token}"
                ))
                .header("host", HOST)
                .send()
                .await;
            resp.assert_status(StatusCode::SEE_OTHER);
            let retried = format!("/page?{HANDOFF_RETRY_PARAM}=1");
            resp.assert_header("location", format!("https://{HOST}{retried}"));

            // The retried page opens a handoff for itself, marker included.
            let token = token_for(&db, target, &retried).await;
            let resp = cli
                .get(format!(
                    "/@warpgate{REDEEM_PATH}?{HANDOFF_TOKEN_PARAM}={token}"
                ))
                .header("host", HOST)
                .send()
                .await;
            resp.assert_status(StatusCode::FORBIDDEN);
            assert!(resp.0.headers().get("location").is_none());
            resp.assert_text(COOKIES_NEEDED).await;
        }

        mod step_up {
            //! The start route on the control-plane host with step-up on, and
            //! the stamp the redeemed session carries.
            use std::time::Duration;

            use poem::{Endpoint, IntoResponse};
            use warpgate_common::StepUpIntervalConfig;
            use warpgate_common_http::SessionAuthorization;
            use warpgate_db_entities::{Role, TargetRoleAssignment, UserRoleAssignment};

            use super::*;
            use crate::common::{SessionExt, session_id_for_login};
            use crate::test_db::insert_user;

            const CONTROL_PLANE: &str = "warp.example";
            /// The user a ticket in these tests was issued to.
            const TICKET_USER: Uuid = Uuid::from_u128(7);

            /// Signs the browser in on the control plane as `user`, with its
            /// last sign-in at the unix time `stamp`.
            #[handler]
            async fn sign_in(req: &Request, session: &Session) -> poem::Result<()> {
                let ctx =
                    Data::<&UnauthenticatedRequestContext>::from_request_without_body(req).await?;
                session_id_for_login(req, &ctx)
                    .await
                    .map_err(poem::error::InternalServerError)?;
                let user_id: Uuid = query_value(req, "user").unwrap().parse().unwrap();
                // As a completed sign-in does, the user session is the user's
                // in the store too, so another node can take it up.
                let store =
                    Data::<&Arc<Mutex<SessionStore>>>::from_request_without_body(req).await?;
                let handle = store.lock().await.handle_for_login(req, &ctx).await?;
                handle
                    .lock()
                    .await
                    .set_user_info(warpgate_common::auth::AuthStateUserInfo {
                        id: user_id,
                        username: format!("user-{user_id}"),
                    })
                    .await
                    .map_err(poem::error::InternalServerError)?;
                let stamp: i64 = query_value(req, "stamp").unwrap().parse().unwrap();
                session.set_auth(SessionAuthorization::User {
                    user_id,
                    username: format!("user-{user_id}"),
                });
                // As the SSO return stamps a completed sign-in.
                crate::step_up::stamp_sso(
                    session,
                    &ctx.services().db,
                    OffsetDateTime::from_unix_timestamp(stamp).unwrap(),
                )
                .await
                .map_err(poem::error::InternalServerError)?;
                Ok(())
            }

            /// A page proxied on a bound host: whether the browser session
            /// counts there.
            #[handler]
            fn page(req: &Request) -> &'static str {
                if req
                    .data::<warpgate_common_http::auth::AuthenticatedRequestContext>()
                    .is_some()
                {
                    "auth"
                } else {
                    "anon"
                }
            }

            /// A page proxied on a bound host: the identity headers the proxy
            /// sends its target, as `username/type` (`-` for one not sent).
            #[handler]
            async fn upstream(req: &Request) -> String {
                let headers = crate::proxy::upstream_headers_for_test(req).await;
                let header = |name: &str| {
                    headers
                        .get(name)
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or("-")
                        .to_owned()
                };
                format!(
                    "{}/{}",
                    header("x-warpgate-username"),
                    header("x-warpgate-authentication-type")
                )
            }

            /// Signs the browser out, as the control plane's sign-out does.
            #[handler]
            async fn sign_out(req: &Request, session: &Session) -> poem::Result<()> {
                let ctx =
                    Data::<&UnauthenticatedRequestContext>::from_request_without_body(req).await?;
                let store =
                    Data::<&Arc<Mutex<SessionStore>>>::from_request_without_body(req).await?;
                crate::api::common::logout(session, store.0, &ctx.services().db).await;
                Ok(())
            }

            /// The browser session's last sign-in, as a unix time.
            #[handler]
            fn stamp_page(session: &Session) -> String {
                session
                    .get_last_sso_at()
                    .map(|at| at.unix_timestamp().to_string())
                    .unwrap_or_default()
            }

            async fn app(db: DatabaseConnection) -> impl poem::Endpoint {
                app_with(db, |_| {}).await
            }

            /// [`app`] with the control plane at [`CONTROL_PLANE`]
            /// (`external_host`), as the begin route needs, trusting
            /// `X-Forwarded-*` headers if `trust_forwarded`.
            async fn begin_app(
                db: DatabaseConnection,
                trust_forwarded: bool,
            ) -> impl poem::Endpoint {
                app_with(db, move |store| {
                    store.external_host = Some(CONTROL_PLANE.into());
                    store.http.trust_x_forwarded_headers = trust_forwarded;
                })
                .await
            }

            async fn app_with(
                db: DatabaseConnection,
                configure: impl FnOnce(&mut warpgate_common::WarpgateConfigStore),
            ) -> impl poem::Endpoint {
                let services = services(db.clone()).await;
                {
                    let mut config = services.config.lock().await;
                    config.store.step_up_interval = Some(StepUpIntervalConfig {
                        http: Some(Duration::from_secs(60)),
                        ..Default::default()
                    });
                    configure(&mut config.store);
                }
                let ctx = UnauthenticatedRequestContext::new(services).await;
                // The start route behind what the auth middleware gives a
                // signed-in browser: the user in `x-test-user`, and none
                // without it.
                let start = get(start_endpoint).around(|ep, mut req| async move {
                    if let Some(user_id) = req.header("x-test-user") {
                        let user_id: Uuid = user_id.parse().unwrap();
                        let actx = req
                            .data::<UnauthenticatedRequestContext>()
                            .unwrap()
                            .to_authenticated(RequestAuthorization::Session(
                                SessionAuthorization::User {
                                    user_id,
                                    username: format!("user-{user_id}"),
                                },
                            ));
                        req.extensions_mut().insert(actx);
                    }
                    ep.call(req).await.map(IntoResponse::into_response)
                });
                Route::new()
                    .at("/sign-in", get(sign_in))
                    .at("/stamp", get(stamp_page))
                    .at("/sign-out", poem::post(sign_out))
                    .at(
                        "/page",
                        get(page).around(crate::common::inject_request_authorization),
                    )
                    .at(
                        "/upstream",
                        get(upstream).around(crate::common::inject_request_authorization),
                    )
                    // A proxied page wrapped as the catchall is in production
                    // (`lib.rs`): the public-target bypass, then the auth gate.
                    .at(
                        "/gated-upstream",
                        crate::common::page_auth(upstream)
                            .around(crate::common::inject_request_authorization),
                    )
                    // The same, for a browser holding a ticket in `x-test-ticket`
                    // (the target id it was issued for), as `TicketMiddleware`
                    // leaves a header ticket: on a temporary session of its own.
                    .at(
                        "/ticket-gated-upstream",
                        crate::common::page_auth(upstream)
                            .around(crate::common::inject_request_authorization)
                            .around(|ep, mut req| async move {
                                let target_id: Uuid =
                                    req.header("x-test-ticket").unwrap().parse().unwrap();
                                let session = Session::default();
                                session.set_auth(SessionAuthorization::Ticket {
                                    user_id: TICKET_USER,
                                    username: "ticket-user".into(),
                                    target_id,
                                    ticket_id: Some(Uuid::new_v4()),
                                });
                                req.extensions_mut().insert(session);
                                req.set_data(crate::middleware::ticket::TemporaryTicketSession);
                                ep.call(req).await.map(IntoResponse::into_response)
                            }),
                    )
                    .at(format!("/@warpgate{BEGIN_PATH}"), get(begin_endpoint))
                    .at(format!("/@warpgate{START_PATH}"), start)
                    .at(format!("/@warpgate{REDEEM_PATH}"), get(redeem_endpoint))
                    .data(SessionStore::new())
                    .data(SharedSessionStorage::new(db.clone()))
                    .data(ctx)
                    .with(ServerSession::new(
                        session_cookie_config(),
                        SharedSessionStorage::new(db),
                    ))
                    // `TestClient` leaves `original_uri` at `/`; a served
                    // request carries its own, which the login redirect's
                    // `next` is built from. Scheme and addresses stay the
                    // `TestClient` defaults.
                    .around(|ep, req| async move {
                        let (parts, body) = req.into_parts();
                        let mut served = poem::http::Request::builder()
                            .method(parts.method)
                            .uri(parts.uri)
                            .version(parts.version)
                            .body(())
                            .unwrap();
                        *served.headers_mut() = parts.headers;
                        *served.extensions_mut() = parts.extensions;
                        let (served, ()) = served.into_parts();
                        let req = Request::from_parts(
                            poem::RequestParts::from((
                                served,
                                poem::web::LocalAddr::default(),
                                poem::web::RemoteAddr::default(),
                                poem::http::uri::Scheme::HTTP,
                            )),
                            body,
                        );
                        ep.call(req).await.map(IntoResponse::into_response)
                    })
            }

            /// A user with a role granting `target`.
            async fn user_for(db: &DatabaseConnection, target: Uuid) -> Uuid {
                user_for_targets(db, &[target]).await
            }

            /// A user with a role granting each of `targets`.
            async fn user_for_targets(db: &DatabaseConnection, targets: &[Uuid]) -> Uuid {
                let user_id = Uuid::new_v4();
                insert_user(db, user_id, &format!("user-{user_id}")).await;
                let role_id = Uuid::new_v4();
                Role::ActiveModel {
                    id: Set(role_id),
                    name: Set(format!("role-{role_id}")),
                    description: Set(String::new()),
                    is_default: Set(false),
                }
                .insert(db)
                .await
                .unwrap();
                UserRoleAssignment::ActiveModel {
                    user_id: Set(user_id),
                    role_id: Set(role_id),
                    granted_at: Set(Some(OffsetDateTime::now_utc())),
                    expires_at: Set(None),
                    revoked_at: Set(None),
                }
                .insert(db)
                .await
                .unwrap();
                for target in targets {
                    TargetRoleAssignment::ActiveModel {
                        target_id: Set(*target),
                        role_id: Set(role_id),
                    }
                    .insert(db)
                    .await
                    .unwrap();
                }
                user_id
            }

            /// Signs in on the control plane `ago` seconds back and opens a
            /// handoff for `/page`: the control-plane cookie, the handoff and
            /// the stamp.
            async fn signed_in(
                cli: &TestClient<impl poem::Endpoint>,
                db: &DatabaseConnection,
                target: Uuid,
                user: Uuid,
                ago: i64,
            ) -> (String, Opened, i64) {
                let stamp = OffsetDateTime::now_utc().unix_timestamp() - ago;
                let resp = cli
                    .get(format!("/sign-in?user={user}&stamp={stamp}"))
                    .header("host", CONTROL_PLANE)
                    .send()
                    .await;
                resp.assert_status_is_ok();
                let cookie = session_cookie(&resp);
                let opened = open(db, target, HOST, "/page", OffsetDateTime::now_utc())
                    .await
                    .unwrap()
                    .unwrap();
                (cookie, opened, stamp)
            }

            async fn start(
                cli: &TestClient<impl poem::Endpoint>,
                cookie: &str,
                user: Uuid,
                challenge: &str,
            ) -> TestResponse {
                cli.get(format!(
                    "/@warpgate{START_PATH}?{HANDOFF_CHALLENGE_PARAM}={challenge}"
                ))
                .header("host", CONTROL_PLANE)
                .header("accept", "text/html")
                .header("cookie", cookie)
                .header("x-test-user", user.to_string())
                .send()
                .await
            }

            /// A control-plane sign-in older than the step-up interval mints
            /// nothing: the browser is sent to sign in again, and the handoff
            /// can still be minted once.
            #[tokio::test]
            async fn a_stale_sign_in_is_sent_to_sign_in_and_mints_nothing() {
                let db = memory_db().await;
                let target = bound_target(&db).await;
                let user = user_for(&db, target).await;
                let cli = TestClient::new(app(db.clone()).await);
                let (cookie, opened, _) = signed_in(&cli, &db, target, user, 3600).await;

                let resp = start(&cli, &cookie, user, &opened.challenge).await;
                let location = resp
                    .0
                    .headers()
                    .get("location")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default()
                    .to_owned();
                assert!(location.starts_with("/@warpgate#/login"), "{location}");
                assert!(!location.contains(HANDOFF_TOKEN_PARAM), "{location}");
                let now = OffsetDateTime::now_utc();
                let minted = mint(&db, &opened.challenge, user, Uuid::new_v4(), None, now)
                    .await
                    .unwrap();
                assert!(minted.is_some(), "the stale start minted a token");
            }

            /// A fresh control-plane sign-in mints a token, and the session
            /// the bound host redeems it into carries that sign-in's stamp.
            #[tokio::test]
            async fn a_fresh_sign_in_is_redeemed_with_its_stamp() {
                let db = memory_db().await;
                let target = bound_target(&db).await;
                let user = user_for(&db, target).await;
                let cli = TestClient::new(app(db.clone()).await);
                let (cookie, opened, stamp) = signed_in(&cli, &db, target, user, 10).await;

                let resp = start(&cli, &cookie, user, &opened.challenge).await;
                resp.assert_status(StatusCode::SEE_OTHER);
                let location = resp.0.headers()["location"].to_str().unwrap().to_owned();
                let redeem = location
                    .strip_prefix(&format!("https://{HOST}"))
                    .expect("sent to the bound host")
                    .to_owned();
                let resp = cli
                    .get(&redeem)
                    .header("host", HOST)
                    .header("cookie", format!("{HANDOFF_COOKIE_NAME}={}", opened.nonce))
                    .send()
                    .await;
                resp.assert_status(StatusCode::SEE_OTHER);
                resp.assert_header("location", format!("https://{HOST}/page"));
                let bound = session_cookie(&resp);

                let resp = cli
                    .get("/stamp")
                    .header("host", HOST)
                    .header("cookie", &bound)
                    .send()
                    .await;
                resp.assert_text(stamp.to_string()).await;
            }

            /// The same through the cookie gate, mounted outside the session
            /// middleware as `lib.rs` mounts it: the redeem response gives
            /// the browser the bound host's session cookie beside the
            /// removal of the nonce cookie, and that cookie is served there.
            #[tokio::test]
            async fn a_redeem_through_the_cookie_gate_sets_the_session_cookie() {
                use crate::common::HOST_SESSION_COOKIE_NAME;
                use crate::middleware::CookieGateMiddleware;

                /// The `name=value` pair of the `name` cookie `resp` sets.
                fn pair_set(resp: &TestResponse, name: &str) -> Option<String> {
                    set_cookies(resp)
                        .into_iter()
                        .find(|pair| pair.starts_with(&format!("{name}=")))
                }

                let db = memory_db().await;
                let target = bound_target(&db).await;
                let user = user_for(&db, target).await;
                let ctx = UnauthenticatedRequestContext::new(services(db.clone()).await).await;
                let cli = TestClient::new(
                    app(db.clone())
                        .await
                        .with(CookieGateMiddleware::new(false, None))
                        .data(ctx),
                );

                let stamp = OffsetDateTime::now_utc().unix_timestamp() - 10;
                let resp = cli
                    .get(format!("/sign-in?user={user}&stamp={stamp}"))
                    .header("host", CONTROL_PLANE)
                    .send()
                    .await;
                resp.assert_status_is_ok();
                let control = pair_set(&resp, HOST_SESSION_COOKIE_NAME)
                    .expect("a session cookie on the control plane");
                let opened = open(&db, target, HOST, "/page", OffsetDateTime::now_utc())
                    .await
                    .unwrap()
                    .unwrap();

                let resp = start(&cli, &control, user, &opened.challenge).await;
                resp.assert_status(StatusCode::SEE_OTHER);
                let location = resp.0.headers()["location"].to_str().unwrap().to_owned();
                let redeem = location
                    .strip_prefix(&format!("https://{HOST}"))
                    .expect("sent to the bound host")
                    .to_owned();
                let resp = cli
                    .get(&redeem)
                    .header("host", HOST)
                    .header("cookie", format!("{HANDOFF_COOKIE_NAME}={}", opened.nonce))
                    .send()
                    .await;
                resp.assert_status(StatusCode::SEE_OTHER);
                resp.assert_header("location", format!("https://{HOST}/page"));
                assert!(clears_the_nonce(&resp), "{:?}", set_cookies(&resp));
                let bound = pair_set(&resp, HOST_SESSION_COOKIE_NAME)
                    .unwrap_or_else(|| panic!("no session cookie in {:?}", set_cookies(&resp)));
                assert_ne!(bound, control);

                let resp = cli
                    .get("/stamp")
                    .header("host", HOST)
                    .header("cookie", &bound)
                    .send()
                    .await;
                resp.assert_text(stamp.to_string()).await;
            }

            /// A handoff that expired while the browser signed in is refused
            /// with a body telling the user to open the page again, and
            /// nothing is minted.
            #[tokio::test]
            async fn a_sign_in_slower_than_the_handoff_is_told_to_reopen_the_page() {
                let db = memory_db().await;
                let target = bound_target(&db).await;
                let user = user_for(&db, target).await;
                let cli = TestClient::new(app(db.clone()).await);
                let (cookie, _, _) = signed_in(&cli, &db, target, user, 10).await;
                let long_ago =
                    OffsetDateTime::now_utc() - OPEN_LIFETIME - time::Duration::seconds(1);
                let opened = open(&db, target, HOST, "/page", long_ago)
                    .await
                    .unwrap()
                    .unwrap();

                let resp = start(&cli, &cookie, user, &opened.challenge).await;
                resp.assert_status(StatusCode::FORBIDDEN);
                resp.assert_header("cache-control", "no-store");
                resp.assert_content_type("text/plain; charset=utf-8");
                resp.assert_text(SIGN_IN_TOO_SLOW).await;
            }

            /// Signs in, opens a handoff and mints its token: the path of the
            /// redeem the browser is sent to, and the handoff's nonce.
            async fn minted_redeem(
                cli: &TestClient<impl poem::Endpoint>,
                db: &DatabaseConnection,
                target: Uuid,
                user: Uuid,
            ) -> (String, String, String) {
                let (cookie, opened, _) = signed_in(cli, db, target, user, 10).await;
                let resp = start(cli, &cookie, user, &opened.challenge).await;
                resp.assert_status(StatusCode::SEE_OTHER);
                let location = resp.0.headers()["location"].to_str().unwrap().to_owned();
                let redeem = location
                    .strip_prefix(&format!("https://{HOST}"))
                    .expect("sent to the bound host")
                    .to_owned();
                (cookie, redeem, opened.nonce)
            }

            /// Redeems `redeem` on [`HOST`] with its nonce and asserts the
            /// refusal stored no target-host session: no stored browser
            /// session holds a bound authorization, and the response gives
            /// the browser no session cookie.
            async fn assert_refused_and_nothing_stored(
                cli: &TestClient<impl poem::Endpoint>,
                db: &DatabaseConnection,
                redeem: &str,
                nonce: &str,
            ) {
                let resp = cli
                    .get(redeem)
                    .header("host", HOST)
                    .header("cookie", format!("{HANDOFF_COOKIE_NAME}={nonce}"))
                    .send()
                    .await;
                let session_value = resp
                    .0
                    .headers()
                    .get_all("set-cookie")
                    .iter()
                    .filter_map(|value| value.to_str().ok())
                    .filter_map(|value| value.split(';').next())
                    .find_map(|pair| pair.strip_prefix(&format!("{SESSION_COOKIE_NAME}=")))
                    .map(ToOwned::to_owned);
                assert!(
                    session_value.as_deref().is_none_or(str::is_empty),
                    "the refusal gave the browser a session: {session_value:?}"
                );
                let rows = HttpSession::Entity::find().all(db).await.unwrap();
                assert!(
                    rows.iter()
                        .all(|row| !row.data.contains(crate::common::BOUND_AUTH_SESSION_KEY)),
                    "a bound authorization is stored after the refusal"
                );
                resp.assert_status(StatusCode::SEE_OTHER);
                resp.assert_header(
                    "location",
                    format!("https://{HOST}/page?{HANDOFF_RETRY_PARAM}=1"),
                );
            }

            /// A user who loses the target between mint and redeem gets no
            /// session on its host: the refusal stores nothing.
            #[tokio::test]
            async fn a_redeem_refused_for_target_access_stores_no_session() {
                let db = memory_db().await;
                let target = bound_target(&db).await;
                let user = user_for(&db, target).await;
                let cli = TestClient::new(app(db.clone()).await);
                let (_, redeem, nonce) = minted_redeem(&cli, &db, target, user).await;

                TargetRoleAssignment::Entity::delete_many()
                    .exec(&db)
                    .await
                    .unwrap();

                assert_refused_and_nothing_stored(&cli, &db, &redeem, &nonce).await;
            }

            /// A user who signs out on the control plane between mint and
            /// redeem gets no session on the target's host: the refusal
            /// stores nothing. (The session store's own purge of a cookie
            /// naming an ended session covers this case too.)
            #[tokio::test]
            async fn a_redeem_refused_for_an_ended_user_session_stores_no_session() {
                let db = memory_db().await;
                let target = bound_target(&db).await;
                let user = user_for(&db, target).await;
                let cli = TestClient::new(app(db.clone()).await);
                let (control, redeem, nonce) = minted_redeem(&cli, &db, target, user).await;

                cli.post("/sign-out")
                    .header("host", CONTROL_PLANE)
                    .header("cookie", &control)
                    .send()
                    .await
                    .assert_status_is_ok();

                assert_refused_and_nothing_stored(&cli, &db, &redeem, &nonce).await;
            }

            /// A user session that is now another user's, checked on a node
            /// that has not seen it, is refused without the purge the session
            /// store does for an ended one: the redeem's own purge is what
            /// leaves nothing stored.
            #[tokio::test]
            async fn a_redeem_refused_for_another_user_s_session_stores_no_session() {
                use sea_orm::IntoActiveModel;

                let db = memory_db().await;
                let target = bound_target(&db).await;
                let user = user_for(&db, target).await;
                let node_a = TestClient::new(app(db.clone()).await);
                let node_b = TestClient::new(app(db.clone()).await);
                let (control, redeem, nonce) = minted_redeem(&node_a, &db, target, user).await;

                let (_, storage_id) = control.split_once('=').unwrap();
                let user_session_id = HttpSession::Entity::find_by_id(storage_id.to_owned())
                    .one(&db)
                    .await
                    .unwrap()
                    .and_then(|row| row.user_session_id)
                    .expect("the control-plane session names its user session");
                let mut row =
                    warpgate_db_entities::UserSession::Entity::find_by_id(user_session_id)
                        .one(&db)
                        .await
                        .unwrap()
                        .unwrap()
                        .into_active_model();
                row.user_id = Set(Some(Uuid::new_v4()));
                row.update(&db).await.unwrap();

                assert_refused_and_nothing_stored(&node_b, &db, &redeem, &nonce).await;
            }

            const OTHER_HOST: &str = "vm2.warp.example";

            /// A second HTTP target, bound to [`OTHER_HOST`].
            async fn other_bound_target(db: &DatabaseConnection) -> Uuid {
                let id = Uuid::new_v4();
                Target::ActiveModel {
                    id: Set(id),
                    name: Set(format!("target-{id}")),
                    description: Set(String::new()),
                    kind: Set(TargetKind::Http),
                    options: Set(serde_json::json!({
                        "http": {"url": "http://h2", "external_host": OTHER_HOST}
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

            /// Hands the control-plane sign-in in `cookie` off to `host`,
            /// bound to `target`: the session cookie it gets there.
            async fn hand_off(
                cli: &TestClient<impl poem::Endpoint>,
                db: &DatabaseConnection,
                cookie: &str,
                user: Uuid,
                target: Uuid,
                host: &str,
            ) -> String {
                let opened = open(db, target, host, "/page", OffsetDateTime::now_utc())
                    .await
                    .unwrap()
                    .unwrap();
                let resp = start(cli, cookie, user, &opened.challenge).await;
                resp.assert_status(StatusCode::SEE_OTHER);
                let location = resp.0.headers()["location"].to_str().unwrap().to_owned();
                let redeem = location
                    .strip_prefix(&format!("https://{host}"))
                    .expect("sent to the bound host")
                    .to_owned();
                let resp = cli
                    .get(&redeem)
                    .header("host", host)
                    .header("cookie", format!("{HANDOFF_COOKIE_NAME}={}", opened.nonce))
                    .send()
                    .await;
                resp.assert_status(StatusCode::SEE_OTHER);
                resp.assert_header("location", format!("https://{host}/page"));
                session_cookie(&resp)
            }

            async fn page_on(
                cli: &TestClient<impl poem::Endpoint>,
                host: &str,
                cookie: &str,
            ) -> String {
                let resp = cli
                    .get("/page")
                    .header("host", host)
                    .header("cookie", cookie)
                    .send()
                    .await;
                resp.assert_status_is_ok();
                resp.0.into_body().into_string().await.unwrap()
            }

            /// A request proxied on a bound host names the handed-off user to
            /// the target, as a user sign-in, exactly as on the control plane.
            #[tokio::test]
            async fn a_bound_host_request_names_its_user_upstream() {
                let db = memory_db().await;
                let target = bound_target(&db).await;
                let user = user_for(&db, target).await;
                let cli = TestClient::new(app(db.clone()).await);
                let (control, _, _) = signed_in(&cli, &db, target, user, 10).await;
                let bound = hand_off(&cli, &db, &control, user, target, HOST).await;

                let resp = cli
                    .get("/upstream")
                    .header("host", HOST)
                    .header("cookie", &bound)
                    .send()
                    .await;
                resp.assert_status_is_ok();
                resp.assert_text(format!("user-{user}/user")).await;
            }

            /// [`bound_target`], but `public: true`: as cove's own web target
            /// is, bound to a host of its own.
            async fn public_bound_target(db: &DatabaseConnection) -> Uuid {
                let id = Uuid::new_v4();
                Target::ActiveModel {
                    id: Set(id),
                    name: Set(format!("target-{id}")),
                    description: Set(String::new()),
                    kind: Set(TargetKind::Http),
                    options: Set(serde_json::json!({
                        "http": {"url": "http://h", "external_host": HOST, "public": true}
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

            /// `/gated-upstream` on `host`: the status and the identity the
            /// target was sent, `username/type`.
            async fn gated_on(
                cli: &TestClient<impl poem::Endpoint>,
                host: &str,
                cookie: Option<&str>,
            ) -> (StatusCode, String) {
                let mut req = cli
                    .get("/gated-upstream")
                    .header("host", host)
                    .header("accept", "text/html")
                    .header("sec-fetch-mode", "navigate");
                if let Some(cookie) = cookie {
                    req = req.header("cookie", cookie);
                }
                let resp = req.send().await;
                let status = resp.0.status();
                (status, resp.0.into_body().into_string().await.unwrap())
            }

            /// Control for the public case below: through the production
            /// wrapping, a handed-off browser on a non-public bound host is
            /// served as its user.
            #[tokio::test]
            async fn a_gated_bound_host_request_names_its_handed_off_user() {
                let db = memory_db().await;
                let target = bound_target(&db).await;
                let user = user_for(&db, target).await;
                let cli = TestClient::new(app(db.clone()).await);
                let (control, _, _) = signed_in(&cli, &db, target, user, 10).await;
                let bound = hand_off(&cli, &db, &control, user, target, HOST).await;

                let (status, seen) = gated_on(&cli, HOST, Some(&bound)).await;
                assert_eq!(status, StatusCode::OK, "{seen}");
                assert_eq!(seen, format!("user-{user}/user"));
            }

            /// An anonymous navigation on a public target's own host is served
            /// as `<public>` (no identity sent), not sent through a handoff:
            /// a sign-in there starts only at the begin route.
            #[tokio::test]
            async fn an_anonymous_public_bound_host_navigation_is_served_as_public() {
                let db = memory_db().await;
                public_bound_target(&db).await;
                let cli = TestClient::new(app(db.clone()).await);

                let (status, seen) = gated_on(&cli, HOST, None).await;
                assert_eq!(status, StatusCode::OK, "{seen}");
                assert_eq!(seen, "-/-");
            }

            /// A browser handed off to a public target's own host is served
            /// there as its user: the public-target bypass names the identity
            /// `inject_request_authorization` accepted from the target-host
            /// session (`common::onto_public_target_session`).
            #[tokio::test]
            async fn a_public_bound_host_request_names_its_handed_off_user() {
                let db = memory_db().await;
                let target = public_bound_target(&db).await;
                let user = user_for(&db, target).await;
                let cli = TestClient::new(app(db.clone()).await);
                let (control, _, _) = signed_in(&cli, &db, target, user, 10).await;
                let bound = hand_off(&cli, &db, &control, user, target, HOST).await;

                let (status, seen) = gated_on(&cli, HOST, Some(&bound)).await;
                assert_eq!(status, StatusCode::OK, "{seen}");
                assert!(
                    seen.starts_with(&format!("user-{user}/")),
                    "a handed-off browser on a public bound host was served as {seen:?}"
                );
            }

            /// The control-plane session, presented on a public target's own
            /// host (no cookie gate in this app), names no one there:
            /// `inject_request_authorization` drops it, and the public-target
            /// bypass does not read it back from the raw session.
            #[tokio::test]
            async fn a_control_plane_session_names_no_one_on_a_public_bound_host() {
                let db = memory_db().await;
                let target = public_bound_target(&db).await;
                let user = user_for(&db, target).await;
                let cli = TestClient::new(app(db.clone()).await);
                let (control, _, _) = signed_in(&cli, &db, target, user, 10).await;

                let (status, seen) = gated_on(&cli, HOST, Some(&control)).await;
                assert_eq!(status, StatusCode::OK, "{seen}");
                assert_eq!(seen, "-/-", "the control-plane session named its user");
            }

            /// A ticket for a public target, on its own host, names its user
            /// there (`ticket`); a ticket for another target names no one.
            #[tokio::test]
            async fn a_ticket_names_its_user_on_its_own_public_bound_host_only() {
                let db = memory_db().await;
                let target = public_bound_target(&db).await;
                let cli = TestClient::new(app(db.clone()).await);
                for (ticket_target, expected) in
                    [(target, "ticket-user/ticket"), (Uuid::new_v4(), "-/-")]
                {
                    let resp = cli
                        .get("/ticket-gated-upstream")
                        .header("host", HOST)
                        .header("accept", "text/html")
                        .header("sec-fetch-mode", "navigate")
                        .header("x-test-ticket", ticket_target.to_string())
                        .send()
                        .await;
                    resp.assert_status_is_ok();
                    resp.assert_text(expected).await;
                }
            }

            /// Every `Set-Cookie` of `resp`, as `name=value` pairs.
            fn set_cookies(resp: &TestResponse) -> Vec<String> {
                resp.0
                    .headers()
                    .get_all("set-cookie")
                    .iter()
                    .filter_map(|value| value.to_str().ok())
                    .filter_map(|value| value.split(';').next())
                    .map(ToOwned::to_owned)
                    .collect()
            }

            /// The value of the nonce cookie `resp` sets.
            fn nonce_set_by(resp: &TestResponse) -> String {
                set_cookies(resp)
                    .iter()
                    .find_map(|pair| pair.strip_prefix(&format!("{HANDOFF_COOKIE_NAME}=")))
                    .unwrap()
                    .to_owned()
            }

            /// `GET` the begin route on `host` for `next` (sent encoded as
            /// given), as a top-level navigation, with `headers`.
            async fn begin(
                cli: &TestClient<impl poem::Endpoint>,
                host: &str,
                next: Option<&str>,
                headers: &[(&str, &str)],
            ) -> TestResponse {
                let mut path = format!("/@warpgate{BEGIN_PATH}");
                if let Some(next) = next {
                    let query = url::form_urlencoded::Serializer::new(String::new())
                        .append_pair(BEGIN_NEXT_PARAM, next)
                        .finish();
                    path = format!("{path}?{query}");
                }
                let mut req = cli
                    .get(path)
                    .header("host", host)
                    .header("accept", "text/html")
                    .header("sec-fetch-mode", "navigate");
                for (name, value) in headers {
                    req = req.header(*name, *value);
                }
                req.send().await
            }

            /// The challenge in the control-plane start address `location`,
            /// which must be on the control-plane host.
            fn challenge_in(location: &str) -> String {
                let url = url::Url::parse(location).unwrap();
                assert_eq!(url.scheme(), "https", "{location}");
                assert_eq!(url.host_str(), Some(CONTROL_PLANE), "{location}");
                assert_eq!(url.path(), format!("/@warpgate{START_PATH}"), "{location}");
                url.query_pairs()
                    .find(|(key, _)| key == HANDOFF_CHALLENGE_PARAM)
                    .map(|(_, value)| value.into_owned())
                    .unwrap()
            }

            /// Begins on [`HOST`] for `next`: the challenge and the nonce.
            async fn begun(cli: &TestClient<impl poem::Endpoint>, next: &str) -> (String, String) {
                let resp = begin(cli, HOST, Some(next), &[]).await;
                resp.assert_status(StatusCode::SEE_OTHER);
                let location = resp.0.headers()["location"].to_str().unwrap().to_owned();
                (challenge_in(&location), nonce_set_by(&resp))
            }

            /// Mints the token for `challenge` signed in as `user`: the path
            /// of the redeem on [`HOST`].
            async fn redeem_for(
                cli: &TestClient<impl poem::Endpoint>,
                control: &str,
                user: Uuid,
                challenge: &str,
            ) -> String {
                let resp = start(cli, control, user, challenge).await;
                resp.assert_status(StatusCode::SEE_OTHER);
                let location = resp.0.headers()["location"].to_str().unwrap().to_owned();
                location
                    .strip_prefix(&format!("https://{HOST}"))
                    .unwrap()
                    .to_owned()
            }

            /// The begin route opens a handoff back to the target's configured
            /// host, whatever `Host` or `X-Forwarded-Host` the request
            /// carries: a forged header either still names the bound host,
            /// and the handoff returns to the configured one, or names
            /// another host, and nothing is begun.
            #[tokio::test]
            async fn begin_returns_to_the_configured_host_whatever_the_headers() {
                for trust_forwarded in [false, true] {
                    let db = memory_db().await;
                    let target = public_bound_target(&db).await;
                    let cli = TestClient::new(begin_app(db.clone(), trust_forwarded).await);

                    let cases: Vec<(&str, Vec<(&str, &str)>)> = if trust_forwarded {
                        // A trusted X-Forwarded-Host picks the bound host; the
                        // request's Host never reaches the handoff.
                        vec![("evil.example", vec![("x-forwarded-host", HOST)])]
                    } else {
                        vec![
                            (HOST, vec![("x-forwarded-host", "evil.example")]),
                            (
                                HOST,
                                vec![("x-forwarded-host", "vm1.warp.example.evil.example")],
                            ),
                        ]
                    };
                    for (host, headers) in cases {
                        let resp = begin(&cli, host, Some("/page?x=1"), &headers).await;
                        resp.assert_status(StatusCode::SEE_OTHER);
                        let location = resp.0.headers()["location"].to_str().unwrap().to_owned();
                        assert!(!location.contains("evil"), "{location}");
                        let challenge = challenge_in(&location);
                        let row = opened(&db, &challenge, OffsetDateTime::now_utc())
                            .await
                            .unwrap()
                            .unwrap();
                        assert_eq!(row.hostname, HOST);
                        assert_eq!(row.target_id, target);
                        assert_eq!(row.next, "/page?x=1");
                    }

                    // A Host (or trusted X-Forwarded-Host) naming no bound
                    // host begins nothing.
                    let forged: &[(&str, &[(&str, &str)])] = if trust_forwarded {
                        &[(HOST, &[("x-forwarded-host", "evil.example")])]
                    } else {
                        &[
                            ("evil.example", &[("x-forwarded-host", HOST)]),
                            (CONTROL_PLANE, &[]),
                        ]
                    };
                    for (host, headers) in forged {
                        let resp = begin(&cli, host, Some("/page"), headers).await;
                        resp.assert_status(StatusCode::NOT_FOUND);
                        assert!(set_cookies(&resp).is_empty(), "{host} {headers:?}");
                    }
                    assert_eq!(
                        HttpHandoff::Entity::find().all(&db).await.unwrap().len(),
                        if trust_forwarded { 1 } else { 2 },
                        "trust_forwarded: {trust_forwarded}"
                    );
                }
            }

            /// The begin route takes only a `next` that is site-relative once
            /// decoded ([`is_safe_redirect_target`]): any other, or none, is
            /// refused and opens nothing. Not a navigation, it is refused too.
            #[tokio::test]
            async fn begin_refuses_a_next_that_is_not_site_relative() {
                let db = memory_db().await;
                public_bound_target(&db).await;
                let cli = TestClient::new(begin_app(db.clone(), false).await);
                for next in [
                    None,
                    Some(""),
                    Some("page"),
                    Some("//evil.example/"),
                    Some("/\\evil.example/"),
                    Some("/a\\b"),
                    Some("/%2f/evil.example/"),
                    Some("/%2F/evil.example/"),
                    Some("%2F%2Fevil.example/"),
                    Some("/%5cevil.example/"),
                    Some("/%5C/evil.example/"),
                    Some("/%252f/evil.example/"),
                    Some("/%255c/evil.example/"),
                    Some("/@evil.example/"),
                    Some("/x@evil.example/"),
                    Some("/%40evil.example/"),
                    Some("https://evil.example/"),
                    Some("javascript:alert(1)"),
                    Some("/a\nb"),
                    Some("/a\tb"),
                    Some("/%0a"),
                    Some("/%250a"),
                ] {
                    let resp = begin(&cli, HOST, next, &[]).await;
                    resp.assert_status(StatusCode::BAD_REQUEST);
                    assert!(set_cookies(&resp).is_empty(), "{next:?}");
                }

                // A fetch, not a navigation.
                let resp = cli
                    .get(format!("/@warpgate{BEGIN_PATH}?{BEGIN_NEXT_PARAM}=%2Fpage"))
                    .header("host", HOST)
                    .send()
                    .await;
                resp.assert_status(StatusCode::FORBIDDEN);
                assert_eq!(set_cookies(&resp), Vec::<String>::new());

                assert_eq!(HttpHandoff::Entity::find().all(&db).await.unwrap(), vec![]);
            }

            /// A framed begin is refused: `Sec-Fetch-Dest` other than
            /// `document` (`iframe`, `frame`, `empty`...) opens nothing, and
            /// sets no cookie; `document`, or no such header (an older
            /// browser), begins as usual.
            #[tokio::test]
            async fn begin_refuses_a_framed_navigation() {
                let db = memory_db().await;
                public_bound_target(&db).await;
                let cli = TestClient::new(begin_app(db.clone(), false).await);
                for dest in ["iframe", "frame", "embed", "object", "empty", ""] {
                    let resp = begin(&cli, HOST, Some("/page"), &[("sec-fetch-dest", dest)]).await;
                    resp.assert_status(StatusCode::FORBIDDEN);
                    assert!(set_cookies(&resp).is_empty(), "{dest}");
                }
                assert_eq!(HttpHandoff::Entity::find().all(&db).await.unwrap(), vec![]);
                for headers in [&[("sec-fetch-dest", "document")][..], &[]] {
                    let resp = begin(&cli, HOST, Some("/page"), headers).await;
                    resp.assert_status(StatusCode::SEE_OTHER);
                }
            }

            /// An anonymous visitor on a public target's own host begins a
            /// sign-in, is sent to sign in on the control plane, comes back
            /// through the same handoff, and is then served as its user. The
            /// begin sets the nonce cookie and nothing else.
            #[tokio::test]
            async fn an_anonymous_visitor_begins_signs_in_and_comes_back_named() {
                let db = memory_db().await;
                let target = public_bound_target(&db).await;
                let user = user_for(&db, target).await;
                let cli = TestClient::new(begin_app(db.clone(), false).await);

                let resp = begin(&cli, HOST, Some("/gated-upstream?x=1"), &[]).await;
                resp.assert_status(StatusCode::SEE_OTHER);
                let cookies = set_cookies(&resp);
                assert_eq!(cookies.len(), 1, "{cookies:?}");
                let nonce = nonce_set_by(&resp);
                let set_cookie = resp.0.headers()["set-cookie"].to_str().unwrap().to_owned();
                for attribute in ["Path=/", "Secure", "HttpOnly", "SameSite=Lax"] {
                    assert!(set_cookie.contains(attribute), "{set_cookie}");
                }
                assert!(!set_cookie.contains("Domain"), "{set_cookie}");
                let location = resp.0.headers()["location"].to_str().unwrap().to_owned();
                let challenge = challenge_in(&location);

                // Not signed in on the control plane: sent to sign in, to
                // come back to this same start.
                let resp = cli
                    .get(format!(
                        "/@warpgate{START_PATH}?{HANDOFF_CHALLENGE_PARAM}={challenge}"
                    ))
                    .header("host", CONTROL_PLANE)
                    .header("accept", "text/html")
                    .header("sec-fetch-mode", "navigate")
                    .send()
                    .await;
                let location = resp.0.headers()["location"].to_str().unwrap().to_owned();
                let next = location.strip_prefix("/@warpgate#/login?next=").unwrap();
                let next = percent_encoding::percent_decode_str(next)
                    .decode_utf8()
                    .unwrap()
                    .into_owned();
                assert_eq!(
                    next,
                    format!("/@warpgate{START_PATH}?{HANDOFF_CHALLENGE_PARAM}={challenge}")
                );
                assert!(
                    crate::api::sso_provider_list::is_safe_redirect_target(&next),
                    "the sign-in's next is refused: {next}"
                );

                // Signed in, back at the same start: handed off.
                let stamp = OffsetDateTime::now_utc().unix_timestamp();
                let resp = cli
                    .get(format!("/sign-in?user={user}&stamp={stamp}"))
                    .header("host", CONTROL_PLANE)
                    .send()
                    .await;
                resp.assert_status_is_ok();
                let control = session_cookie(&resp);
                let redeem = redeem_for(&cli, &control, user, &challenge).await;
                let resp = cli
                    .get(&redeem)
                    .header("host", HOST)
                    .header("cookie", format!("{HANDOFF_COOKIE_NAME}={nonce}"))
                    .send()
                    .await;
                resp.assert_status(StatusCode::SEE_OTHER);
                resp.assert_header("location", format!("https://{HOST}/gated-upstream?x=1"));
                let bound = session_cookie(&resp);

                let (status, seen) = gated_on(&cli, HOST, Some(&bound)).await;
                assert_eq!(status, StatusCode::OK, "{seen}");
                assert_eq!(seen, format!("user-{user}/user"));
            }

            /// Begin changes no session: a browser already handed off keeps
            /// its target-host session and is given only the nonce cookie,
            /// and the control-plane sign-in is untouched.
            #[tokio::test]
            async fn begin_changes_no_session() {
                let db = memory_db().await;
                let target = public_bound_target(&db).await;
                let user = user_for(&db, target).await;
                let cli = TestClient::new(begin_app(db.clone(), false).await);
                let (control, _, stamp) = signed_in(&cli, &db, target, user, 10).await;
                let bound = hand_off(&cli, &db, &control, user, target, HOST).await;
                let sessions_before = HttpSession::Entity::find().all(&db).await.unwrap();

                let resp = begin(&cli, HOST, Some("/page"), &[("cookie", bound.as_str())]).await;
                resp.assert_status(StatusCode::SEE_OTHER);
                let cookies = set_cookies(&resp);
                assert_eq!(cookies.len(), 1, "{cookies:?}");
                assert!(
                    cookies
                        .first()
                        .unwrap()
                        .starts_with(&format!("{HANDOFF_COOKIE_NAME}="))
                );

                let sessions_after = HttpSession::Entity::find().all(&db).await.unwrap();
                assert_eq!(sessions_before.len(), sessions_after.len());
                for (before, after) in sessions_before.iter().zip(&sessions_after) {
                    assert_eq!(before.id, after.id);
                    assert_eq!(before.data, after.data);
                }
                let (status, seen) = gated_on(&cli, HOST, Some(&bound)).await;
                assert_eq!(status, StatusCode::OK, "{seen}");
                assert_eq!(seen, format!("user-{user}/user"));
                let resp = cli
                    .get("/stamp")
                    .header("host", CONTROL_PLANE)
                    .header("cookie", &control)
                    .send()
                    .await;
                resp.assert_text(stamp.to_string()).await;
            }

            /// A begun handoff completes only in the browser that began it,
            /// and once: a token redeemed with another browser's nonce, or
            /// with none, is refused and spent, and a redeemed token
            /// replayed with the right nonce is refused.
            #[tokio::test]
            async fn a_begun_handoff_redeems_only_with_its_nonce_and_once() {
                let db = memory_db().await;
                let target = public_bound_target(&db).await;
                let user = user_for(&db, target).await;
                let cli = TestClient::new(begin_app(db.clone(), false).await);
                let (control, _, _) = signed_in(&cli, &db, target, user, 10).await;
                let refused_to = format!("https://{HOST}/page?{HANDOFF_RETRY_PARAM}=1");

                // Another browser's nonce, then none at all.
                let (other_challenge, other_nonce) = begun(&cli, "/elsewhere").await;
                for nonce in [Some(other_nonce.as_str()), None] {
                    let (challenge, own_nonce) = begun(&cli, "/page").await;
                    assert_ne!(challenge, other_challenge);
                    let redeem = redeem_for(&cli, &control, user, &challenge).await;
                    let mut req = cli.get(&redeem).header("host", HOST);
                    if let Some(nonce) = nonce {
                        req = req.header("cookie", format!("{HANDOFF_COOKIE_NAME}={nonce}"));
                    }
                    let resp = req.send().await;
                    resp.assert_status(StatusCode::SEE_OTHER);
                    resp.assert_header("location", &refused_to);
                    assert!(
                        !set_cookies(&resp)
                            .iter()
                            .any(|pair| pair.starts_with(&format!("{SESSION_COOKIE_NAME}="))
                                && pair.len() > SESSION_COOKIE_NAME.len() + 1),
                        "nonce {nonce:?}: a session was given"
                    );
                    // Spent: its own nonce no longer completes it.
                    let resp = cli
                        .get(&redeem)
                        .header("host", HOST)
                        .header("cookie", format!("{HANDOFF_COOKIE_NAME}={own_nonce}"))
                        .send()
                        .await;
                    resp.assert_status(StatusCode::SEE_OTHER);
                    resp.assert_header(
                        "location",
                        format!("https://{HOST}/?{HANDOFF_RETRY_PARAM}=1"),
                    );
                }

                // Its own nonce completes it, once.
                let (challenge, nonce) = begun(&cli, "/page").await;
                let redeem = redeem_for(&cli, &control, user, &challenge).await;
                let resp = cli
                    .get(&redeem)
                    .header("host", HOST)
                    .header("cookie", format!("{HANDOFF_COOKIE_NAME}={nonce}"))
                    .send()
                    .await;
                resp.assert_status(StatusCode::SEE_OTHER);
                resp.assert_header("location", format!("https://{HOST}/page"));
                session_cookie(&resp);
                let resp = cli
                    .get(&redeem)
                    .header("host", HOST)
                    .header("cookie", format!("{HANDOFF_COOKIE_NAME}={nonce}"))
                    .send()
                    .await;
                resp.assert_status(StatusCode::SEE_OTHER);
                resp.assert_header(
                    "location",
                    format!("https://{HOST}/?{HANDOFF_RETRY_PARAM}=1"),
                );
                assert!(
                    !set_cookies(&resp)
                        .iter()
                        .any(|pair| pair.starts_with(&format!("{SESSION_COOKIE_NAME}="))),
                    "the replay was given a session"
                );
            }

            /// A user without access to the target is refused when its
            /// begun handoff reaches the control plane's start (404, no
            /// token), and a user who loses access between start and redeem
            /// is refused at the redeem with no session stored.
            #[tokio::test]
            async fn a_begun_handoff_without_target_access_is_refused_at_start_and_redeem() {
                let db = memory_db().await;
                let target = public_bound_target(&db).await;
                let cli = TestClient::new(begin_app(db.clone(), false).await);

                let outsider = user_for_targets(&db, &[]).await;
                let (control, _, _) = signed_in(&cli, &db, target, outsider, 10).await;
                let (challenge, _) = begun(&cli, "/page").await;
                let resp = start(&cli, &control, outsider, &challenge).await;
                resp.assert_status(StatusCode::NOT_FOUND);
                assert!(resp.0.headers().get("location").is_none());

                let user = user_for(&db, target).await;
                let (control, _, _) = signed_in(&cli, &db, target, user, 10).await;
                let (challenge, nonce) = begun(&cli, "/page").await;
                let redeem = redeem_for(&cli, &control, user, &challenge).await;
                TargetRoleAssignment::Entity::delete_many()
                    .exec(&db)
                    .await
                    .unwrap();
                assert_refused_and_nothing_stored(&cli, &db, &redeem, &nonce).await;
            }

            /// Handed off to two hosts, each served by a node of its own, a
            /// sign-out on the control plane ends both target-host sessions
            /// and deletes them from the store.
            #[tokio::test]
            async fn a_sign_out_ends_the_target_host_sessions_on_every_node() {
                let db = memory_db().await;
                let first = bound_target(&db).await;
                let second = other_bound_target(&db).await;
                let user = user_for_targets(&db, &[first, second]).await;
                let node_a = TestClient::new(app(db.clone()).await);
                let node_b = TestClient::new(app(db.clone()).await);
                let (control, _, _) = signed_in(&node_a, &db, first, user, 10).await;
                let on_first = hand_off(&node_a, &db, &control, user, first, HOST).await;
                let on_second = hand_off(&node_b, &db, &control, user, second, OTHER_HOST).await;
                assert_eq!(page_on(&node_a, HOST, &on_first).await, "auth");
                assert_eq!(page_on(&node_b, OTHER_HOST, &on_second).await, "auth");

                node_a
                    .post("/sign-out")
                    .header("host", CONTROL_PLANE)
                    .header("cookie", &control)
                    .send()
                    .await
                    .assert_status_is_ok();

                assert_eq!(page_on(&node_a, HOST, &on_first).await, "anon");
                assert_eq!(page_on(&node_b, OTHER_HOST, &on_second).await, "anon");
                assert!(
                    !stored(&db, &on_first).await,
                    "the first host's session is stored"
                );
                assert!(
                    !stored(&db, &on_second).await,
                    "the second host's session is stored"
                );
            }

            /// A target-host session whose sign-in has ended counts on no
            /// node, even while its stored row is still there.
            #[tokio::test]
            async fn an_ended_sign_in_ends_its_target_host_session_while_still_stored() {
                let db = memory_db().await;
                let target = bound_target(&db).await;
                let user = user_for(&db, target).await;
                let node_a = TestClient::new(app(db.clone()).await);
                let node_b = TestClient::new(app(db.clone()).await);
                let (control, _, _) = signed_in(&node_a, &db, target, user, 10).await;
                let bound = hand_off(&node_b, &db, &control, user, target, HOST).await;
                assert_eq!(page_on(&node_b, HOST, &bound).await, "auth");

                let (_, storage_id) = control.split_once('=').unwrap();
                let user_session_id = HttpSession::Entity::find_by_id(storage_id.to_owned())
                    .one(&db)
                    .await
                    .unwrap()
                    .and_then(|row| row.user_session_id)
                    .expect("the control-plane session names its user session");
                warpgate_db_entities::UserSession::mark_ended_including_target_sessions(
                    &db,
                    user_session_id,
                )
                .await
                .unwrap();
                assert!(stored(&db, &bound).await);

                for node in [&node_a, &node_b] {
                    assert_eq!(page_on(node, HOST, &bound).await, "anon");
                }
            }

            mod step_up_ending {
                //! A step-up on one bound host ends every other bound host's
                //! session of the same sign-in on its next request.
                use super::*;

                /// Signs the control-plane browser in (again, with `cookie`) as
                /// `user`, its SSO sign-in `ago` seconds back.
                async fn sign_in_at(
                    cli: &TestClient<impl poem::Endpoint>,
                    cookie: Option<&str>,
                    user: Uuid,
                    ago: i64,
                ) -> String {
                    let stamp = OffsetDateTime::now_utc().unix_timestamp() - ago;
                    let mut req = cli
                        .get(format!("/sign-in?user={user}&stamp={stamp}"))
                        .header("host", CONTROL_PLANE);
                    if let Some(cookie) = cookie {
                        req = req.header("cookie", cookie);
                    }
                    let resp = req.send().await;
                    resp.assert_status_is_ok();
                    cookie.map_or_else(|| session_cookie(&resp), ToOwned::to_owned)
                }

                /// Signed in on two bound hosts, the user steps up on the first;
                /// the second host's session, used only after that, is refused on
                /// its first request and on every later one, and is gone from
                /// the store. The first host's new session, the control-plane
                /// sign-in and its user session go on.
                #[tokio::test]
                async fn a_step_up_on_one_host_ends_the_other_hosts_older_session() {
                    let db = memory_db().await;
                    let first = bound_target(&db).await;
                    let second = other_bound_target(&db).await;
                    let user = user_for_targets(&db, &[first, second]).await;
                    let cli = TestClient::new(app(db.clone()).await);

                    let control = sign_in_at(&cli, None, user, 30).await;
                    let on_first = hand_off(&cli, &db, &control, user, first, HOST).await;
                    let on_second = hand_off(&cli, &db, &control, user, second, OTHER_HOST).await;
                    assert_eq!(page_on(&cli, HOST, &on_first).await, "auth");
                    assert_eq!(page_on(&cli, OTHER_HOST, &on_second).await, "auth");

                    // The step-up on the first host: a fresh SSO sign-in on the
                    // control plane, handed off to the first host again.
                    sign_in_at(&cli, Some(&control), user, 5).await;
                    let on_first = hand_off(&cli, &db, &control, user, first, HOST).await;
                    assert_eq!(page_on(&cli, HOST, &on_first).await, "auth");

                    for attempt in 0..3 {
                        assert_eq!(
                            page_on(&cli, OTHER_HOST, &on_second).await,
                            "anon",
                            "request {attempt} on the second host"
                        );
                    }
                    assert!(
                        !stored(&db, &on_second).await,
                        "the second host's older session is still stored"
                    );

                    assert_eq!(page_on(&cli, HOST, &on_first).await, "auth");
                    let on_second = hand_off(&cli, &db, &control, user, second, OTHER_HOST).await;
                    assert_eq!(page_on(&cli, OTHER_HOST, &on_second).await, "auth");
                }
            }
        }

        #[test]
        fn the_retry_marker_is_added_found_and_removed_exactly() {
            assert_eq!(with_retry_marker("/"), format!("/?{HANDOFF_RETRY_PARAM}=1"));
            assert_eq!(
                with_retry_marker("/p?a=1"),
                format!("/p?a=1&{HANDOFF_RETRY_PARAM}=1")
            );
            assert!(!has_retry_marker("/p?a=1"));
            assert!(!has_retry_marker(&format!("/{HANDOFF_RETRY_PARAM}")));
            assert!(has_retry_marker(&with_retry_marker("/p?a=1")));
            assert_eq!(without_retry_marker(&with_retry_marker("/")), "/");
            assert_eq!(
                without_retry_marker(&format!("/p?a=1&{HANDOFF_RETRY_PARAM}=1&b=two%20words")),
                "/p?a=1&b=two%20words"
            );
            assert_eq!(without_retry_marker("/p?a=1"), "/p?a=1");
        }
    }
}
