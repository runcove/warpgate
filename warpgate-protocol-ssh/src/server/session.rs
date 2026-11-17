use std::borrow::Cow;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{Ipv4Addr, SocketAddr};
use std::ops::ControlFlow;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use bytes::Bytes;
use futures::{Future, FutureExt};
use russh::keys::{PublicKey, PublicKeyBase64};
use russh::server::ChannelOpenHandle;
use russh::{ChannelId, ChannelOpenFailure, MethodKind, MethodSet, Sig};
use termcolor::Color;
use time::OffsetDateTime;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::sync::{Mutex, broadcast, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::*;
use url::Url;
use uuid::Uuid;
use warpgate_common::auth::{
    AuthCredential, AuthResult, AuthSelector, AuthState, AuthStateUserInfo, CredentialKind,
    RememberApprovalBy,
};
use warpgate_common::eventhub::{EventHub, EventSender};
use warpgate_common::helpers::username::username_eq_ci;
use warpgate_common::{
    Secret, TargetOptions, TargetSSHOptions, TargetSessionId, UserFacingReason, UserSessionId,
    WarpgateError,
};
use warpgate_common_http::ext::{construct_control_plane_url, construct_external_url};
use warpgate_core::approvals::{GateOutcome, GatedConnection};
use warpgate_core::auth::step_up::{
    AuthenticatedKey, ExemptCredentialChange, ExemptRevocation, StepUpExemption, StepUpWindow,
    exempt_grant_revocation, exemption_still_listed, get_pubkey_last_sso_at, is_fresh,
    public_key_fingerprint, ssh_step_up_exemption, step_up_window, update_pubkey_last_sso_at,
};
use warpgate_core::auth::submit_credential;
use warpgate_core::login_protection::FailedAttemptInfo;
use warpgate_core::recordings::{
    ConnectionRecorder, RecordingOwner, TerminalRecorder, TrafficConnectionParams,
    TrafficRecorder,
};
use warpgate_core::{
    AdmittedTarget, ApprovedTarget, AuthorizedIdentity, ConfigProvider, Services,
    TargetAuthorization, TargetSessionStart, WarpgateServerHandle, authorize_and_spend_ticket,
    authorize_for_target, authorize_for_target_by_name,
};
use warpgate_db_entities::Parameters;
use warpgate_db_entities::Parameters::SshHostKeyVerificationMode;

use super::channel_registry::{Channel, ChannelRegistry};
use super::channel_writer::ChannelWriter;
use super::event_intake::EventIntake;
use super::russh_handler::{ChannelInputs, ServerHandlerEvent};
use super::service_output::ServiceOutput;
use super::session_handle::SessionHandleCommand;
use crate::server::get_allowed_auth_methods;
use crate::server::service_output::{VisualConnectionChainItem, paint_fg};
use crate::server::target_menu::{MenuEvent, spawn_target_menu_loop};
use crate::{
    ChannelOperation, ConnectionError, DirectTCPIPParams, PtyRequest, RCCommand, RCCommandReply,
    RCEvent, RCState, RemoteClient, ResolvedSshChainHost, ServerChannelId, SshClientError,
    SshRecordingMetadata, X11Request, resolve_approved_ssh_chain,
};

const EVENT_QUEUE_CAPACITY: usize = 128;

/// How long a teardown waits for the channel writer's own queue to drain —
/// i.e. for `Handle::close` to have been *sent* — before giving up on it, and
/// how long a reading client then gets to receive what was sent.
const DISCONNECT_FLUSH_TIMEOUT: Duration = Duration::from_secs(5);
/// How long the session's last message gets ahead of the connection-level
/// disconnect. A client that reads both in one batch acts on the disconnect
/// and exits without printing the message.
const DISCONNECT_NOTICE_GAP: Duration = Duration::from_secs(1);

/// The step-up window is re-read at least this often (live config, fresh SSO),
/// and no sooner than the minimum, so a boundary never spins the loop.
const STEP_UP_RECHECK_MAX: Duration = Duration::from_secs(10);
const STEP_UP_RECHECK_MIN: Duration = Duration::from_millis(250);
/// Consecutive unreadable checks after which a connection is closed.
const STEP_UP_MAX_READ_FAILURES: u32 = 6;
/// Longest one step-up database read may take before it counts as an
/// unreadable check. Half of `STEP_UP_RECHECK_MAX`: far above a healthy
/// read, and short enough that the failures allowed before a close
/// (`STEP_UP_MAX_READ_FAILURES`) add up within about a minute.
const STEP_UP_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Run one step-up database read with `STEP_UP_READ_TIMEOUT` as its bound. A
/// read that does not finish in time is returned as an error, so it is counted
/// like any other unreadable check.
async fn bound_step_up_read<T>(
    username: &str,
    limit: Duration,
    read: impl std::future::Future<Output = Result<T, WarpgateError>>,
) -> Result<T, WarpgateError> {
    if let Ok(result) = tokio::time::timeout(limit, read).await {
        result
    } else {
        warn!(%username, timeout = ?limit, "The step-up database read timed out");
        Err(WarpgateError::DatabaseError(sea_orm::DbErr::Custom(
            "step-up database read timed out".into(),
        )))
    }
}

/// What the session loop woke for.
#[allow(clippy::large_enum_variant)]
enum Woke {
    Event(Option<Event>),
    Idle,
    StepUp,
}

#[allow(clippy::large_enum_variant)]
enum TargetSelection {
    None,
    Menu,
    NotFound(String),
    PendingApproval(TargetAuthorization<TargetSSHOptions>),
    /// Held at the administrator gate: the authorization is riding on the
    /// spawned wait, which reports back as [`Event::AdminApprovalResolved`].
    /// Being a selection state is what makes the claim exclusive — a re-entry
    /// finds this instead of [`Self::PendingApproval`] and cannot start a
    /// duplicate wait, the same way [`Self::Connected`] cannot re-dial.
    AwaitingApproval,
    /// Carries the capability minted for the target session, so being in this
    /// state means every pre-dial gate ran for exactly the host to be dialed.
    Found(AdmittedTarget<TargetSSHOptions>),
    Connected,
}

#[derive(Debug)]
pub enum Event {
    Command(SessionHandleCommand),
    ServerHandler(ServerHandlerEvent),
    ConsoleInput(Bytes),
    ServiceOutput(Bytes),
    Client(RCEvent),
    MenuRedraw(u16, u16),
    Menu(MenuEvent),
    ServerChannelOpenResult(Uuid, Result<ServerChannelId, russh::Error>),
    AdminApprovalPending,
    AdminApprovalResolved {
        approved: Option<ApprovedTarget<TargetSSHOptions>>,
    },
}

/// State of an in-flight auto-continue web-approval wait, carried across
/// keyboard-interactive rounds.
///
/// `waits_used` is deliberately **not** here: this struct is dropped on every
/// terminal return, so a counter living here would reset and the cap could
/// never fire. It lives on [`ServerSession`] instead.
struct WebApprovalWait {
    /// Early-wake signal for this state id. `Option` so a `Closed` receiver can
    /// be dropped — a `select!` on a permanently-closed receiver returns
    /// instantly and would spin rounds at client RTT.
    receiver: Option<broadcast::Receiver<AuthResult>>,
    /// Identifies the auth state this wait is bound to. `AuthState` carries no
    /// id of its own at v0.28.6, so the wait is keyed on the security key the
    /// state generates for itself — freshly random per state, and the very
    /// string the user is asked to match in the browser. A round whose current
    /// state shows a different key discards the wait, so one principal's
    /// approval can never wake another principal's session.
    identification_string: String,
    /// Budget expiry, set lazily at the first zero-prompt round so that time
    /// spent typing an OTP does not eat the SSO budget.
    deadline: Option<Instant>,
    round: u8,
    /// Single source of truth for whether the approval URL has been emitted.
    url_shown: bool,
    /// Set on the round that delivered the not-confirmed message; the next
    /// round rejects.
    farewell: bool,
}

struct PendingKeyboardInteractiveAuth {
    otp_prompt_sent: bool,
    web_approval_wait: Option<WebApprovalWait>,
}

impl PendingKeyboardInteractiveAuth {
    const fn fresh() -> Self {
        Self {
            otp_prompt_sent: false,
            web_approval_wait: None,
        }
    }
}

/// How many browser-approval waits one TCP connection may start.
///
/// This is the **only** bound on a keyboard-interactive web-approval round —
/// both the auto-continue path (where a wait is a live broadcast subscription)
/// and the manual Press-Enter path (where the wait is the human) are charged
/// against it. There is deliberately no second, per-round counter: one lived on
/// `PendingKeyboardInteractiveAuth`, which is dropped by every terminal return,
/// so it reset whenever it mattered.
///
/// This is the server-owned bound. The client's `number_of_password_prompts` is
/// not a control we own, and russh's `max_auth_attempts` is a dead field —
/// declared and defaulted, but nothing in the crate enforces it.
const MAX_WEB_AUTH_WAITS: u8 = 3;

/// Charge one wait against the per-connection budget, returning the new count
/// and whether the cap has been exceeded.
///
/// Increment-before-compare is deliberate: it permits exactly
/// [`MAX_WEB_AUTH_WAITS`] waits and rejects at the start of the next one. The
/// add saturates because post-cap attempts keep incrementing before they are
/// rejected, and a wrapping `u8` would silently hand the client a fresh budget.
const fn bump_waits(used: u8) -> (u8, bool) {
    let used = used.saturating_add(1);
    (used, used > MAX_WEB_AUTH_WAITS)
}

/// Whether a round entering with these inputs is going to create a wait, and so
/// must charge one against the per-connection budget.
///
/// Two of the four blocks of [`ServerSession::web_approval_round_auto`] create a
/// wait: the TOTP-outstanding block and the new-wait block. The cap counts waits
/// regardless of which block created them, so a TOTP-plus-web user cannot get an
/// uncharged wait and repeated TOTP-outstanding rounds cannot re-subscribe for
/// free. The farewell block rejects and the poll block reuses the carried wait,
/// so neither charges — the budget bounds waits, not rounds.
fn round_creates_wait(
    pending_wait: Option<&WebApprovalWait>,
    identification_string: &str,
    totp_outstanding: bool,
) -> bool {
    if pending_wait.is_some_and(|wait| wait.farewell) {
        return false;
    }
    if totp_outstanding {
        return true;
    }
    // Rounds 2..N reuse the carried wait; anything else starts a new one,
    // including the discard of a wait bound to a different principal.
    pending_wait.is_none_or(|wait| wait.identification_string != identification_string)
}

/// Keep a carried wait only if it is bound to the auth state this round is
/// evaluating; otherwise discard it so a new wait starts at round 1.
///
/// The discard drops the whole wait, receiver included. Nothing about the
/// per-connection wait count is reachable from here, which is what makes the
/// count inherited rather than reset by a mid-connection username switch.
fn wait_for_state(
    wait: Option<WebApprovalWait>,
    identification_string: &str,
) -> Option<WebApprovalWait> {
    wait.filter(|wait| wait.identification_string == identification_string)
}

/// Consume the previous round's pending state and produce this round's, moving
/// the web-approval wait — and therefore its live broadcast receiver — forward.
///
/// The previous struct is consumed by value here rather than by a closure that
/// only borrows what it needs, which is what makes the receiver actually
/// survive: dropped, it leaves zero subscribers at the moment `complete()`
/// sends, and the approval is only noticed at the next poll tick.
fn carry_forward(previous: PendingKeyboardInteractiveAuth) -> PendingKeyboardInteractiveAuth {
    PendingKeyboardInteractiveAuth {
        otp_prompt_sent: false,
        web_approval_wait: previous.web_approval_wait,
    }
}

enum ProbeState {
    /// New session
    NoAttempt,
    /// Charged with suspicious probing
    Probe {
        username: String,
        method: &'static str,
    },
    /// Vindicated by a successful auth or guilty as charged with a failed login
    Settled,
}

struct CachedSuccessfulTicketAuth {
    ticket: Secret<String>,
    user_info: AuthStateUserInfo,
}

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub enum TrafficRecorderKey {
    Tcp(String, u32),
    Socket(String),
}

pub struct ServerSession {
    pub id: UserSessionId,
    user_info: Option<AuthStateUserInfo>,
    /// The sealed account-wide proof from the completed [`AuthState`], for the
    /// menu's re-authorization on selection. Deliberately absent for ticket
    /// sessions: a ticket binds one target and grants no account-wide
    /// authorization, so a ticket session reaching the menu fails closed.
    authorized_identity: Option<AuthorizedIdentity>,
    /// `"user"` or `"ticket"`, sent downstream as `WARPGATE_AUTHENTICATION_TYPE`.
    authentication_type: Option<String>,
    /// The admitted target's own `env` map, captured when the target is
    /// admitted. The selection moves on to `Connected` once dialled, so it
    /// cannot be read back from [`Self::target`] when a channel asks for a
    /// shell or exec.
    target_env: Option<HashMap<String, String>>,
    session_handle: Option<russh::server::Handle>,
    channels: ChannelRegistry,
    /// The client's input waiting on each channel's budget, ended when the
    /// target closes the channel.
    channel_inputs: ChannelInputs,
    /// Client-side events for channel ids no registered channel carries yet.
    /// They can only refer to a server-initiated open whose
    /// [`Event::ServerChannelOpenResult`] hasn't been processed — until it is,
    /// the client id (and thus the owning channel) is unknown, so unlike
    /// target-side events they can't be held on the channel itself.
    deferred_server_events: Vec<ServerHandlerEvent>,
    /// Events taken off the queue while a command reply was being awaited
    /// (see [`Self::send_command_and_wait`]), replayed by the main event loop.
    pending_events: VecDeque<Event>,
    rc_tx: UnboundedSender<(RCCommand, Option<RCCommandReply>)>,
    rc_abort_tx: UnboundedSender<()>,
    rc_state: RCState,
    remote_address: SocketAddr,
    services: Services,
    server_handle: Arc<Mutex<WarpgateServerHandle>>,
    target: TargetSelection,
    /// The child session minted by `start_target_session`. Recordings key on
    /// it; recordings requested before it exists (the target-selection menu,
    /// or an exec/subsystem dispatched through an approval gate) are held in
    /// [`Self::pending_recordings`] and started by
    /// [`Self::start_pending_recordings`] when it is stamped.
    target_session_id: Option<TargetSessionId>,
    /// Recording requests made while [`Self::target_session_id`] was still
    /// `None`, in arrival order. Drained on stamp.
    pending_recordings: Vec<(Uuid, SshRecordingMetadata)>,
    /// The user and target named on a failed recording's log line; set with
    /// [`Self::target_session_id`].
    recording_owner: RecordingOwner,
    /// Set when the session was refused because a recording could not start
    /// (see [`Self::refuse_unrecorded_session`]). From then on
    /// [`Self::maybe_connect_remote`] never dials the target: a recording
    /// parked for the menu or an approval gate is only started when the target
    /// is stamped, and its callers go on to connect.
    recording_refused: bool,
    traffic_recorders: HashMap<TrafficRecorderKey, TrafficRecorder>,
    hub: EventHub<Event>,
    event_sender: EventSender<Event>,
    intake: EventIntake<Event>,
    service_output: ServiceOutput,
    channel_writer: ChannelWriter,
    /// Cached auth state together with the target name it was created for. The
    /// state's `target_name` is fixed at construction and scopes web approvals,
    /// so it can only be reused for that same target.
    auth_state: Option<(Arc<Mutex<AuthState>>, String)>,
    /// A disconnect event used for the approval waiter
    disconnect_token: CancellationToken,
    /// The distinct public key rows this connection authenticated with, set for
    /// every key login (step-up may be switched on while it is open). Each key's
    /// `last_sso_at` plus the live interval bounds the connection; it closes
    /// when any of them passes, and a key login with no matched row counts as
    /// expired once step-up applies.
    step_up_pubkeys: Option<Vec<Uuid>>,
    /// For each public key row a submission matched on the current auth state,
    /// the fingerprint of the key the client signed with. It is what
    /// `step_up_interval.exempt_users` is decided on, so a key row rewritten
    /// while the login is in progress cannot change which key was used.
    /// Dropped with the auth state.
    authenticated_pubkeys: Vec<AuthenticatedKey>,
    /// Set when this connection was admitted through
    /// `step_up_interval.exempt_users`: who and what it was admitted for, so a
    /// config reload that no longer lists them, or the maximum lifetime, ends it.
    step_up_exempt: Option<ExemptGrant>,
    /// When to next evaluate the step-up window; `None` when untracked.
    step_up_recheck: Option<Instant>,
    /// The earliest deadline seen at the last successful read, kept so a
    /// failing database cannot extend the connection past it.
    step_up_known_deadline: Option<OffsetDateTime>,
    /// Consecutive failed `last_sso_at` reads.
    step_up_read_failures: u32,
    /// The reason sent to the client in the SSH disconnect message.
    disconnect_description: String,
    keyboard_interactive_state: Option<PendingKeyboardInteractiveAuth>,
    cached_successful_ticket_auth: Option<CachedSuccessfulTicketAuth>,
    allowed_auth_methods: MethodSet,
    host_key_trust_prompt_active: Arc<AtomicBool>,
    /// Track the state of a client snooping around pre-auth
    probe: ProbeState,
    /// Browser-approval waits started on this connection, on either the
    /// auto-continue or the manual Press-Enter path.
    ///
    /// This lives here, not on `PendingKeyboardInteractiveAuth`, because that
    /// struct is re-stored only on the `Auth::Partial` path and dropped by every
    /// terminal return — a counter there would reset on the next
    /// keyboard-interactive attempt and the cap could never fire. `ServerSession`
    /// is constructed once per accepted TCP stream and dies with the connection,
    /// so the count survives `self.auth_state = None`, every terminal reject, and
    /// any number of fresh `USERAUTH_REQUEST`s.
    web_auth_waits_used: u8,
    /// A duplicate of the client's socket descriptor, shut down at teardown
    /// so the connection ends with the session rather than with russh's
    /// inactivity timer. `None` once used.
    client_socket: Option<std::net::TcpStream>,
}

fn session_debug_tag(id: &UserSessionId, remote_address: &SocketAddr) -> String {
    format!("[{id} - {remote_address}]")
}

/// The owner of an SSH session's recordings before its target is known.
fn ssh_recording_owner() -> RecordingOwner {
    RecordingOwner {
        protocol: "ssh",
        user: String::new(),
        target: String::new(),
    }
}

fn shell_recording_metadata(server_channel_id: ServerChannelId) -> SshRecordingMetadata {
    SshRecordingMetadata::Shell {
        // HACK russh ChannelId is opaque except via Display
        channel: server_channel_id.0.to_string().parse().unwrap_or_default(),
    }
}

fn format_web_auth_instructions(login_url: Option<Url>, identification_string: &str) -> String {
    let spaced_key = identification_string
        .chars()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    let url_line = login_url.map(|u| format!("{u}\n")).unwrap_or_default();
    format!(
        "-----------------------------------------------------------------------\n\
         Please verify the SSH authentication request in your browser.\n\
         {url_line}\n\
         Make sure you're seeing this security key: {spaced_key}\n\
         -----------------------------------------------------------------------\n"
    )
}

fn reject_with_allowed_auth_methods(allowed_auth_methods: MethodSet) -> russh::server::Auth {
    russh::server::Auth::Reject {
        proceed_with_methods: Some(allowed_auth_methods),
        partial_success: false,
    }
}

/// Whether a client-sent environment variable falls in the namespace Warpgate
/// itself sets downstream (`WARPGATE_USERNAME`, `WARPGATE_AUTHENTICATION_TYPE`).
///
/// Such requests are dropped. With OpenSSH, Warpgate's own value is sent later
/// and wins anyway, but anything downstream that trusts these variables must
/// never be able to see a value the client chose - for instance if Warpgate's
/// injection were ever skipped for a channel.
fn is_reserved_env_name(name: &str) -> bool {
    name.starts_with("WARPGATE_")
}

/// Whether a `WebUserApproval` sitting in `valid_credentials` is evidence that
/// *this* attempt just completed a step-up SSO handshake.
///
/// Two consumers, one question. The freshness gate skips its `last_sso_at` read
/// when the answer is true, and the accept path stamps `last_sso_at` only when
/// the answer is true.
///
/// An approval injected by the web-approval grace-period bypass answers false.
/// It was granted for an earlier attempt - possibly a different session
/// entirely - so counting it would both let the gate through without an SSO
/// handshake and re-stamp the clock, and chained reconnects inside the grace
/// window would slide the step-up window forward forever. A user whose
/// `credential_policy.ssh` legitimately lists `WebUserApproval` reaches exactly
/// that combination, because a policy-raised `Need` is bypassable by design.
/// What a connection admitted through `step_up_interval.exempt_users` was
/// admitted for.
#[derive(Debug, Clone)]
struct ExemptGrant {
    username: String,
    user_id: Uuid,
    /// The public key rows the sign-in matched.
    pubkey_ids: Vec<Uuid>,
    /// Their fingerprints when the grant was made.
    fingerprints: Vec<String>,
    target: String,
    granted_at: Instant,
}

#[derive(Debug, PartialEq, Eq)]
enum ExemptVerdict {
    /// Still covered; look again after this long.
    Keep(Duration),
    NoLongerListed,
    MaxLifetime,
    /// The database no longer matches what the grant was made on.
    CredentialsChanged(ExemptCredentialChange),
}

fn exempt_verdict(
    grant: &ExemptGrant,
    step_up: Option<&warpgate_common::StepUpIntervalConfig>,
    elapsed: Duration,
) -> ExemptVerdict {
    if !exemption_still_listed(step_up, &grant.username, &grant.fingerprints, &grant.target) {
        return ExemptVerdict::NoLongerListed;
    }
    let max = step_up.map_or(Duration::ZERO, |s| s.exempt_max_session);
    if elapsed >= max {
        return ExemptVerdict::MaxLifetime;
    }
    ExemptVerdict::Keep((max - elapsed).clamp(STEP_UP_RECHECK_MIN, STEP_UP_RECHECK_MAX))
}

/// One look at a connection admitted through `exempt_users`: the live config
/// and the lifetime first, then, when those still cover it, the database (a
/// deleted or replaced key, or a new SSO or password credential, ends it as
/// it would end a normal connection). A database error is returned, never
/// read as "still covered".
async fn exempt_recheck(
    grant: &ExemptGrant,
    step_up: Option<&warpgate_common::StepUpIntervalConfig>,
    db: &sea_orm::DatabaseConnection,
    elapsed: Duration,
) -> Result<ExemptVerdict, WarpgateError> {
    exempt_recheck_bounded(grant, step_up, db, elapsed, STEP_UP_READ_TIMEOUT).await
}

/// `exempt_recheck` with the bound on its database read given.
async fn exempt_recheck_bounded(
    grant: &ExemptGrant,
    step_up: Option<&warpgate_common::StepUpIntervalConfig>,
    db: &sea_orm::DatabaseConnection,
    elapsed: Duration,
    limit: Duration,
) -> Result<ExemptVerdict, WarpgateError> {
    let verdict = exempt_verdict(grant, step_up, elapsed);
    if !matches!(verdict, ExemptVerdict::Keep(_)) {
        return Ok(verdict);
    }
    Ok(
        match bound_step_up_read(
            &grant.username,
            limit,
            exempt_grant_revocation(
                db,
                step_up,
                grant.user_id,
                &grant.pubkey_ids,
                &grant.fingerprints,
                &grant.target,
            ),
        )
        .await?
        {
            Some(ExemptRevocation::NoLongerListed | ExemptRevocation::UserDeleted) => {
                ExemptVerdict::NoLongerListed
            }
            Some(ExemptRevocation::Credentials(change)) => {
                ExemptVerdict::CredentialsChanged(change)
            }
            None => verdict,
        },
    )
}

/// What one tick of the exempt recheck does to the connection.
#[derive(Debug, PartialEq, Eq)]
enum ExemptTick {
    /// Keep it and look again after `next`. `failures` is the count of
    /// consecutive unreadable checks to carry into the next tick.
    Keep { next: Duration, failures: u32 },
    /// End it, for this reason.
    Close { why: &'static str, failures: u32 },
}

impl ExemptTick {
    const fn failures(&self) -> u32 {
        match self {
            Self::Keep { failures, .. } | Self::Close { failures, .. } => *failures,
        }
    }
}

/// The decision `enforce_step_up_window` takes on each tick for a connection
/// admitted through `exempt_users`, given what the recheck returned and the
/// count of consecutive unreadable checks so far.
///
/// A revocation closes at once. A check that could not read the database
/// never keeps the connection on its own account and never clears the count:
/// it adds one, and the connection closes with the last failure it is
/// allowed. Only a complete read that still covers the connection resets the
/// count to zero.
fn exempt_tick(
    result: &Result<ExemptVerdict, WarpgateError>,
    failures: u32,
    known_deadline: Option<OffsetDateTime>,
    now: OffsetDateTime,
) -> ExemptTick {
    let close = |why| ExemptTick::Close { why, failures };
    match result {
        Ok(ExemptVerdict::Keep(next)) => ExemptTick::Keep {
            next: *next,
            failures: 0,
        },
        Ok(ExemptVerdict::NoLongerListed) => close("no longer listed in the config"),
        Ok(ExemptVerdict::MaxLifetime) => close("maximum lifetime reached"),
        Ok(ExemptVerdict::CredentialsChanged(change)) => close(change.reason()),
        Err(_) => {
            let failures = failures.saturating_add(1);
            if read_failure_closes(failures, known_deadline, now) {
                ExemptTick::Close {
                    why: "the exemption could not be verified",
                    failures,
                }
            } else {
                ExemptTick::Keep {
                    next: STEP_UP_RECHECK_MAX,
                    failures,
                }
            }
        }
    }
}

/// Whether one more unreadable check ends a connection: it has no known
/// deadline left, or this was the last failure it is allowed.
fn read_failure_closes(
    failures: u32,
    known_deadline: Option<OffsetDateTime>,
    now: OffsetDateTime,
) -> bool {
    known_deadline.is_some_and(|d| now > d) || failures >= STEP_UP_MAX_READ_FAILURES
}

const fn web_approval_proves_step_up(approval_present: bool, approval_was_bypassed: bool) -> bool {
    approval_present && !approval_was_bypassed
}

/// Whether the sign-in recorded the key the client presented for every key
/// row it matched. `exempt_users` is decided on those recorded fingerprints,
/// so a key sign-in without one for a matched row is never exempt: step-up
/// applies to it as to a user who is not listed.
fn presented_keys_recorded(
    matched_pubkey_ids: &[Uuid],
    authenticated: &[AuthenticatedKey],
) -> bool {
    !matched_pubkey_ids.is_empty()
        && matched_pubkey_ids.iter().all(|row_id| {
            authenticated
                .iter()
                .any(|key| key.row_id == *row_id && !key.fingerprint.is_empty())
        })
}

/// How long one auto-continue round waits before handing a packet back to the
/// client.
///
/// A server→client packet has to cross the wire well inside the client's
/// read deadline — an `ServerAliveInterval 30` × `ServerAliveCountMax 3` client
/// gives a 90 s ceiling — and russh cannot emit anything while an auth handler
/// future is pending. Keeping each wait short is also what bounds how long the
/// session's serialized event loop is held, so `Close` and `Disconnect` are
/// serviced within one round.
const WEB_AUTH_POLL_CADENCE: Duration = Duration::from_secs(10);

/// Text shown when the browser approval never arrived within the budget. It has
/// to travel in a final zero-prompt `Auth::Partial`, because `Auth::Reject`
/// carries no message field.
const WEB_AUTH_NOT_CONFIRMED_MESSAGE: &str =
    "\n[!] Browser authentication was not confirmed, please try again.\n";

/// Whether a web-approval round has produced the whole `Auth` reply itself, or
/// whether the caller should keep assembling one.
enum WebApprovalRoundOutcome {
    Continue,
    Return(russh::server::Auth),
}

/// What an auto-continue web-approval round should do next.
#[derive(Debug, PartialEq, Eq)]
enum WebAuthStep {
    Accept,
    PollAgain { include_url: bool },
    Reject { message: Option<String> },
}

/// The whole decision of an auto-continue round, as a pure function.
///
/// It takes the **verdict** that `try_auth_lazy` just returned, never a raw
/// wake event: being woken is not evidence of approval, since the completion
/// signal fires on a browser *rejection* as well. Only an explicit `Accepted`
/// can accept.
///
/// It takes `url_shown` rather than a round number so that URL emission has
/// exactly one source of truth, and it deliberately takes no wait counter — the
/// per-connection wait cap is enforced on the wait-creation path, before this
/// function is reached.
fn next_web_auth_step(
    now: Instant,
    deadline: Option<Instant>,
    url_shown: bool,
    verdict: &AuthResult,
) -> WebAuthStep {
    match verdict {
        // Wins even over an expired budget: by now `_auth_accept`, `complete()`
        // and the `last_sso_at` stamp have already run, so rejecting on a stale
        // deadline would discard a completed authentication.
        AuthResult::Accepted { .. } => WebAuthStep::Accept,
        AuthResult::Rejected => WebAuthStep::Reject { message: None },
        AuthResult::Need(_) => {
            if deadline.is_some_and(|deadline| now >= deadline) {
                WebAuthStep::Reject {
                    message: Some(WEB_AUTH_NOT_CONFIRMED_MESSAGE.to_owned()),
                }
            } else {
                WebAuthStep::PollAgain {
                    include_url: !url_shown,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashSet, VecDeque};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use russh::{MethodKind, MethodSet};
    use tokio::sync::{Semaphore, broadcast, oneshot};
    use uuid::Uuid;
    use warpgate_common::auth::{AuthResult, AuthStateUserInfo, CredentialKind};
    use warpgate_common::eventhub::EventHub;
    use warpgate_core::auth::step_up::AuthenticatedKey;

    use super::{
        ChannelOperation, EventIntake, ExemptGrant, ExemptTick, ExemptVerdict, MAX_WEB_AUTH_WAITS,
        PendingCommand, PendingKeyboardInteractiveAuth, RCCommand, STEP_UP_MAX_READ_FAILURES,
        STEP_UP_READ_TIMEOUT, STEP_UP_RECHECK_MAX, SshClientError, TARGET_FORWARD_OPEN_TIMEOUT,
        TARGET_REPLY_TIMEOUT, WebApprovalWait, WebAuthStep, bound_step_up_read, bump_waits,
        carry_forward, exempt_recheck, exempt_tick, exempt_verdict, is_reserved_env_name,
        next_web_auth_step, presented_keys_recorded, read_failure_closes,
        reject_with_allowed_auth_methods, reply_limit, round_creates_wait, wait_for_reply,
        wait_for_state,
    };

    /// A client cannot set the variables Warpgate injects about the user;
    /// everything else a client sends still passes.
    #[test]
    fn client_env_requests_in_the_warpgate_namespace_are_refused() {
        for name in [
            "WARPGATE_USERNAME",
            "WARPGATE_AUTHENTICATION_TYPE",
            "WARPGATE_ANYTHING_ELSE",
        ] {
            assert!(is_reserved_env_name(name), "{name} must be dropped");
        }
        for name in ["LANG", "TERM", "LC_ALL", "MY_WARPGATE_USERNAME", "WARPGATE"] {
            assert!(!is_reserved_env_name(name), "{name} must pass through");
        }
    }

    /// The step-up gate and the `last_sso_at` stamp must both refuse an
    /// approval that the grace-period bypass injected. Otherwise a user whose
    /// credential policy lists `WebUserApproval` re-stamps `last_sso_at` on
    /// every reconnect inside `web_approval_grace_period_seconds`, and the
    /// step-up interval never fires again.
    fn grant(user: &str, fps: &[&str], target: &str) -> ExemptGrant {
        ExemptGrant {
            username: user.into(),
            user_id: Uuid::nil(),
            pubkey_ids: vec![],
            fingerprints: fps.iter().map(|f| (*f).to_owned()).collect(),
            target: target.into(),
            granted_at: Instant::now(),
        }
    }

    fn exempt_cfg(
        user: &str,
        keys: &[&str],
        targets: Option<&[&str]>,
        max: Duration,
    ) -> warpgate_common::StepUpIntervalConfig {
        warpgate_common::StepUpIntervalConfig {
            exempt_users: vec![warpgate_common::StepUpExemptUser {
                user: user.into(),
                keys: keys.iter().map(|k| (*k).to_owned()).collect(),
                targets: targets.map(|t| t.iter().map(|t| (*t).to_owned()).collect()),
            }],
            exempt_max_session: max,
            ..Default::default()
        }
    }

    #[test]
    fn an_exempt_connection_survives_a_reload_that_still_lists_it() {
        let g = grant("qa", &["SHA256:a"], "staging");
        let cfg = exempt_cfg(
            "qa",
            &["SHA256:a", "SHA256:b"],
            Some(&["staging", "x"]),
            Duration::from_secs(3600),
        );
        assert!(matches!(
            exempt_verdict(&g, Some(&cfg), Duration::from_secs(5)),
            ExemptVerdict::Keep(_)
        ));
    }

    #[test]
    fn a_reload_that_drops_the_user_key_or_target_ends_an_exempt_connection() {
        let g = grant("qa", &["SHA256:a"], "staging");
        let max = Duration::from_secs(3600);
        let gone = ExemptVerdict::NoLongerListed;
        let none = warpgate_common::StepUpIntervalConfig::default();
        assert_eq!(exempt_verdict(&g, Some(&none), Duration::ZERO), gone);
        assert_eq!(exempt_verdict(&g, None, Duration::ZERO), gone);
        let other_user = exempt_cfg("qa2", &["SHA256:a"], None, max);
        assert_eq!(exempt_verdict(&g, Some(&other_user), Duration::ZERO), gone);
        let other_key = exempt_cfg("qa", &["SHA256:b"], None, max);
        assert_eq!(exempt_verdict(&g, Some(&other_key), Duration::ZERO), gone);
        let other_target = exempt_cfg("qa", &["SHA256:a"], Some(&["prod"]), max);
        assert_eq!(
            exempt_verdict(&g, Some(&other_target), Duration::ZERO),
            gone
        );
    }

    #[test]
    fn an_exempt_connection_ends_at_the_maximum_lifetime() {
        let g = grant("qa", &["SHA256:a"], "staging");
        let cfg = exempt_cfg("qa", &["SHA256:a"], None, Duration::from_secs(60));
        assert!(matches!(
            exempt_verdict(&g, Some(&cfg), Duration::from_secs(59)),
            ExemptVerdict::Keep(_)
        ));
        assert_eq!(
            exempt_verdict(&g, Some(&cfg), Duration::from_secs(60)),
            ExemptVerdict::MaxLifetime
        );
        // A shortened limit applies to a connection that is already open.
        let shorter = exempt_cfg("qa", &["SHA256:a"], None, Duration::from_secs(10));
        assert_eq!(
            exempt_verdict(&g, Some(&shorter), Duration::from_secs(30)),
            ExemptVerdict::MaxLifetime
        );
    }

    fn unreadable() -> Result<ExemptVerdict, warpgate_common::WarpgateError> {
        Err(warpgate_common::WarpgateError::DatabaseError(
            sea_orm::DbErr::Custom("database unavailable".into()),
        ))
    }

    fn tick_at(
        result: &Result<ExemptVerdict, warpgate_common::WarpgateError>,
        failures: u32,
    ) -> ExemptTick {
        exempt_tick(result, failures, None, time::OffsetDateTime::now_utc())
    }

    /// Run `enforce_step_up_window`'s per-tick step over a list of results,
    /// threading the failure count the way the session does, and return what
    /// each tick decided.
    fn run_ticks(
        results: &[Result<ExemptVerdict, warpgate_common::WarpgateError>],
    ) -> Vec<ExemptTick> {
        let mut failures = 0;
        let mut decided = Vec::new();
        for result in results {
            let tick = tick_at(result, failures);
            failures = tick.failures();
            let closed = matches!(tick, ExemptTick::Close { .. });
            decided.push(tick);
            if closed {
                break;
            }
        }
        decided
    }

    fn keep_after_error(failures: u32) -> ExemptTick {
        ExemptTick::Keep {
            next: STEP_UP_RECHECK_MAX,
            failures,
        }
    }

    const COULD_NOT_VERIFY: &str = "the exemption could not be verified";

    /// Unreadable checks 1 to 5 keep the connection and the 6th closes it. If
    /// the error branch kept it for good, or cleared the count, a database
    /// that stays down would leave a revoked connection open.
    #[test]
    fn unreadable_checks_one_to_five_keep_the_connection_and_the_sixth_closes() {
        let results: Vec<_> = (0..10).map(|_| unreadable()).collect();
        assert_eq!(
            run_ticks(&results),
            vec![
                keep_after_error(1),
                keep_after_error(2),
                keep_after_error(3),
                keep_after_error(4),
                keep_after_error(5),
                ExemptTick::Close {
                    why: COULD_NOT_VERIFY,
                    failures: 6
                },
            ]
        );
    }

    /// An unreadable check always adds to the count, from any count, and the
    /// connection it keeps is looked at again within the recheck cap.
    #[test]
    fn an_unreadable_check_never_resets_the_count() {
        for failures in 0..STEP_UP_MAX_READ_FAILURES - 1 {
            match tick_at(&unreadable(), failures) {
                ExemptTick::Keep { next, failures: f } => {
                    assert_eq!(f, failures + 1);
                    assert!(next <= STEP_UP_RECHECK_MAX);
                }
                closed @ ExemptTick::Close { .. } => panic!("closed at {failures}: {closed:?}"),
            }
        }
        assert_eq!(
            tick_at(&unreadable(), STEP_UP_MAX_READ_FAILURES - 1),
            ExemptTick::Close {
                why: COULD_NOT_VERIFY,
                failures: STEP_UP_MAX_READ_FAILURES
            }
        );
        // An error between complete reads is counted from where it stands.
        assert_eq!(tick_at(&unreadable(), 3), keep_after_error(4));
    }

    /// Only a complete read that still covers the connection clears the
    /// count: after five unreadable checks and one such read, five more
    /// unreadable checks are again survived.
    #[test]
    fn a_complete_read_resets_the_count() {
        let covered = Duration::from_secs(7);
        let mut results: Vec<_> = (0..5).map(|_| unreadable()).collect();
        results.push(Ok(ExemptVerdict::Keep(covered)));
        results.extend((0..6).map(|_| unreadable()));
        assert_eq!(
            run_ticks(&results),
            vec![
                keep_after_error(1),
                keep_after_error(2),
                keep_after_error(3),
                keep_after_error(4),
                keep_after_error(5),
                ExemptTick::Keep {
                    next: covered,
                    failures: 0
                },
                keep_after_error(1),
                keep_after_error(2),
                keep_after_error(3),
                keep_after_error(4),
                keep_after_error(5),
                ExemptTick::Close {
                    why: COULD_NOT_VERIFY,
                    failures: 6
                },
            ]
        );
    }

    fn revocations() -> [(ExemptVerdict, &'static str); 5] {
        use super::ExemptCredentialChange as Change;
        [
            (
                ExemptVerdict::NoLongerListed,
                "no longer listed in the config",
            ),
            (ExemptVerdict::MaxLifetime, "maximum lifetime reached"),
            (
                ExemptVerdict::CredentialsChanged(Change::KeyChanged),
                Change::KeyChanged.reason(),
            ),
            (
                ExemptVerdict::CredentialsChanged(Change::SsoCredentialAdded),
                Change::SsoCredentialAdded.reason(),
            ),
            (
                ExemptVerdict::CredentialsChanged(Change::PasswordCredentialAdded),
                Change::PasswordCredentialAdded.reason(),
            ),
        ]
    }

    /// A revocation closes on the tick it is seen, at any count.
    #[test]
    fn a_revocation_closes_at_once() {
        for failures in [0, 3, STEP_UP_MAX_READ_FAILURES - 1] {
            for (verdict, why) in revocations() {
                assert_eq!(
                    tick_at(&Ok(verdict), failures),
                    ExemptTick::Close { why, failures },
                    "count {failures}, {why}"
                );
            }
        }
    }

    /// A deadline already passed ends the connection at its first unreadable
    /// check, as for a normal connection.
    #[test]
    fn an_unreadable_check_after_the_known_deadline_closes_at_once() {
        let now = time::OffsetDateTime::now_utc();
        let past = Some(now - time::Duration::seconds(1));
        let ahead = Some(now + time::Duration::seconds(60));
        assert_eq!(
            exempt_tick(&unreadable(), 0, past, now),
            ExemptTick::Close {
                why: COULD_NOT_VERIFY,
                failures: 1
            }
        );
        assert_eq!(
            exempt_tick(&unreadable(), 0, ahead, now),
            keep_after_error(1)
        );
    }

    mod exempt_recheck_against_the_database {
        use sea_orm::{
            ActiveModelTrait, ColumnTrait, ConnectionTrait, Database, DatabaseConnection,
            EntityTrait, QueryFilter, Set,
        };
        use warpgate_db_entities as entities;
        use warpgate_db_entities::Parameters::{
            ConfigMigrationValues, set_config_migration_values,
        };
        use warpgate_db_migrations::migrate_database;

        use super::super::ExemptCredentialChange;
        use super::*;

        const KEY_A: &str =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPu/YbG0OTn/9QBTFDjJBQQhHk5XIRPXKYWNHm21np1q";
        const FP_A: &str = "SHA256:dCsd+OZuerpGdJl7d6JN1z8Qe4jKnWrhUHtPhQ2Ghtg";
        const KEY_B: &str =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINlugWu1+DBB3PR2myFjhALc5Jug2vLAzEBjnb0SUe9o";

        const MAX: Duration = Duration::from_secs(3600);

        struct Admitted {
            db: DatabaseConnection,
            user_id: Uuid,
            key_id: Uuid,
            grant: ExemptGrant,
            cfg: warpgate_common::StepUpIntervalConfig,
        }

        /// A service user with one listed key, admitted the way the login does.
        async fn admitted() -> Admitted {
            set_config_migration_values(ConfigMigrationValues::default());
            let db = Database::connect("sqlite::memory:").await.unwrap();
            migrate_database(&db).await.unwrap();
            let user_id = Uuid::new_v4();
            let username = format!("qa-{user_id}");
            entities::User::ActiveModel {
                id: Set(user_id),
                username: Set(username.clone()),
                description: Set(String::new()),
                credential_policy: Set(sea_orm::JsonValue::Object(Default::default())),
                rate_limit_bytes_per_second: Set(None),
                ldap_server_id: Set(None),
                ldap_object_uuid: Set(None),
                allowed_ip_ranges: Set(sea_orm::JsonValue::Null),
            }
            .insert(&db)
            .await
            .unwrap();
            let key_id = add_key(&db, user_id, KEY_A).await;
            Admitted {
                grant: ExemptGrant {
                    username: username.clone(),
                    user_id,
                    pubkey_ids: vec![key_id],
                    fingerprints: vec![FP_A.to_owned()],
                    target: "staging".into(),
                    granted_at: Instant::now(),
                },
                cfg: exempt_cfg(&username, &[FP_A], None, MAX),
                db,
                user_id,
                key_id,
            }
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

        async fn recheck(a: &Admitted) -> Result<ExemptVerdict, warpgate_common::WarpgateError> {
            exempt_recheck(&a.grant, Some(&a.cfg), &a.db, Duration::from_secs(5)).await
        }

        fn closes(change: ExemptCredentialChange) -> Result<ExemptVerdict, ()> {
            Ok(ExemptVerdict::CredentialsChanged(change))
        }

        #[tokio::test]
        async fn a_connection_that_is_still_covered_survives() {
            let a = admitted().await;
            assert!(matches!(recheck(&a).await, Ok(ExemptVerdict::Keep(_))));
            // Another key added to the user later is not this connection's key.
            add_key(&a.db, a.user_id, KEY_B).await;
            assert!(matches!(recheck(&a).await, Ok(ExemptVerdict::Keep(_))));
        }

        #[tokio::test]
        async fn deleting_the_key_row_ends_the_connection() {
            let a = admitted().await;
            entities::PublicKeyCredential::Entity::delete_by_id(a.key_id)
                .exec(&a.db)
                .await
                .unwrap();
            assert_eq!(
                recheck(&a).await.map_err(|_| ()),
                closes(ExemptCredentialChange::KeyChanged)
            );
        }

        #[tokio::test]
        async fn replacing_the_key_ends_the_connection() {
            // The admin endpoints rewrite a key row in place, keeping its id.
            let a = admitted().await;
            entities::PublicKeyCredential::Entity::update_many()
                .set(entities::PublicKeyCredential::ActiveModel {
                    openssh_public_key: Set(KEY_B.into()),
                    ..Default::default()
                })
                .filter(entities::PublicKeyCredential::Column::Id.eq(a.key_id))
                .exec(&a.db)
                .await
                .unwrap();
            assert_eq!(
                recheck(&a).await.map_err(|_| ()),
                closes(ExemptCredentialChange::KeyChanged)
            );
        }

        #[tokio::test]
        async fn replacing_the_row_with_a_new_one_ends_the_connection() {
            let a = admitted().await;
            entities::PublicKeyCredential::Entity::delete_by_id(a.key_id)
                .exec(&a.db)
                .await
                .unwrap();
            add_key(&a.db, a.user_id, KEY_A).await;
            assert_eq!(
                recheck(&a).await.map_err(|_| ()),
                closes(ExemptCredentialChange::KeyChanged),
                "the grant is for the row the sign-in matched"
            );
        }

        #[tokio::test]
        async fn a_new_password_credential_ends_the_connection() {
            let a = admitted().await;
            entities::PasswordCredential::ActiveModel {
                id: Set(Uuid::new_v4()),
                user_id: Set(a.user_id),
                argon_hash: Set("not-a-real-hash".into()),
            }
            .insert(&a.db)
            .await
            .unwrap();
            assert_eq!(
                recheck(&a).await.map_err(|_| ()),
                closes(ExemptCredentialChange::PasswordCredentialAdded)
            );
        }

        #[tokio::test]
        async fn a_new_sso_credential_ends_the_connection() {
            let a = admitted().await;
            entities::SsoCredential::ActiveModel {
                id: Set(Uuid::new_v4()),
                user_id: Set(a.user_id),
                provider: Set(None),
                email: Set("qa@example.com".into()),
            }
            .insert(&a.db)
            .await
            .unwrap();
            assert_eq!(
                recheck(&a).await.map_err(|_| ()),
                closes(ExemptCredentialChange::SsoCredentialAdded)
            );
        }

        #[tokio::test]
        async fn a_config_that_stops_listing_the_user_ends_it_without_the_database() {
            let a = admitted().await;
            a.db.execute_unprepared("DROP TABLE credentials_sso")
                .await
                .unwrap();
            let none = exempt_cfg("someone-else", &[FP_A], None, MAX);
            let got = exempt_recheck(&a.grant, Some(&none), &a.db, Duration::ZERO).await;
            assert!(matches!(got, Ok(ExemptVerdict::NoLongerListed)), "{got:?}");
        }

        #[tokio::test]
        async fn a_database_error_is_an_error_and_repeated_ones_end_the_connection() {
            let a = admitted().await;
            a.db.execute_unprepared("DROP TABLE credentials_sso")
                .await
                .unwrap();
            // Never read as "still covered" ...
            assert!(recheck(&a).await.is_err());

            // ... and the session counts it like an unreadable step-up stamp:
            // the connection has no known deadline, so it ends with the last
            // failure it is allowed.
            let now = time::OffsetDateTime::now_utc();
            for failures in 1..STEP_UP_MAX_READ_FAILURES {
                assert!(!read_failure_closes(failures, None, now), "{failures}");
            }
            assert!(read_failure_closes(STEP_UP_MAX_READ_FAILURES, None, now));
            // A deadline already passed ends it at the first failure.
            let past = now - time::Duration::seconds(1);
            assert!(read_failure_closes(1, Some(past), now));
            assert!(!read_failure_closes(
                1,
                Some(now + time::Duration::seconds(60)),
                now
            ));
        }

        /// The recheck result feeds `exempt_tick` the way
        /// `enforce_step_up_window` does, threading the count through ticks.
        fn tick(
            result: &Result<ExemptVerdict, warpgate_common::WarpgateError>,
            failures: u32,
        ) -> ExemptTick {
            exempt_tick(result, failures, None, time::OffsetDateTime::now_utc())
        }

        #[tokio::test]
        async fn a_failing_database_ends_the_connection_on_the_sixth_tick() {
            let a = admitted().await;
            a.db.execute_unprepared("DROP TABLE credentials_sso")
                .await
                .unwrap();

            let mut failures = 0;
            for n in 1..=STEP_UP_MAX_READ_FAILURES {
                let result = recheck(&a).await;
                assert!(result.is_err(), "tick {n} must not read as covered");
                match tick(&result, failures) {
                    ExemptTick::Keep { failures: f, .. } => {
                        assert!(n < STEP_UP_MAX_READ_FAILURES, "tick {n} must close");
                        failures = f;
                    }
                    ExemptTick::Close { why, failures: f } => {
                        assert_eq!(n, STEP_UP_MAX_READ_FAILURES, "closed early at tick {n}");
                        assert_eq!(why, "the exemption could not be verified");
                        failures = f;
                    }
                }
                assert_eq!(failures, n);
            }
        }

        /// A read that never returns (the only pooled connection is held
        /// elsewhere) counts as an unreadable check within the bound, so the
        /// connection closes after the allowed number of them.
        #[tokio::test]
        async fn a_hung_database_read_counts_as_a_failure_within_the_bound() {
            use sea_orm::TransactionTrait;

            let a = admitted().await;
            let _held = a.db.begin().await.unwrap();
            // Pause only now: setting the database up needs real time.
            tokio::time::pause();

            let mut failures = 0;
            for n in 1..=STEP_UP_MAX_READ_FAILURES {
                let started = tokio::time::Instant::now();
                let result =
                    exempt_recheck(&a.grant, Some(&a.cfg), &a.db, Duration::from_secs(5)).await;
                assert!(
                    result.is_err(),
                    "tick {n}: a hung read must not read as covered"
                );
                assert!(
                    started.elapsed() <= STEP_UP_READ_TIMEOUT + Duration::from_millis(100),
                    "tick {n} took {:?}",
                    started.elapsed()
                );
                match tick(&result, failures) {
                    ExemptTick::Keep { failures: f, .. } => {
                        assert!(n < STEP_UP_MAX_READ_FAILURES, "tick {n} must close");
                        failures = f;
                    }
                    ExemptTick::Close { why, failures: f } => {
                        assert_eq!(n, STEP_UP_MAX_READ_FAILURES);
                        assert_eq!(why, "the exemption could not be verified");
                        failures = f;
                    }
                }
                assert_eq!(failures, n);
            }
        }

        #[tokio::test(start_paused = true)]
        async fn bound_step_up_read_gives_up_on_a_read_that_never_finishes() {
            let started = tokio::time::Instant::now();
            let result: Result<(), _> = bound_step_up_read(
                "someone",
                STEP_UP_READ_TIMEOUT,
                std::future::pending::<Result<(), warpgate_common::WarpgateError>>(),
            )
            .await;
            assert!(result.is_err());
            assert_eq!(started.elapsed(), STEP_UP_READ_TIMEOUT);

            let ok = bound_step_up_read("someone", STEP_UP_READ_TIMEOUT, async { Ok(7) }).await;
            assert_eq!(ok.unwrap(), 7);
        }

        #[tokio::test]
        async fn a_complete_read_resets_the_count_and_a_database_revocation_closes_at_once() {
            let a = admitted().await;

            // Five unreadable ticks' worth of count, then a complete read that
            // still covers the connection.
            let result = recheck(&a).await;
            let Ok(ExemptVerdict::Keep(next)) = &result else {
                panic!("expected a covered connection, got {result:?}");
            };
            assert_eq!(
                tick(&result, STEP_UP_MAX_READ_FAILURES - 1),
                ExemptTick::Keep {
                    next: *next,
                    failures: 0
                }
            );

            // The key replaced in the database closes the connection on that
            // tick, with no failures needed.
            entities::PublicKeyCredential::Entity::update_many()
                .set(entities::PublicKeyCredential::ActiveModel {
                    openssh_public_key: Set(KEY_B.into()),
                    ..Default::default()
                })
                .filter(entities::PublicKeyCredential::Column::Id.eq(a.key_id))
                .exec(&a.db)
                .await
                .unwrap();
            let result = recheck(&a).await;
            assert_eq!(
                tick(&result, 0),
                ExemptTick::Close {
                    why: ExemptCredentialChange::KeyChanged.reason(),
                    failures: 0
                }
            );
        }
    }

    fn key(row_id: Uuid, fingerprint: &str) -> AuthenticatedKey {
        AuthenticatedKey {
            row_id,
            fingerprint: fingerprint.to_owned(),
        }
    }

    /// A key sign-in that recorded no presented key for a matched row never
    /// reaches the exemption, so step-up applies to it.
    #[test]
    fn a_key_sign_in_without_a_recorded_fingerprint_is_not_considered_for_the_exemption() {
        let (a, b) = (Uuid::from_u128(1), Uuid::from_u128(2));

        assert!(presented_keys_recorded(&[a], &[key(a, "SHA256:a")]));
        assert!(presented_keys_recorded(
            &[a, b],
            &[key(b, "SHA256:b"), key(a, "SHA256:a")]
        ));

        // Nothing recorded at all.
        assert!(!presented_keys_recorded(&[a], &[]));
        // Recorded for another row only.
        assert!(!presented_keys_recorded(&[a], &[key(b, "SHA256:b")]));
        // One of two matched rows has none.
        assert!(!presented_keys_recorded(&[a, b], &[key(a, "SHA256:a")]));
        // A blank fingerprint is no fingerprint.
        assert!(!presented_keys_recorded(&[a], &[key(a, "")]));
        // No matched row to record a key for.
        assert!(!presented_keys_recorded(&[], &[key(a, "SHA256:a")]));
        assert!(!presented_keys_recorded(&[], &[]));
    }

    #[test]
    fn a_bypassed_web_approval_neither_satisfies_step_up_nor_stamps_last_sso_at() {
        // A real approval collected by this attempt: gate satisfied, stamp taken.
        assert!(super::web_approval_proves_step_up(true, false));

        // The same credential, injected by the grace-period bypass: neither.
        assert!(
            !super::web_approval_proves_step_up(true, true),
            "a grace-period bypass must not count as a step-up handshake, or \
             last_sso_at is re-stamped on every reconnect inside the window"
        );

        // No approval at all: the gate falls through to the freshness read.
        assert!(!super::web_approval_proves_step_up(false, false));
        assert!(!super::web_approval_proves_step_up(false, true));
    }

    #[test]
    fn rejected_public_key_auth_advertises_only_configured_methods() {
        let configured_methods = MethodSet::from(&[MethodKind::PublicKey][..]);
        let auth = reject_with_allowed_auth_methods(configured_methods.clone());

        let russh::server::Auth::Reject {
            proceed_with_methods: Some(advertised_methods),
            ..
        } = auth
        else {
            panic!("expected an authentication rejection with advertised methods");
        };

        assert_eq!(advertised_methods, configured_methods);
        assert!(!advertised_methods.contains(&MethodKind::Password));
        assert!(!advertised_methods.contains(&MethodKind::KeyboardInteractive));
    }

    fn accepted() -> AuthResult {
        AuthResult::Accepted {
            user_info: AuthStateUserInfo {
                id: Uuid::nil(),
                username: "someone".to_owned(),
            },
        }
    }

    fn need_web_approval() -> AuthResult {
        AuthResult::Need(
            [CredentialKind::WebUserApproval]
                .into_iter()
                .collect::<HashSet<_>>(),
        )
    }

    fn wait_bound_to(
        identification_string: &str,
        sender: &broadcast::Sender<AuthResult>,
    ) -> WebApprovalWait {
        WebApprovalWait {
            receiver: Some(sender.subscribe()),
            identification_string: identification_string.to_owned(),
            deadline: None,
            round: 7,
            url_shown: true,
            farewell: false,
        }
    }

    /// I3: a wait is bound to one principal. `get_auth_state` mints a new
    /// `AuthState` when the username changes, while a carried receiver still
    /// points at the previous state's channel — so a mismatching state key must
    /// discard the wait rather than let one principal's approval wake another's
    /// session.
    #[test]
    fn unit_web_auth_state_id_mismatch_discards_the_wait() {
        let (sender, _) = broadcast::channel::<AuthResult>(1);
        let mine = "1A2B";
        let theirs = "9F0E";

        let kept = wait_for_state(Some(wait_bound_to(mine, &sender)), mine)
            .expect("a wait bound to the current state must survive");
        assert_eq!(kept.round, 7);
        assert!(kept.receiver.is_some());

        assert!(
            wait_for_state(Some(kept), theirs).is_none(),
            "a wait bound to a different auth state must be discarded"
        );
    }

    /// I6: the wait counter lives on the connection, not on the wait, so the I3
    /// discard path inherits it. If a mid-connection username switch reset the
    /// budget, a client could alternate usernames to sustain waits — and each
    /// restart allocates an `AuthState` the store retains for ten minutes.
    #[test]
    fn unit_web_auth_discard_path_inherits_the_wait_counter() {
        let (sender, _) = broadcast::channel::<AuthResult>(1);

        // Three waits already spent on this connection.
        let mut used = 0u8;
        for _ in 0..MAX_WEB_AUTH_WAITS {
            let (next, capped) = bump_waits(used);
            used = next;
            assert!(!capped);
        }

        // A username switch discards the carried wait entirely...
        assert!(wait_for_state(Some(wait_bound_to("1A2B", &sender)), "9F0E").is_none());

        // ...and the wait it forces is charged against the inherited count.
        let (used, capped) = bump_waits(used);
        assert_eq!(used, MAX_WEB_AUTH_WAITS + 1);
        assert!(capped, "a discard must not restart the wait budget");
    }

    /// One entry into `web_approval_round_auto`, charging the per-connection
    /// budget exactly where the real round does.
    fn round(
        used: u8,
        pending: Option<&WebApprovalWait>,
        identification_string: &str,
        totp_outstanding: bool,
    ) -> (u8, bool) {
        if round_creates_wait(pending, identification_string, totp_outstanding) {
            bump_waits(used)
        } else {
            (used, false)
        }
    }

    /// I6: the cap counts waits regardless of which block created them. The
    /// TOTP-outstanding block creates a wait too — it subscribes and stores one —
    /// so it must charge the budget. Without this a TOTP+web user gets an
    /// uncharged wait, and repeated TOTP-outstanding rounds re-subscribe for
    /// free.
    #[test]
    fn unit_web_auth_totp_outstanding_round_charges_the_budget() {
        let (sender, _) = broadcast::channel::<AuthResult>(1);
        let state = "1A2B";

        // Each TOTP-outstanding round carries the previous round's wait, so the
        // state key matches — the charge must not be skipped on that account.
        let carried = wait_bound_to(state, &sender);

        let mut used = 0u8;
        for _ in 0..MAX_WEB_AUTH_WAITS {
            let (next, capped) = round(used, Some(&carried), state, true);
            assert!(
                next > used,
                "a TOTP-outstanding round must consume one from the budget"
            );
            used = next;
            assert!(!capped);
        }

        let (used, capped) = round(used, Some(&carried), state, true);
        assert_eq!(used, MAX_WEB_AUTH_WAITS + 1);
        assert!(
            capped,
            "a TOTP-outstanding round past the cap must reject, not create a fourth wait"
        );
    }

    /// A farewell round rejects without creating anything, so it must not charge
    /// the budget.
    #[test]
    fn unit_web_auth_farewell_round_does_not_charge_the_budget() {
        let (sender, _) = broadcast::channel::<AuthResult>(1);
        let state = "1A2B";
        let mut farewell = wait_bound_to(state, &sender);
        farewell.farewell = true;

        assert!(!round_creates_wait(Some(&farewell), state, false));
        // Even with TOTP still outstanding, the farewell reject comes first.
        assert!(!round_creates_wait(Some(&farewell), state, true));
        assert_eq!(
            round(MAX_WEB_AUTH_WAITS, Some(&farewell), state, true),
            (MAX_WEB_AUTH_WAITS, false)
        );
    }

    /// Rounds 2..N reuse the carried wait, so they charge nothing — the budget
    /// bounds waits, not rounds.
    #[test]
    fn unit_web_auth_poll_round_does_not_charge_the_budget() {
        let (sender, _) = broadcast::channel::<AuthResult>(1);
        let state = "1A2B";
        let carried = wait_bound_to(state, &sender);

        assert!(!round_creates_wait(Some(&carried), state, false));
        assert_eq!(round(1, Some(&carried), state, false), (1, false));

        // A wait bound to another principal is discarded, which does create one.
        assert!(round_creates_wait(Some(&carried), "9F0E", false));
        // As does having no wait at all.
        assert!(round_creates_wait(None, state, false));
    }

    /// I6: the cap counts **waits**, not rounds — three waits pass and the
    /// fourth rejects. A per-round increment would reject real users at roughly
    /// 30 s at the 10 s cadence, making the 2 m budget unreachable and the
    /// farewell path dead code.
    #[test]
    fn unit_web_auth_wait_cap_permits_exactly_three_waits() {
        assert_eq!(MAX_WEB_AUTH_WAITS, 3);
        assert_eq!(bump_waits(0), (1, false));
        assert_eq!(bump_waits(1), (2, false));
        assert_eq!(bump_waits(2), (3, false));
        assert_eq!(bump_waits(3), (4, true));
    }

    /// I6: the counter saturates rather than wrapping. Post-cap, every further
    /// attempt still increments before rejecting, so a wrapping `u8` would hand
    /// the client a fresh three-wait budget every ~256 attempts — silently,
    /// since the release profile sets no `overflow-checks`.
    #[test]
    fn unit_web_auth_wait_cap_saturates_instead_of_wrapping() {
        assert_eq!(bump_waits(u8::MAX), (u8::MAX, true));
        assert_ne!(bump_waits(u8::MAX).0, 0);
    }

    /// I4: the wait — and therefore its live broadcast receiver — has to survive
    /// being carried from one keyboard-interactive round to the next. The naive
    /// implementation drops the receiver every round, so there are zero
    /// subscribers at the moment `complete()` sends, `send()` returns `Err`,
    /// warpgate discards it, and approval is only noticed at the next tick.
    #[tokio::test]
    async fn unit_web_auth_wait_receiver_survives_a_round() {
        let (sender, _) = broadcast::channel::<AuthResult>(1);
        let previous = PendingKeyboardInteractiveAuth {
            otp_prompt_sent: true,
            web_approval_wait: Some(WebApprovalWait {
                receiver: Some(sender.subscribe()),
                identification_string: "AAAA".to_owned(),
                deadline: None,
                round: 1,
                url_shown: true,
                farewell: false,
            }),
        };

        let next = carry_forward(previous);

        let carried = next
            .web_approval_wait
            .expect("the wait must be carried into the next round");
        let mut receiver = carried
            .receiver
            .expect("the carried wait must still hold its receiver");

        sender
            .send(accepted())
            .expect("the carried receiver must still be subscribed");
        assert!(matches!(
            receiver.recv().await,
            Ok(AuthResult::Accepted { .. })
        ));
    }

    /// I2: an `Accepted` verdict is the only thing that accepts, and it does so
    /// unconditionally.
    #[test]
    fn unit_web_auth_accepted_verdict_accepts() {
        let now = Instant::now();
        assert_eq!(
            next_web_auth_step(now, Some(now + Duration::from_secs(60)), true, &accepted()),
            WebAuthStep::Accept
        );
    }

    /// Accept wins over an expired budget: by the time a verdict of `Accepted`
    /// exists, `_auth_accept`, `complete()` and the `last_sso_at` stamp have
    /// already run, so rejecting on a stale deadline would discard a completed
    /// authentication.
    #[test]
    fn unit_web_auth_accepted_beats_expired_deadline() {
        let now = Instant::now();
        assert_eq!(
            next_web_auth_step(now, Some(now - Duration::from_secs(1)), true, &accepted()),
            WebAuthStep::Accept
        );
    }

    /// I2: the browser-reject sequence — `api_reject_auth` fires the same wake
    /// signal as an approval, so a `Rejected` verdict must reject at once
    /// rather than waiting out the budget.
    #[test]
    fn unit_web_auth_rejected_verdict_rejects_immediately() {
        let now = Instant::now();
        assert_eq!(
            next_web_auth_step(
                now,
                Some(now + Duration::from_secs(60)),
                true,
                &AuthResult::Rejected
            ),
            WebAuthStep::Reject { message: None }
        );
    }

    /// First zero-prompt round with budget left: poll again, carrying the URL.
    #[test]
    fn unit_web_auth_need_first_round_includes_url() {
        let now = Instant::now();
        assert_eq!(
            next_web_auth_step(
                now,
                Some(now + Duration::from_secs(60)),
                false,
                &need_web_approval()
            ),
            WebAuthStep::PollAgain { include_url: true }
        );
    }

    /// I5 / SC2: once the URL has been shown, later rounds must suppress it —
    /// PuTTY and Paramiko print the instruction field on every round.
    #[test]
    fn unit_web_auth_need_later_round_suppresses_url() {
        let now = Instant::now();
        assert_eq!(
            next_web_auth_step(
                now,
                Some(now + Duration::from_secs(60)),
                true,
                &need_web_approval()
            ),
            WebAuthStep::PollAgain { include_url: false }
        );
    }

    /// A deadline that has not been set yet (the first zero-prompt round has
    /// not happened) can never expire.
    #[test]
    fn unit_web_auth_need_without_deadline_polls_again() {
        let now = Instant::now();
        assert_eq!(
            next_web_auth_step(now, None, false, &need_web_approval()),
            WebAuthStep::PollAgain { include_url: true }
        );
    }

    /// SC3: budget expiry rejects, and carries the not-confirmed text so it can
    /// be delivered in a farewell round (`Auth::Reject` has no message field).
    #[test]
    fn unit_web_auth_need_expired_deadline_rejects_with_message() {
        let now = Instant::now();
        let step = next_web_auth_step(
            now,
            Some(now - Duration::from_secs(1)),
            true,
            &need_web_approval(),
        );
        let WebAuthStep::Reject {
            message: Some(message),
        } = step
        else {
            panic!("expected a Reject carrying a message, got {step:?}");
        };
        assert!(
            message.contains("not confirmed"),
            "farewell message should carry the not-confirmed text, got {message:?}"
        );
    }

    /// Exact boundary: `now == deadline` is expired, matching the `now >= deadline`
    /// test in the spec algorithm.
    #[test]
    fn unit_web_auth_need_exact_boundary_deadline_rejects() {
        let now = Instant::now();
        assert!(matches!(
            next_web_auth_step(now, Some(now), true, &need_web_approval()),
            WebAuthStep::Reject { message: Some(_) }
        ));
    }

    async fn test_intake() -> (
        EventIntake<&'static str>,
        warpgate_common::eventhub::EventSender<&'static str>,
    ) {
        let (hub, sender) = EventHub::setup(4);
        let control = hub.subscribe(|_| true).await;
        let target = hub.subscribe(|_| false).await;
        (
            EventIntake::new(control, target, Arc::new(Semaphore::new(1))),
            sender,
        )
    }

    /// A target connection that never answers (russh#789) fails the command
    /// once the bound has passed instead of holding the session for good,
    /// and events that arrived meanwhile are kept for the main loop.
    #[tokio::test]
    async fn unit_command_reply_wait_ends_at_the_limit() {
        let (mut intake, sender) = test_intake().await;
        let (_reply_tx, reply_rx) = oneshot::channel();
        sender.send_once("meanwhile").await.unwrap();
        let mut held = VecDeque::new();
        let limit = Duration::from_millis(50);

        let result = tokio::time::timeout(
            Duration::from_secs(5),
            wait_for_reply(
                PendingCommand::Waiting(reply_rx),
                limit,
                &mut intake,
                &mut held,
            ),
        )
        .await
        .expect("the wait must end at its limit");

        assert!(matches!(result, Err(SshClientError::NoReply(l)) if l == limit));
        assert_eq!(held, VecDeque::from(["meanwhile"]));
    }

    #[tokio::test]
    async fn unit_command_reply_wait_returns_the_reply() {
        let (mut intake, _sender) = test_intake().await;
        let (reply_tx, reply_rx) = oneshot::channel();
        reply_tx.send(Ok(())).unwrap();
        let mut held = VecDeque::new();

        let result = wait_for_reply(
            PendingCommand::Waiting(reply_rx),
            Duration::from_secs(30),
            &mut intake,
            &mut held,
        )
        .await;

        assert!(result.is_ok());
        assert!(held.is_empty());
    }

    #[test]
    fn unit_command_reply_limit_is_longer_only_for_forwarded_opens() {
        let id = Uuid::nil();
        assert_eq!(
            reply_limit(&RCCommand::Channel(id, ChannelOperation::OpenShell)),
            TARGET_REPLY_TIMEOUT
        );
        assert_eq!(
            reply_limit(&RCCommand::ForwardTCPIP("localhost".into(), 1)),
            TARGET_REPLY_TIMEOUT
        );
        assert_eq!(
            reply_limit(&RCCommand::Channel(
                id,
                ChannelOperation::OpenDirectStreamlocal("/tmp/socket".into())
            )),
            TARGET_FORWARD_OPEN_TIMEOUT
        );
    }

    /// A sign-in that the connection's handle refuses at completion must leave
    /// the session with no user and no identity, whatever the refusal was.
    mod sign_in_completion {
        use std::net::SocketAddr;
        use std::path::PathBuf;

        use sea_orm::{
            ActiveModelTrait, ConnectionTrait, Database, DatabaseConnection, EntityTrait, Set,
        };
        use warpgate_common::{GlobalParams, WarpgateConfig, WarpgateConfigStore};
        use warpgate_core::cluster::Cluster;
        use warpgate_core::login_protection::LoginProtectionService;
        use warpgate_core::rate_limiting::RateLimiterRegistry;
        use warpgate_core::recordings::SessionRecordings;
        use warpgate_core::{
            ApprovalRequestSink, AuthStateStore, DatabaseConfigProvider, SecretBackendRegistry,
            Services, SessionHandle, State, UserSessionStateInit,
        };
        use warpgate_db_entities as entities;
        use warpgate_db_entities::Parameters::{
            ConfigMigrationValues, set_config_migration_values,
        };
        use warpgate_db_migrations::migrate_database;

        use super::super::*;

        const INSIDE: &str = "10.1.2.3";
        const OUTSIDE: &str = "192.0.2.1";

        struct NoopHandle;

        impl SessionHandle for NoopHandle {
            fn close(&mut self) {}
        }

        struct SignIn {
            db: DatabaseConnection,
            session: ServerSession,
            user: AuthStateUserInfo,
            // The client's end of the connection, kept open for the test.
            _client: std::net::TcpStream,
        }

        async fn services(db: &DatabaseConnection, params: GlobalParams) -> Services {
            let rate_limiter_registry = Arc::new(Mutex::new(RateLimiterRegistry::new(db.clone())));
            let cluster = Arc::new(Cluster::new(db.clone(), 0).await.unwrap());
            Services {
                db: db.clone(),
                recordings: Arc::new(SessionRecordings::new(db.clone(), &params)),
                config: Arc::new(Mutex::new(WarpgateConfig {
                    store: WarpgateConfigStore::default(),
                })),
                state: State::new(db, &rate_limiter_registry, cluster.node_id),
                cluster: cluster.clone(),
                rate_limiter_registry,
                config_provider: Arc::new(DatabaseConfigProvider::new(db).into()),
                auth_state_store: Arc::new(Mutex::new(AuthStateStore::new(ApprovalRequestSink {
                    db: db.clone(),
                    cluster,
                }))),
                admin_token: Arc::new(None),
                login_protection: Arc::new(LoginProtectionService::new(db.clone()).await.unwrap()),
                global_params: Arc::new(params),
                listener_status: Default::default(),
                secret_backends: Arc::new(SecretBackendRegistry::new(db.clone())),
                live_streams: Default::default(),
                pending_revocations: Default::default(),
            }
        }

        /// A connection from `ip` whose sign-in is about to complete, as the
        /// server registers it: before its credentials are checked.
        async fn sign_in_from(ip: &str) -> SignIn {
            sign_in_with(
                ip,
                GlobalParams::new(PathBuf::from("/warpgate.yaml"), false).unwrap(),
            )
            .await
        }

        async fn sign_in_with(ip: &str, params: GlobalParams) -> SignIn {
            set_config_migration_values(ConfigMigrationValues::default());
            let db = Database::connect("sqlite::memory:").await.unwrap();
            migrate_database(&db).await.unwrap();
            let user_id = Uuid::new_v4();
            entities::User::ActiveModel {
                id: Set(user_id),
                username: Set("alice".into()),
                description: Set(String::new()),
                credential_policy: Set(sea_orm::JsonValue::Object(Default::default())),
                rate_limit_bytes_per_second: Set(None),
                ldap_server_id: Set(None),
                ldap_object_uuid: Set(None),
                allowed_ip_ranges: Set(sea_orm::JsonValue::Null),
            }
            .insert(&db)
            .await
            .unwrap();
            let services = services(&db, params).await;

            let remote_address = SocketAddr::new(ip.parse().unwrap(), 22);
            let server_handle = State::register_node_local_user_session(
                &services.state,
                crate::PROTOCOL_NAME,
                UserSessionStateInit {
                    remote_address: Some(remote_address),
                    handle: Box::new(NoopHandle),
                },
            )
            .await
            .unwrap();
            let id = server_handle.lock().await.user_session_id();

            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (client_socket, _) = listener.accept().unwrap();

            let rc_handles = RemoteClient::create(id, services.clone()).unwrap();
            let (hub, event_sender) = EventHub::setup(EVENT_QUEUE_CAPACITY);
            let control_events = hub
                .subscribe(|e| !matches!(e, Event::ConsoleInput(_) | Event::Client(_)))
                .await;
            let target_events = hub.subscribe(|e| matches!(e, Event::Client(_))).await;
            let channel_writer = ChannelWriter::new();
            let intake =
                EventIntake::new(control_events, target_events, channel_writer.data_slots());
            let session = ServerSession {
                id,
                user_info: None,
                authorized_identity: None,
                authentication_type: None,
                target_env: None,
                session_handle: None,
                channels: ChannelRegistry::new(),
                channel_inputs: ChannelInputs::default(),
                deferred_server_events: vec![],
                pending_events: VecDeque::new(),
                rc_tx: rc_handles.command_tx,
                rc_abort_tx: rc_handles.abort_tx,
                rc_state: RCState::NotInitialized,
                remote_address,
                services: services.clone(),
                server_handle,
                target: TargetSelection::None,
                target_session_id: None,
                pending_recordings: vec![],
                recording_owner: ssh_recording_owner(),
                recording_refused: false,
                traffic_recorders: HashMap::new(),
                hub,
                event_sender,
                intake,
                service_output: ServiceOutput::new(),
                channel_writer,
                auth_state: None,
                disconnect_token: CancellationToken::new(),
                step_up_pubkeys: None,
                authenticated_pubkeys: Vec::new(),
                step_up_exempt: None,
                step_up_recheck: None,
                step_up_known_deadline: None,
                step_up_read_failures: 0,
                disconnect_description: String::new(),
                keyboard_interactive_state: None,
                cached_successful_ticket_auth: None,
                allowed_auth_methods: get_allowed_auth_methods(&services).await.unwrap(),
                host_key_trust_prompt_active: Arc::new(AtomicBool::new(false)),
                probe: ProbeState::NoAttempt,
                web_auth_waits_used: 0,
                client_socket: Some(client_socket),
            };
            SignIn {
                db,
                session,
                user: AuthStateUserInfo {
                    id: user_id,
                    username: "alice".into(),
                },
                _client: client,
            }
        }

        impl SignIn {
            fn identity(&self) -> AuthorizedIdentity {
                AuthorizedIdentity::for_authenticated_session(
                    self.user.clone(),
                    crate::PROTOCOL_NAME,
                )
            }

            /// The administrator narrows the allowed ranges to leave the
            /// connection's address out, while the sign-in is in progress.
            async fn narrow_ranges(&self) {
                let ranges = sea_orm::JsonValue::Array(vec![sea_orm::JsonValue::String(
                    "10.0.0.0/8".into(),
                )]);
                entities::User::ActiveModel {
                    id: Set(self.user.id),
                    allowed_ip_ranges: Set(ranges),
                    ..Default::default()
                }
                .update(&self.db)
                .await
                .unwrap();
            }

            async fn delete_user(&self) {
                entities::User::Entity::delete_by_id(self.user.id)
                    .exec(&self.db)
                    .await
                    .unwrap();
            }

            async fn handle_user(&self) -> Option<AuthStateUserInfo> {
                self.session
                    .server_handle
                    .lock()
                    .await
                    .user_session_state()
                    .lock()
                    .await
                    .user_info
                    .clone()
            }

            /// Nothing of the sign-in is left on the session or its handle.
            async fn assert_not_signed_in(&self) {
                assert!(self.session.user_info.is_none(), "session user");
                assert!(
                    self.session.authorized_identity.is_none(),
                    "session identity"
                );
                assert_eq!(self.handle_user().await, None, "handle user");
            }
        }

        #[tokio::test]
        async fn a_sign_in_of_a_deleted_user_leaves_no_user_or_identity() {
            let mut s = sign_in_from(INSIDE).await;
            s.delete_user().await;

            let admitted = s
                .session
                .admit_user_sign_in(s.identity(), s.user.clone(), None)
                .await;

            assert!(
                matches!(admitted, Err(WarpgateError::UserNoLongerAdmitted)),
                "{admitted:?}"
            );
            s.assert_not_signed_in().await;
        }

        #[tokio::test]
        async fn a_sign_in_outside_narrowed_ranges_leaves_no_user_or_identity() {
            let mut s = sign_in_from(OUTSIDE).await;
            s.narrow_ranges().await;

            let admitted = s
                .session
                .admit_user_sign_in(s.identity(), s.user.clone(), None)
                .await;

            assert!(
                matches!(admitted, Err(WarpgateError::UserNoLongerAdmitted)),
                "{admitted:?}"
            );
            s.assert_not_signed_in().await;
        }

        /// A failure that is not a refusal (here, the database cannot be
        /// written) leaves the session as unsigned-in as a refusal does.
        #[tokio::test]
        async fn a_sign_in_failing_at_the_handle_leaves_no_user_or_identity() {
            let mut s = sign_in_from(INSIDE).await;
            s.db.execute_unprepared("DROP TABLE user_sessions")
                .await
                .unwrap();

            let admitted = s
                .session
                .admit_user_sign_in(s.identity(), s.user.clone(), None)
                .await;

            assert!(
                matches!(&admitted, Err(error) if !matches!(error, WarpgateError::UserNoLongerAdmitted)),
                "{admitted:?}"
            );
            s.assert_not_signed_in().await;
        }

        /// The ticket sign-in has no identity and calls the accept step
        /// itself; a refusal there leaves no user either.
        #[tokio::test]
        async fn a_refused_accept_step_leaves_no_user() {
            let mut s = sign_in_from(OUTSIDE).await;
            s.narrow_ranges().await;

            let accepted = s.session._auth_accept(s.user.clone(), None).await;

            assert!(
                matches!(accepted, Err(WarpgateError::UserNoLongerAdmitted)),
                "{accepted:?}"
            );
            s.assert_not_signed_in().await;
        }

        /// The other side: an admitted sign-in records both, so the tests
        /// above are not satisfied by a session that never records anything.
        #[tokio::test]
        async fn an_admitted_sign_in_records_the_user_and_the_identity() {
            let mut s = sign_in_from(INSIDE).await;
            s.narrow_ranges().await;

            s.session
                .admit_user_sign_in(s.identity(), s.user.clone(), None)
                .await
                .unwrap();

            assert_eq!(s.session.user_info, Some(s.user.clone()));
            assert_eq!(
                s.session
                    .authorized_identity
                    .as_ref()
                    .map(|identity| identity.user_info().clone()),
                Some(s.user.clone())
            );
            assert_eq!(s.handle_user().await, Some(s.user.clone()));
        }

        /// A session whose recording is enabled but cannot start: the recordings
        /// root is a regular file, so creating the recording directory fails.
        mod unrecorded {
            use entities::Parameters::{RecordingsDiskConfig, RecordingsStorageConfig};
            use sea_orm::IntoActiveModel;

            use super::*;
            use crate::{ForwardedStreamlocalParams, ForwardedTcpIpParams};

            struct Failing {
                s: SignIn,
                _dir: tempfile::TempDir,
            }

            async fn shell_with_failing_recording(refuse: bool, enable: bool) -> Failing {
                let dir = tempfile::tempdir().unwrap();
                std::fs::write(dir.path().join("recordings"), "not a directory").unwrap();
                let params = GlobalParams::new(dir.path().join("warpgate.yaml"), false)
                    .unwrap()
                    .with_refuse_unrecorded_sessions(refuse);
                let mut s = sign_in_with(INSIDE, params).await;
                let mut parameters = entities::Parameters::Entity::get(&s.db)
                    .await
                    .unwrap()
                    .into_active_model();
                parameters.recordings_enable = Set(enable);
                parameters.recordings_storage = Set(serde_json::to_string(
                    &RecordingsStorageConfig::Disk(RecordingsDiskConfig {
                        path: "recordings".into(),
                    }),
                )
                .unwrap());
                parameters.update(&s.db).await.unwrap();

                s.session.target_session_id = Some(TargetSessionId(Uuid::new_v4()));
                let _ = s
                    .session
                    .start_terminal_recording(
                        Uuid::new_v4(),
                        SshRecordingMetadata::Shell { channel: 0 },
                    )
                    .await;
                Failing { s, _dir: dir }
            }

            fn closed(s: &SignIn) -> bool {
                s.session.client_socket.is_none()
            }

            #[tokio::test]
            async fn a_shell_whose_recording_fails_closes_the_connection_when_required() {
                assert!(
                    !GlobalParams::new(PathBuf::from("/warpgate.yaml"), false)
                        .unwrap()
                        .refuse_unrecorded_sessions()
                );
                let f = shell_with_failing_recording(true, true).await;
                assert!(closed(&f.s), "the connection is closed");
                assert_eq!(
                    f.s.session.disconnect_description,
                    WarpgateError::SessionNotRecorded.to_string()
                );
            }

            #[tokio::test]
            async fn with_refusal_off_the_shell_continues_unrecorded() {
                let f = shell_with_failing_recording(false, true).await;
                assert!(!closed(&f.s), "the connection stays open");
                assert_eq!(f.s.session.disconnect_description, "");
            }

            /// Recording switched off is not a failure: nothing is refused.
            #[tokio::test]
            async fn recording_switched_off_refuses_nothing() {
                let f = shell_with_failing_recording(true, false).await;
                assert!(!closed(&f.s), "the connection stays open");
            }

            /// What the session sends towards the target, seen in place of
            /// the client task.
            type Sent = UnboundedReceiver<(RCCommand, Option<RCCommandReply>)>;

            /// A signed-in session, connected to its target, whose next
            /// recording start fails for real: recordings on,
            /// `--recordings-keep-group-read` with files secured, and the
            /// target session's directory under the recordings root a symlink,
            /// which the start refuses to follow.
            struct Connected {
                s: SignIn,
                sent: Sent,
                _dir: tempfile::TempDir,
            }

            async fn connected_with_failing_recording(refuse: bool) -> Connected {
                let dir = tempfile::tempdir().unwrap();
                let id = TargetSessionId(Uuid::new_v4());
                let root = dir.path().join("recordings");
                std::fs::create_dir_all(&root).unwrap();
                std::fs::create_dir_all(dir.path().join("elsewhere")).unwrap();
                std::os::unix::fs::symlink(dir.path().join("elsewhere"), root.join(id.to_string()))
                    .unwrap();
                let params = GlobalParams::new(dir.path().join("warpgate.yaml"), true)
                    .unwrap()
                    .with_recordings_keep_group_read(true)
                    .with_refuse_unrecorded_sessions(refuse);
                let mut s = sign_in_with(INSIDE, params).await;
                enable_recordings(&s.db).await;
                let (tx, sent) = tokio::sync::mpsc::unbounded_channel();
                s.session.rc_tx = tx;
                s.session.rc_state = RCState::Connected;
                s.session.target = TargetSelection::Connected;
                s.session.target_session_id = Some(id);
                Connected { s, sent, _dir: dir }
            }

            async fn enable_recordings(db: &DatabaseConnection) {
                let mut parameters = entities::Parameters::Entity::get(db)
                    .await
                    .unwrap()
                    .into_active_model();
                parameters.recordings_enable = Set(true);
                parameters.recordings_storage = Set(serde_json::to_string(
                    &RecordingsStorageConfig::Disk(RecordingsDiskConfig {
                        path: "recordings".into(),
                    }),
                )
                .unwrap());
                parameters.update(db).await.unwrap();
            }

            fn server_channel(n: u32) -> ServerChannelId {
                use russh::keys::ssh_encoding::Decode;
                ServerChannelId(ChannelId::decode(&mut &n.to_be_bytes()[..]).unwrap())
            }

            /// A session channel the client has opened.
            fn open_session_channel(s: &mut ServerSession, n: u32) -> ServerChannelId {
                let id = server_channel(n);
                let uuid = s.channels.begin_client_open(id);
                let _ = s.channels.confirm(uuid);
                id
            }

            /// Everything sent so far, without waiting.
            fn drain(sent: &mut Sent) -> Vec<RCCommand> {
                let mut out = vec![];
                while let Ok((command, _)) = sent.try_recv() {
                    out.push(command);
                }
                out
            }

            /// A command that dials the target or acts on it. A refused
            /// session may still send `Disconnect`.
            fn reaches_target(command: &RCCommand) -> bool {
                match command {
                    RCCommand::Connect(_) => true,
                    RCCommand::Channel(_, operation) => matches!(
                        operation,
                        ChannelOperation::OpenShell
                            | ChannelOperation::OpenDirectTCPIP(_)
                            | ChannelOperation::OpenDirectStreamlocal(_)
                            | ChannelOperation::RequestEnv(..)
                            | ChannelOperation::RequestShell
                            | ChannelOperation::RequestExec(_)
                    ),
                    _ => false,
                }
            }

            fn assert_refused(c: &Connected, sent: &[RCCommand]) {
                assert!(
                    !sent.iter().any(reaches_target),
                    "sent to the target: {sent:?}"
                );
                assert!(c.s.session.recording_refused);
                assert!(closed(&c.s), "the connection is closed");
            }

            /// Stands in for russh's `ChannelOpenHandle`, recording the reply.
            #[derive(Clone, Default)]
            struct FakeOpen(Arc<std::sync::Mutex<Option<bool>>>);

            impl FakeOpen {
                fn accepted(&self) -> Option<bool> {
                    *self.0.lock().unwrap()
                }
            }

            impl OpenReply for FakeOpen {
                async fn accept(self) {
                    *self.0.lock().unwrap() = Some(true);
                }

                async fn reject(self, _reason: ChannelOpenFailure) {
                    *self.0.lock().unwrap() = Some(false);
                }
            }

            fn direct_tcpip() -> DirectTCPIPParams {
                DirectTCPIPParams {
                    host_to_connect: "db".into(),
                    port_to_connect: 5432,
                    originator_address: "127.0.0.1".into(),
                    originator_port: 40000,
                }
            }

            #[tokio::test]
            async fn a_refused_exec_never_reaches_the_target() {
                let mut c = connected_with_failing_recording(true).await;
                let ch = open_session_channel(&mut c.s.session, 1);
                let (reply, replied) = oneshot::channel();
                c.s.session
                    .handle_server_handler_event(ServerHandlerEvent::ExecRequest(
                        ch,
                        Bytes::from_static(b"id"),
                        reply,
                    ))
                    .await
                    .unwrap();
                let sent = drain(&mut c.sent);
                assert_refused(&c, &sent);
                assert_eq!(replied.await, Ok(false), "the exec request is refused");
            }

            #[tokio::test]
            async fn a_refused_shell_never_reaches_the_target() {
                let mut c = connected_with_failing_recording(true).await;
                let ch = open_session_channel(&mut c.s.session, 1);
                let (reply, replied) = oneshot::channel();
                c.s.session
                    .handle_server_handler_event(ServerHandlerEvent::ShellRequest(ch, reply))
                    .await
                    .unwrap();
                let sent = drain(&mut c.sent);
                assert_refused(&c, &sent);
                assert_eq!(replied.await, Ok(false), "the shell request is refused");
            }

            #[tokio::test]
            async fn a_refused_direct_tcpip_forward_never_reaches_the_target() {
                let mut c = connected_with_failing_recording(true).await;
                let open = FakeOpen::default();
                c.s.session
                    ._channel_open_direct_tcpip(server_channel(1), direct_tcpip(), open.clone())
                    .await
                    .unwrap();
                let sent = drain(&mut c.sent);
                assert_refused(&c, &sent);
                assert_eq!(open.accepted(), Some(false), "the open is rejected");
            }

            #[tokio::test]
            async fn a_refused_direct_streamlocal_forward_never_reaches_the_target() {
                let mut c = connected_with_failing_recording(true).await;
                let open = FakeOpen::default();
                c.s.session
                    ._channel_open_direct_streamlocal(
                        server_channel(1),
                        "/run/app.sock".into(),
                        open.clone(),
                    )
                    .await
                    .unwrap();
                let sent = drain(&mut c.sent);
                assert_refused(&c, &sent);
                assert_eq!(open.accepted(), Some(false), "the open is rejected");
            }

            /// A forward from the target is refused before a channel to the
            /// client is opened for it.
            #[tokio::test]
            async fn a_refused_reverse_forward_opens_nothing_to_the_client() {
                let mut c = connected_with_failing_recording(true).await;
                let tcp = Uuid::new_v4();
                c.s.session
                    .handle_remote_event(RCEvent::ForwardedTcpIp(
                        tcp,
                        ForwardedTcpIpParams {
                            connected_address: "0.0.0.0".into(),
                            connected_port: 8080,
                            originator_address: "10.0.0.9".into(),
                            originator_port: 50000,
                        },
                    ))
                    .await
                    .unwrap();
                let socket = Uuid::new_v4();
                c.s.session
                    .handle_remote_event(RCEvent::ForwardedStreamlocal(
                        socket,
                        ForwardedStreamlocalParams {
                            socket_path: "/run/app.sock".into(),
                        },
                    ))
                    .await
                    .unwrap();
                let sent = drain(&mut c.sent);
                assert_refused(&c, &sent);
                assert!(c.s.session.channels.get(&tcp).is_none());
                assert!(c.s.session.channels.get(&socket).is_none());
            }

            /// With refusal off (the default), the same failing start lets
            /// each kind of session through, unrecorded.
            #[tokio::test]
            async fn with_refusal_off_the_same_failures_go_through_unrecorded() {
                let mut c = connected_with_failing_recording(false).await;
                let ch = open_session_channel(&mut c.s.session, 1);
                c.s.session
                    ._channel_exec_request(ch, Bytes::from_static(b"id"))
                    .await
                    .unwrap();
                let ch = open_session_channel(&mut c.s.session, 2);
                let (reply, replied) = oneshot::channel();
                // The shell goes to the target; the request then stops short of
                // its success reply only because this harness has no russh
                // client handle to send it on.
                let shell =
                    c.s.session
                        .handle_server_handler_event(ServerHandlerEvent::ShellRequest(ch, reply))
                        .await;
                assert!(
                    shell.is_err_and(|e| e.to_string().contains("Invalid session state")),
                    "the shell request got past the recording"
                );
                assert_ne!(replied.await, Ok(false), "the shell request is not refused");
                let sent = drain(&mut c.sent);
                assert!(
                    sent.iter().any(|x| matches!(
                        x,
                        RCCommand::Channel(_, ChannelOperation::RequestExec(_))
                    ))
                );
                assert!(
                    sent.iter().any(|x| matches!(
                        x,
                        RCCommand::Channel(_, ChannelOperation::RequestShell)
                    ))
                );

                let open = FakeOpen::default();
                let session = &mut c.s.session;
                let target = &mut c.sent;
                let ((), command) = tokio::join!(
                    async {
                        session
                            ._channel_open_direct_tcpip(
                                server_channel(3),
                                direct_tcpip(),
                                open.clone(),
                            )
                            .await
                            .unwrap();
                    },
                    async {
                        let (command, reply) = target.recv().await.unwrap();
                        let _ = reply.unwrap().send(Ok(()));
                        command
                    }
                );
                assert!(matches!(
                    command,
                    RCCommand::Channel(_, ChannelOperation::OpenDirectTCPIP(_))
                ));
                assert_eq!(open.accepted(), Some(true));
                assert!(!c.s.session.recording_refused);
                assert!(!closed(&c.s), "the connection stays open");
            }

            /// A direct forward opened before its target session exists
            /// (behind an approval gate) cannot be recorded: refused when
            /// unrecorded sessions are refused and recording is on, let
            /// through otherwise.
            #[tokio::test]
            async fn a_direct_forward_before_the_target_session_follows_the_setting() {
                for (refuse, recording) in [(true, true), (false, true), (true, false)] {
                    let mut c = connected_with_failing_recording(refuse).await;
                    c.s.session.target_session_id = None;
                    if !recording {
                        let mut parameters = entities::Parameters::Entity::get(&c.s.db)
                            .await
                            .unwrap()
                            .into_active_model();
                        parameters.recordings_enable = Set(false);
                        parameters.update(&c.s.db).await.unwrap();
                    }
                    let open = FakeOpen::default();
                    let session = &mut c.s.session;
                    let target = &mut c.sent;
                    let opened = tokio::select! {
                        () = async {
                            session
                                ._channel_open_direct_tcpip(
                                    server_channel(1),
                                    direct_tcpip(),
                                    open.clone(),
                                )
                                .await
                                .unwrap();
                        } => false,
                        // An open that went out waits for this reply, so this
                        // branch wins whenever the target was reached.
                        Some((command, reply)) = target.recv() => {
                            let _ = reply.map(|r| r.send(Ok(())));
                            reaches_target(&command)
                        }
                    };
                    let refused = refuse && recording;
                    assert_eq!(opened, !refused, "refuse: {refuse}, recording: {recording}");
                    if refused {
                        assert_eq!(open.accepted(), Some(false));
                    }
                }
            }

            /// A shell parked for an approval gate is recorded when the gate
            /// lets it through; if that start is refused, the connect that
            /// follows the stamp must not dial the target.
            #[tokio::test]
            async fn a_recording_refused_at_the_stamp_never_dials_the_target() {
                let dir = tempfile::tempdir().unwrap();
                // The target session's id is minted at the stamp, so the root
                // itself is made unusable: a regular file.
                std::fs::write(dir.path().join("recordings"), "not a directory").unwrap();
                let params = GlobalParams::new(dir.path().join("warpgate.yaml"), false)
                    .unwrap()
                    .with_refuse_unrecorded_sessions(true);
                let mut s = sign_in_with(INSIDE, params).await;
                enable_recordings(&s.db).await;
                let (tx, mut sent) = tokio::sync::mpsc::unbounded_channel();
                s.session.rc_tx = tx;
                let ch = open_session_channel(&mut s.session, 1);
                let channel = s.session.map_channel(ch).unwrap();
                let _ = s
                    .session
                    .start_terminal_recording(channel, SshRecordingMetadata::Shell { channel: 1 })
                    .await;
                assert_eq!(s.session.pending_recordings.len(), 1, "parked");

                let options: TargetSSHOptions = serde_json::from_value(serde_json::json!({
                    "host": "target.invalid",
                    "username": "alice",
                }))
                .unwrap();
                let target = warpgate_common::Target {
                    id: Uuid::new_v4(),
                    name: "box".into(),
                    description: String::new(),
                    allow_roles: vec![],
                    options: TargetOptions::Ssh(options),
                    rate_limit_bytes_per_second: None,
                    group_id: None,
                    ticket_max_duration_seconds: None,
                    ticket_requests_disabled: false,
                    ticket_require_approval: false,
                    require_approval: false,
                    ticket_max_uses: None,
                };
                let authorization = warpgate_core::TargetAuthorization::for_ticket_session(
                    s.user.clone(),
                    target,
                    None,
                    warpgate_common::Protocol::Ssh,
                )
                .unwrap()
                .narrow::<TargetSSHOptions>()
                .unwrap();
                let started = s
                    .session
                    .server_handle
                    .lock()
                    .await
                    .start_target_session(authorization)
                    .await
                    .unwrap();
                let TargetSessionStart::Started(admitted) = started else {
                    panic!("no approval is required");
                };

                s.session.stamp_approved_target(admitted).await;
                let connected = s.session.maybe_connect_remote().await;

                let sent = drain(&mut sent);
                assert!(
                    !sent.iter().any(|c| matches!(c, RCCommand::Connect(_))),
                    "dialled: {sent:?}"
                );
                assert!(matches!(
                    connected.unwrap_err().downcast_ref::<WarpgateError>(),
                    Some(WarpgateError::SessionNotRecorded)
                ));
                assert!(closed(&s), "the connection is closed");
            }

            /// A connected shell channel whose recording started, on a real disk
            /// root that [`fail_open_recording_files`] can fail mid-session.
            #[cfg(target_os = "linux")]
            struct Recorded {
                s: SignIn,
                sent: Sent,
                root: PathBuf,
                id: TargetSessionId,
                ch: ServerChannelId,
                channel: Uuid,
                required: bool,
                _dir: tempfile::TempDir,
            }

            /// As [`recorded_shell`], before the channel's recording is started.
            #[cfg(target_os = "linux")]
            async fn connected_shell(refuse: bool) -> Recorded {
                warpgate_core::recordings::test_support::log_events();
                let dir = tempfile::tempdir().unwrap();
                let params = GlobalParams::new(dir.path().join("warpgate.yaml"), false)
                    .unwrap()
                    .with_refuse_unrecorded_sessions(refuse);
                let mut s = sign_in_with(INSIDE, params).await;
                enable_recordings(&s.db).await;
                let id = TargetSessionId(Uuid::new_v4());
                entities::TargetSession::ActiveModel {
                    id: Set(id),
                    user_session_id: Set(s.session.id),
                    target_snapshot: Set("{}".into()),
                    target_id: Set(Uuid::new_v4()),
                    started: Set(time::OffsetDateTime::now_utc()),
                    ..Default::default()
                }
                .insert(&s.db)
                .await
                .unwrap();
                let (tx, sent) = tokio::sync::mpsc::unbounded_channel();
                s.session.rc_tx = tx;
                s.session.rc_state = RCState::Connected;
                s.session.target = TargetSelection::Connected;
                s.session.target_session_id = Some(id);
                // Set when the target is selected.
                s.session.recording_owner = RecordingOwner {
                    user: "alice".into(),
                    target: "box".into(),
                    ..ssh_recording_owner()
                };
                let ch = open_session_channel(&mut s.session, 1);
                let channel = s.session.map_channel(ch).unwrap();
                Recorded {
                    s,
                    sent,
                    root: dir.path().join("recordings"),
                    id,
                    ch,
                    channel,
                    required: refuse,
                    _dir: dir,
                }
            }

            #[cfg(target_os = "linux")]
            async fn recorded_shell(refuse: bool) -> Recorded {
                let mut r = connected_shell(refuse).await;
                assert!(
                    r.s.session
                        .start_terminal_recording(r.channel, SshRecordingMetadata::Shell { channel: 1 })
                        .await
                        .is_continue()
                );
                r
            }

            #[cfg(target_os = "linux")]
            impl Recorded {
                fn failures(&self) -> u64 {
                    self.s.session.services.recordings.failed_recordings()
                }

                /// Fails the recording's open files, as a full disk would.
                fn fail_recording(&self) {
                    assert!(
                        warpgate_core::recordings::test_support::fail_open_recording_files(
                            &self.root
                        ) >= 2,
                        "the data and index files were broken"
                    );
                }

                /// The recorder's own task logs the failure as soon as it happens;
                /// the session sees it at its next write, which fails. So when
                /// required, wait for the close; otherwise for the log line.
                fn failure_seen(&self) -> bool {
                    if self.required {
                        closed(&self.s)
                    } else {
                        self.failures() > 0
                    }
                }

                /// Sends input until the failure is seen (the writes are queued, so
                /// the first ones after the break can still be accepted). Returns
                /// how many inputs were sent and how many reached the target.
                async fn input_until_failure(&mut self) -> (usize, usize) {
                    let mut inputs = 0;
                    let mut forwarded = 0;
                    for _ in 0..1000 {
                        self.s
                            .session
                            ._data(self.ch, Bytes::from_static(b"input"))
                            .await
                            .unwrap();
                        inputs += 1;
                        forwarded += data_sent(&drain(&mut self.sent));
                        if self.failure_seen() {
                            return (inputs, forwarded);
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                    }
                    panic!("the recording never failed");
                }

                /// Delivers target output until the failure is seen.
                async fn output_until_failure(&mut self) {
                    for _ in 0..1000 {
                        let _ = self
                            .s
                            .session
                            .handle_remote_event(RCEvent::Output(
                                self.channel,
                                Bytes::from_static(b"output"),
                            ))
                            .await;
                        if self.failure_seen() {
                            return;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                    }
                    panic!("the recording never failed");
                }

                fn assert_one_failure_line(&self, required: bool) {
                    assert_eq!(self.failures(), 1);
                    let lines =
                        warpgate_core::recordings::test_support::failed_recording_lines(&self.id);
                    assert_eq!(lines.len(), 1, "{lines:?}");
                    assert_eq!(lines[0]["protocol"], "ssh");
                    assert_eq!(lines[0]["user"], "alice");
                    assert_eq!(lines[0]["target"], "box");
                    assert_eq!(lines[0]["stage"], "write");
                    assert_eq!(lines[0]["required"], required.to_string());
                }

                fn assert_closed_for_failure(&self) {
                    assert!(closed(&self.s), "the connection is closed");
                    assert!(self.s.session.recording_refused);
                    assert_eq!(
                        self.s.session.disconnect_description,
                        WarpgateError::SessionRecordingFailed.to_string()
                    );
                }
            }

            #[cfg(target_os = "linux")]
            fn data_sent(sent: &[RCCommand]) -> usize {
                sent.iter()
                    .filter(|c| matches!(c, RCCommand::Channel(_, ChannelOperation::Data(_))))
                    .count()
            }

            /// Required recording failing on input: the connection closes and the
            /// input that could not be recorded never reaches the target.
            #[cfg(target_os = "linux")]
            #[tokio::test]
            async fn input_whose_recording_fails_closes_the_session_when_required() {
                let mut r = recorded_shell(true).await;
                r.s.session
                    ._data(r.ch, Bytes::from_static(b"recorded"))
                    .await
                    .unwrap();
                assert_eq!(data_sent(&drain(&mut r.sent)), 1);
                r.fail_recording();

                let (inputs, forwarded) = r.input_until_failure().await;
                r.assert_closed_for_failure();
                assert_eq!(
                    forwarded,
                    inputs - 1,
                    "the input whose recording failed was not forwarded"
                );
                r.assert_one_failure_line(true);
            }

            /// Required recording failing on output: the connection closes.
            #[cfg(target_os = "linux")]
            #[tokio::test]
            async fn output_whose_recording_fails_closes_the_session_when_required() {
                let mut r = recorded_shell(true).await;
                r.fail_recording();
                r.output_until_failure().await;
                r.assert_closed_for_failure();
                r.assert_one_failure_line(true);
            }

            /// Not required (the default): the session goes on unrecorded, all
            /// input reaches the target, and the failure is logged and counted once.
            #[cfg(target_os = "linux")]
            #[tokio::test]
            async fn with_refusal_off_a_failing_recording_closes_nothing() {
                let mut r = recorded_shell(false).await;
                r.fail_recording();
                let (inputs, forwarded) = r.input_until_failure().await;
                assert_eq!(forwarded, inputs, "every input was forwarded");
                for _ in 0..3 {
                    r.s.session
                        ._data(r.ch, Bytes::from_static(b"more"))
                        .await
                        .unwrap();
                    let _ = r
                        .s
                        .session
                        .handle_remote_event(RCEvent::Output(
                            r.channel,
                            Bytes::from_static(b"output"),
                        ))
                        .await;
                }
                assert_eq!(data_sent(&drain(&mut r.sent)), 3);
                assert!(!closed(&r.s), "the connection stays open");
                assert!(!r.s.session.recording_refused);
                r.assert_one_failure_line(false);
            }

            /// Not required, failing on output: the connection stays open.
            #[cfg(target_os = "linux")]
            #[tokio::test]
            async fn with_refusal_off_failing_output_closes_nothing() {
                let mut r = recorded_shell(false).await;
                r.fail_recording();
                r.output_until_failure().await;
                assert!(!closed(&r.s), "the connection stays open");
                r.assert_one_failure_line(false);
            }

            /// A forward to an address an earlier forward already made a traffic
            /// recorder for, which has died since: the failure is seen before the
            /// open goes to the target. Required: the open is rejected and the
            /// connection closed; otherwise the forward opens, unrecorded.
            #[cfg(target_os = "linux")]
            #[tokio::test]
            async fn a_forward_on_a_dead_traffic_recorder_follows_the_setting() {
                for required in [true, false] {
                    let mut r = recorded_shell(required).await;
                    let params = direct_tcpip();
                    let key = TrafficRecorderKey::Tcp(
                        params.host_to_connect.clone(),
                        params.port_to_connect,
                    );
                    assert!(
                        r.s.session
                            .prepare_traffic_recorder(
                                &key,
                                SshRecordingMetadata::DirectTcpIp {
                                    host: params.host_to_connect.clone(),
                                    port: params.port_to_connect as u16,
                                },
                            )
                            .await
                            .is_continue()
                    );
                    r.fail_recording();
                    let mut probe = r.s.session.traffic_recorders[&key].connection(
                        TrafficConnectionParams::Socket {
                            socket_path: "/probe".into(),
                        },
                    );
                    let mut died = false;
                    for _ in 0..1000 {
                        if probe.write_connection_setup().await.is_err() {
                            died = true;
                            break;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                    }
                    assert!(died, "the traffic recorder died");
                    drop(probe);
                    assert!(!closed(&r.s), "nothing has closed the connection yet");

                    let open = FakeOpen::default();
                    if required {
                        // Refused without waiting on the target.
                        r.s.session
                            ._channel_open_direct_tcpip(
                                server_channel(2),
                                direct_tcpip(),
                                open.clone(),
                            )
                            .await
                            .unwrap();
                        let sent = drain(&mut r.sent);
                        assert!(
                            !sent.iter().any(reaches_target),
                            "sent to the target: {sent:?}"
                        );
                        assert_eq!(open.accepted(), Some(false), "the open is rejected");
                        r.assert_closed_for_failure();
                        continue;
                    }
                    let session = &mut r.s.session;
                    let target = &mut r.sent;
                    let opened = tokio::select! {
                        () = async {
                            session
                                ._channel_open_direct_tcpip(
                                    server_channel(2),
                                    direct_tcpip(),
                                    open.clone(),
                                )
                                .await
                                .unwrap();
                        } => false,
                        // An open that went out waits for this reply, so this
                        // branch wins whenever the target was reached.
                        Some((command, reply)) = target.recv() => {
                            let _ = reply.map(|r| r.send(Ok(())));
                            reaches_target(&command)
                        }
                    };
                    assert!(opened, "the forward opens, unrecorded");
                    {
                        assert!(!closed(&r.s), "the connection stays open");
                    }
                }
            }

            /// Data and extended data the client sends on a session channel before
            /// its exec request have no recording to go to, yet the target's
            /// session channel is open. Required: both are dropped, and the
            /// command's own input, sent after the request, is recorded and
            /// forwarded; client extended data stays dropped. Otherwise everything
            /// is forwarded, as before.
            #[cfg(target_os = "linux")]
            #[tokio::test]
            async fn data_before_a_session_channels_request_is_dropped_when_required() {
                for required in [true, false] {
                    let mut r = connected_shell(required).await;
                    let ch = server_channel(2);
                    let open = FakeOpen::default();
                    let session = &mut r.s.session;
                    let target = &mut r.sent;
                    tokio::join!(
                        async {
                            session
                                ._channel_open(ch, ChannelOperation::OpenShell, None, open.clone())
                                .await
                                .unwrap();
                        },
                        async {
                            let (command, reply) = target.recv().await.unwrap();
                            assert!(
                                matches!(
                                    command,
                                    RCCommand::Channel(_, ChannelOperation::OpenShell)
                                ),
                                "{command:?}"
                            );
                            let _ = reply.map(|r| r.send(Ok(())));
                        }
                    );
                    assert_eq!(open.accepted(), Some(true));
                    drain(&mut r.sent);

                    let early = [
                        ServerHandlerEvent::Data(
                            ch,
                            Bytes::from_static(b"early"),
                            oneshot::channel().0,
                        ),
                        ServerHandlerEvent::ExtendedData(
                            ch,
                            Bytes::from_static(b"early-ext"),
                            1,
                            oneshot::channel().0,
                        ),
                    ];
                    for event in early {
                        r.s.session
                            .handle_server_handler_event(event)
                            .await
                            .unwrap();
                    }
                    let forwarded = |sent: &[RCCommand]| -> Vec<Vec<u8>> {
                        sent.iter()
                            .filter_map(|c| match c {
                                RCCommand::Channel(
                                    _,
                                    ChannelOperation::Data(data)
                                    | ChannelOperation::ExtendedData { data, .. },
                                ) => Some(data.to_vec()),
                                _ => None,
                            })
                            .collect()
                    };
                    let sent = drain(&mut r.sent);
                    if required {
                        assert!(forwarded(&sent).is_empty(), "forwarded: {sent:?}");
                    } else {
                        assert_eq!(
                            forwarded(&sent),
                            vec![b"early".to_vec(), b"early-ext".to_vec()]
                        );
                    }

                    let (reply, replied) = oneshot::channel();
                    r.s.session
                        .handle_server_handler_event(ServerHandlerEvent::ExecRequest(
                            ch,
                            Bytes::from_static(b"cat"),
                            reply,
                        ))
                        .await
                        .unwrap();
                    assert_eq!(replied.await, Ok(true));
                    drain(&mut r.sent);
                    r.s.session
                        .handle_server_handler_event(ServerHandlerEvent::Data(
                            ch,
                            Bytes::from_static(b"input"),
                            oneshot::channel().0,
                        ))
                        .await
                        .unwrap();
                    r.s.session
                        .handle_server_handler_event(ServerHandlerEvent::ExtendedData(
                            ch,
                            Bytes::from_static(b"ext"),
                            1,
                            oneshot::channel().0,
                        ))
                        .await
                        .unwrap();
                    let sent = drain(&mut r.sent);
                    if required {
                        assert_eq!(forwarded(&sent), vec![b"input".to_vec()]);
                    } else {
                        assert_eq!(forwarded(&sent), vec![b"input".to_vec(), b"ext".to_vec()]);
                    }
                    assert!(!closed(&r.s), "the session goes on");
                }
            }

            /// A shell channel whose recording starts on files that cannot be written
            /// (a full disk). Required: the session closes before anything of the
            /// channel reaches the target. Otherwise the channel goes on, its first
            /// writes not waited for.
            #[cfg(target_os = "linux")]
            #[tokio::test]
            async fn a_shell_recording_that_cannot_be_written_follows_the_setting_at_start() {
                for required in [true, false] {
                    let mut r = connected_shell(required).await;
                    let started = r
                        .s
                        .session
                        .services
                        .recordings
                        .start_for::<TerminalRecorder, _>(
                            &r.s.session.recording_owner,
                            &r.id,
                            None,
                            SshRecordingMetadata::Shell { channel: 1 },
                        )
                        .await;
                    r.fail_recording();
                    let flow = r
                        .s
                        .session
                        .attach_terminal_recording(r.channel, started)
                        .await;
                    let sent = drain(&mut r.sent);
                    assert!(!sent.iter().any(reaches_target), "sent: {sent:?}");
                    if required {
                        assert!(flow.is_break(), "refused at start");
                        r.assert_closed_for_failure();
                        r.assert_one_failure_line(true);
                    } else {
                        assert!(flow.is_continue());
                        assert!(!closed(&r.s), "the connection stays open");
                    }
                }
            }

            /// A forward's first connection on a traffic recording whose file
            /// cannot be written (a full disk). Required: its setup record is waited
            /// for, so the open is rejected and nothing reaches the target.
            /// Otherwise the forward opens.
            #[cfg(target_os = "linux")]
            #[tokio::test]
            async fn a_forward_whose_recording_cannot_be_written_follows_the_setting() {
                for required in [true, false] {
                    let mut r = recorded_shell(required).await;
                    let params = direct_tcpip();
                    let key = TrafficRecorderKey::Tcp(
                        params.host_to_connect.clone(),
                        params.port_to_connect,
                    );
                    assert!(
                        r.s.session
                            .prepare_traffic_recorder(
                                &key,
                                SshRecordingMetadata::DirectTcpIp {
                                    host: params.host_to_connect.clone(),
                                    port: params.port_to_connect as u16,
                                },
                            )
                            .await
                            .is_continue()
                    );
                    r.fail_recording();
                    let open = FakeOpen::default();
                    if required {
                        r.s.session
                            ._channel_open_direct_tcpip(
                                server_channel(2),
                                direct_tcpip(),
                                open.clone(),
                            )
                            .await
                            .unwrap();
                        let sent = drain(&mut r.sent);
                        assert!(
                            !sent.iter().any(reaches_target),
                            "sent to the target: {sent:?}"
                        );
                        assert_eq!(open.accepted(), Some(false), "the open is rejected");
                        r.assert_closed_for_failure();
                        continue;
                    }
                    let session = &mut r.s.session;
                    let target = &mut r.sent;
                    let opened = tokio::select! {
                        () = async {
                            session
                                ._channel_open_direct_tcpip(
                                    server_channel(2),
                                    direct_tcpip(),
                                    open.clone(),
                                )
                                .await
                                .unwrap();
                        } => false,
                        Some((command, reply)) = target.recv() => {
                            let _ = reply.map(|r| r.send(Ok(())));
                            reaches_target(&command)
                        }
                    };
                    assert!(opened, "the forward opens");
                    assert!(!closed(&r.s), "the connection stays open");
                }
            }

            /// A reverse forward from the target to an address an earlier one
            /// already made a traffic recorder for, which has died since: the
            /// failure is seen before the channel is opened to the client.
            /// Required: the connection closes; otherwise the forward goes on.
            #[cfg(target_os = "linux")]
            #[tokio::test]
            async fn a_reverse_forward_on_a_dead_traffic_recorder_follows_the_setting() {
                for required in [true, false] {
                    let mut r = recorded_shell(required).await;
                    let params = crate::ForwardedTcpIpParams {
                        connected_address: "127.0.0.1".into(),
                        connected_port: 8080,
                        originator_address: "10.0.0.2".into(),
                        originator_port: 40000,
                    };
                    let key = TrafficRecorderKey::Tcp(
                        params.originator_address.clone(),
                        params.originator_port,
                    );
                    assert!(
                        r.s.session
                            .prepare_traffic_recorder(
                                &key,
                                SshRecordingMetadata::ForwardedTcpIp {
                                    host: params.originator_address.clone(),
                                    port: params.originator_port as u16,
                                },
                            )
                            .await
                            .is_continue()
                    );
                    r.fail_recording();
                    let mut probe = r.s.session.traffic_recorders[&key].connection(
                        TrafficConnectionParams::Socket {
                            socket_path: "/probe".into(),
                        },
                    );
                    let mut died = false;
                    for _ in 0..1000 {
                        if probe.write_connection_setup().await.is_err() {
                            died = true;
                            break;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                    }
                    assert!(died, "the traffic recorder died");
                    drop(probe);
                    assert!(!closed(&r.s), "nothing has closed the connection yet");

                    let _ = r
                        .s
                        .session
                        .handle_remote_event(RCEvent::ForwardedTcpIp(Uuid::new_v4(), params))
                        .await;
                    if required {
                        r.assert_closed_for_failure();
                    } else {
                        assert!(!closed(&r.s), "the connection stays open");
                    }
                    r.assert_one_failure_line(required);
                }
            }
        }
    }
}

impl std::fmt::Debug for ServerSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", session_debug_tag(&self.id, &self.remote_address))
    }
}

/// The reply to a client's channel open: [`ChannelOpenHandle`] in the server,
/// a stand-in in tests (a russh handle cannot be built outside russh).
pub(crate) trait OpenReply: Send {
    fn accept(self) -> impl Future<Output = ()> + Send;
    fn reject(self, reason: ChannelOpenFailure) -> impl Future<Output = ()> + Send;
}

impl OpenReply for ChannelOpenHandle {
    fn accept(self) -> impl Future<Output = ()> + Send {
        ChannelOpenHandle::accept(self)
    }

    fn reject(self, reason: ChannelOpenFailure) -> impl Future<Output = ()> + Send {
        ChannelOpenHandle::reject(self, reason)
    }
}

impl ServerSession {
    pub async fn start(
        remote_address: SocketAddr,
        services: &Services,
        server_handle: Arc<Mutex<WarpgateServerHandle>>,
        mut session_handle_rx: UnboundedReceiver<SessionHandleCommand>,
        mut handler_event_rx: UnboundedReceiver<ServerHandlerEvent>,
        channel_inputs: ChannelInputs,
        client_socket: std::net::TcpStream,
    ) -> Result<impl Future<Output = Result<()>> + use<>> {
        let id = server_handle.lock().await.user_session_id();

        // The span goes on the futures, not on the thread: an `enter()` guard
        // held across the awaits below stayed entered on whichever worker
        // thread the setup last ran on, and that thread's later log lines,
        // from other connections, carried this session's span.
        let span_ = info_span!("SSH", session=%id);
        let session = Self::start_in_span(
            id,
            remote_address,
            services,
            server_handle,
            session_handle_rx,
            handler_event_rx,
            channel_inputs,
            client_socket,
        )
        .instrument(span_.clone())
        .await?;
        Ok(session.instrument(span_))
    }

    async fn start_in_span(
        id: UserSessionId,
        remote_address: SocketAddr,
        services: &Services,
        server_handle: Arc<Mutex<WarpgateServerHandle>>,
        mut session_handle_rx: UnboundedReceiver<SessionHandleCommand>,
        mut handler_event_rx: UnboundedReceiver<ServerHandlerEvent>,
        channel_inputs: ChannelInputs,
        client_socket: std::net::TcpStream,
    ) -> Result<impl Future<Output = Result<()>> + use<>> {
        let mut rc_handles = RemoteClient::create(id, services.clone())?;

        let (hub, event_sender) = EventHub::setup(EVENT_QUEUE_CAPACITY);
        let control_events = hub
            .subscribe(|e| !matches!(e, Event::ConsoleInput(_) | Event::Client(_)))
            .await;
        let target_events = hub.subscribe(|e| matches!(e, Event::Client(_))).await;
        let channel_writer = ChannelWriter::new();
        let intake = EventIntake::new(control_events, target_events, channel_writer.data_slots());

        let mut this = Self {
            id,
            user_info: None,
            authorized_identity: None,
            authentication_type: None,
            target_env: None,
            session_handle: None,
            channels: ChannelRegistry::new(),
            channel_inputs,
            deferred_server_events: vec![],
            pending_events: VecDeque::new(),
            rc_tx: rc_handles.command_tx.clone(),
            rc_abort_tx: rc_handles.abort_tx,
            rc_state: RCState::NotInitialized,
            remote_address,
            services: services.clone(),
            server_handle,
            target: TargetSelection::None,
            target_session_id: None,
            pending_recordings: vec![],
            recording_owner: ssh_recording_owner(),
            recording_refused: false,
            traffic_recorders: HashMap::new(),
            hub,
            event_sender: event_sender.clone(),
            intake,
            service_output: ServiceOutput::new(),
            channel_writer,
            auth_state: None,
            disconnect_token: CancellationToken::new(),
            step_up_pubkeys: None,
            authenticated_pubkeys: Vec::new(),
            step_up_exempt: None,
            step_up_recheck: None,
            step_up_known_deadline: None,
            step_up_read_failures: 0,
            disconnect_description: String::new(),
            keyboard_interactive_state: None,
            cached_successful_ticket_auth: None,
            allowed_auth_methods: get_allowed_auth_methods(services).await?,
            host_key_trust_prompt_active: Arc::new(AtomicBool::new(false)),
            probe: ProbeState::NoAttempt,
            web_auth_waits_used: 0,
            client_socket: Some(client_socket),
        };

        let mut so_rx = this.service_output.subscribe();
        let so_sender = event_sender.clone();
        tokio::spawn(async move {
            loop {
                match so_rx.recv().await {
                    Ok(data) => {
                        if so_sender
                            .send_once(Event::ServiceOutput(data))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                    Err(_) => (),
                }
            }
        });

        let name = format!("SSH {id} session control");
        tokio::task::Builder::new().name(&name).spawn({
            let sender = event_sender.clone();
            let disconnect_token = this.disconnect_token.clone();
            async move {
                while let Some(command) = session_handle_rx.recv().await {
                    if matches!(command, SessionHandleCommand::Close) {
                        disconnect_token.cancel();
                    }
                    if sender.send_once(Event::Command(command)).await.is_err() {
                        break;
                    }
                }
                disconnect_token.cancel();
            }
        })?;

        let name = format!("SSH {id} client events");
        tokio::task::Builder::new().name(&name).spawn({
            let sender = event_sender.clone();
            async move {
                while let Some(e) = rc_handles.event_rx.recv().await {
                    if sender.send_once(Event::Client(e)).await.is_err() {
                        break;
                    }
                }
            }
        })?;

        let name = format!("SSH {id} server handler events");
        tokio::task::Builder::new().name(&name).spawn({
            let sender: EventSender<Event> = event_sender.clone();
            let disconnect_token = this.disconnect_token.clone();
            async move {
                while let Some(e) = handler_event_rx.recv().await {
                    if matches!(e, ServerHandlerEvent::Disconnect) {
                        disconnect_token.cancel();
                    }
                    if sender.send_once(Event::ServerHandler(e)).await.is_err() {
                        break;
                    }
                }
                disconnect_token.cancel();
            }
        })?;

        let inactivity_timeout = services.config.lock().await.store.ssh.inactivity_timeout;

        Ok(async move {
            let mut idle_since = Instant::now();
            let result = loop {
                if let Some(event) = this.pending_events.pop_front() {
                    idle_since = Instant::now();
                    if let Err(error) = this.handle_event(event).await {
                        break Err(error);
                    }
                    continue;
                }
                let inactivity_timeout = if matches!(this.target, TargetSelection::AwaitingApproval)
                {
                    // Session waiting for approval will produce no events either way
                    // and we don't want to kill it
                    None
                } else {
                    Some(inactivity_timeout)
                };
                // The idle deadline is last real activity + timeout and moves
                // only on a real event, so a step-up recheck never restarts it.
                let idle_wait = inactivity_timeout.map(|timeout| {
                    (idle_since + timeout).saturating_duration_since(Instant::now())
                });
                let step_up_wait = this
                    .step_up_recheck
                    .map(|at| at.saturating_duration_since(Instant::now()));
                let next_event_fut = this.get_next_event();
                let idle_due = async {
                    match idle_wait {
                        Some(wait) => tokio::time::sleep(wait).await,
                        None => std::future::pending::<()>().await,
                    }
                };
                let step_up_due = async {
                    match step_up_wait {
                        Some(wait) => tokio::time::sleep(wait).await,
                        None => std::future::pending::<()>().await,
                    }
                };
                let woke = tokio::select! {
                    next_event = next_event_fut => Woke::Event(next_event),
                    () = idle_due => Woke::Idle,
                    () = step_up_due => Woke::StepUp,
                };
                match woke {
                    Woke::Event(Some(event)) => {
                        idle_since = Instant::now();
                        if let Err(error) = this.handle_event(event).await {
                            break Err(error);
                        }
                    }
                    Woke::Event(None) => break Ok(()),
                    Woke::Idle => {
                        info!("Closing the session due to inactivity");
                        let _ = this.emit_service_message("Closing the session due to inactivity");
                        this.request_disconnect();
                        this.disconnect_server().await;
                        break Ok(());
                    }
                    Woke::StepUp => {
                        if this.enforce_step_up_window().await {
                            break Ok(());
                        }
                    }
                }
            };
            debug!("No more events");
            this.settle_failed_probe().await;
            result?;
            Ok::<_, anyhow::Error>(())
        })
    }

    /// Evaluate this connection's step-up window against the live config and
    /// the key's current `last_sso_at`, and schedule the next look. Returns
    /// `true` when the window has passed and the connection was closed.
    async fn enforce_step_up_window(&mut self) -> bool {
        if let Some(grant) = self.step_up_exempt.clone() {
            let step_up = {
                let cfg = self.services.config.lock().await;
                cfg.store.step_up_interval.clone()
            };
            let result = exempt_recheck(
                &grant,
                step_up.as_ref(),
                &self.services.db,
                grant.granted_at.elapsed(),
            )
            .await;
            let tick = exempt_tick(
                &result,
                self.step_up_read_failures,
                self.step_up_known_deadline,
                OffsetDateTime::now_utc(),
            );
            if let Err(error) = &result {
                warn!(
                    %error,
                    failures = tick.failures(),
                    "Could not read the step-up state"
                );
            }
            self.step_up_read_failures = tick.failures();
            return match tick {
                ExemptTick::Keep { next, .. } => {
                    self.step_up_recheck = Some(Instant::now() + next);
                    false
                }
                ExemptTick::Close { why, .. } => {
                    self.close_for_exemption(&grant, why).await;
                    true
                }
            };
        }
        let Some(pubkeys) = self.step_up_pubkeys.clone() else {
            self.step_up_recheck = None;
            return false;
        };
        let interval = {
            let cfg = self.services.config.lock().await;
            cfg.store.step_up_interval.as_ref().and_then(|s| s.ssh)
        };
        let now = OffsetDateTime::now_utc();
        let username = self
            .user_info
            .as_ref()
            .map_or_else(|| "unknown".to_owned(), |u| u.username.clone());
        let mut window = StepUpWindow::NotApplicable;
        if interval.is_some() {
            // A key login with no matched row cannot show a fresh SSO.
            window = if pubkeys.is_empty() {
                StepUpWindow::Expired
            } else {
                StepUpWindow::Remaining(Duration::MAX)
            };
            for pubkey_id in &pubkeys {
                let last = match bound_step_up_read(
                    &username,
                    STEP_UP_READ_TIMEOUT,
                    get_pubkey_last_sso_at(&self.services.db, *pubkey_id),
                )
                .await
                {
                    Ok(last) => last,
                    Err(error) => {
                        return self.step_up_read_failed(&error, now).await;
                    }
                };
                window = match (window, step_up_window(last, interval, now)) {
                    (StepUpWindow::Expired, _) | (_, StepUpWindow::Expired) => {
                        StepUpWindow::Expired
                    }
                    (StepUpWindow::Remaining(a), StepUpWindow::Remaining(b)) => {
                        StepUpWindow::Remaining(a.min(b))
                    }
                    (_, other) => other,
                };
            }
        }
        self.step_up_read_failures = 0;
        match window {
            StepUpWindow::Expired => {
                self.close_for_step_up("step-up window expired").await;
                true
            }
            StepUpWindow::NotApplicable => {
                // Step-up is currently off: keep looking at the config, since
                // it may be switched on while the connection is open.
                self.step_up_known_deadline = None;
                self.step_up_recheck = Some(Instant::now() + STEP_UP_RECHECK_MAX);
                false
            }
            StepUpWindow::Remaining(left) => {
                self.step_up_known_deadline = time::Duration::try_from(left)
                    .ok()
                    .and_then(|left| now.checked_add(left));
                // Capped so a config change or a fresh SSO is seen promptly.
                self.step_up_recheck =
                    Some(Instant::now() + left.clamp(STEP_UP_RECHECK_MIN, STEP_UP_RECHECK_MAX));
                false
            }
        }
    }

    /// A failed read of a key's `last_sso_at` stamp never extends a
    /// connection: it closes once the last known deadline passes, or after
    /// repeated failures, like the login gate that refuses when it cannot read
    /// the stamp. (A connection admitted through `exempt_users` is decided by
    /// `exempt_tick` instead.)
    async fn step_up_read_failed(&mut self, error: &WarpgateError, now: OffsetDateTime) -> bool {
        self.step_up_read_failures += 1;
        warn!(
            %error,
            failures = self.step_up_read_failures,
            "Could not read the step-up state"
        );
        if read_failure_closes(self.step_up_read_failures, self.step_up_known_deadline, now) {
            self.close_for_step_up("step-up window unverifiable").await;
            return true;
        }
        self.step_up_recheck = Some(Instant::now() + STEP_UP_RECHECK_MAX);
        false
    }

    async fn close_for_exemption(&mut self, grant: &ExemptGrant, why: &str) {
        let reason = "Session ended; reconnect to sign in again";
        info!(
            session = %self.id,
            username = %grant.username,
            key_fingerprint = %grant.fingerprints.join(","),
            target = %grant.target,
            reason = why,
            "Closing the connection admitted through step_up_interval.exempt_users"
        );
        let _ = self.emit_service_message(reason);
        self.disconnect_description = reason.to_owned();
        self.step_up_recheck = None;
        self.step_up_exempt = None;
        self.request_disconnect();
        self.disconnect_server().await;
    }

    async fn close_for_step_up(&mut self, why: &str) {
        let reason = "SSO step-up window expired; reconnect to sign in again";
        info!(
            session = %self.id,
            reason = why,
            "Closing the connection: its key's step-up window has passed"
        );
        let _ = self.emit_service_message(reason);
        self.disconnect_description = reason.to_owned();
        self.step_up_recheck = None;
        self.request_disconnect();
        self.disconnect_server().await;
    }

    async fn get_next_event(&mut self) -> Option<Event> {
        self.intake.next().await
    }

    /// Based on the global params (#1957)
    fn supported_credential_kinds(&self) -> Vec<CredentialKind> {
        let mut kinds = vec![];
        if self.allowed_auth_methods.contains(&MethodKind::Password) {
            kinds.push(CredentialKind::Password);
        }
        if self.allowed_auth_methods.contains(&MethodKind::PublicKey) {
            kinds.push(CredentialKind::PublicKey);
        }
        if self
            .allowed_auth_methods
            .contains(&MethodKind::KeyboardInteractive)
        {
            kinds.push(CredentialKind::Totp);
            kinds.push(CredentialKind::WebUserApproval);
        }
        kinds
    }

    /// `rate_limit_credential_type` is forwarded to `Services::create_auth_state`
    /// so an unknown username is recorded as a failed attempt for IP blocking —
    /// `None` for benign contexts (public-key offers) that must not be counted.
    async fn get_auth_state(
        &mut self,
        username: &str,
        target_name: &str,
        rate_limit_credential_type: Option<&str>,
    ) -> Result<Arc<Mutex<AuthState>>, WarpgateError> {
        // The cached state may only be reused for the same username *and* the
        // same target: its `target_name` scopes web approvals, so switching
        // targets on one connection must not carry over the previous target's
        // approval.
        if let Some((state, cached_target)) = &self.auth_state
            && cached_target == target_name
            && username_eq_ci(&state.lock().await.user_info().username, username)
        {
            return Ok(state.clone());
        }

        let state = self
            .services
            .create_auth_state(
                &self.id,
                username,
                crate::PROTOCOL_NAME,
                target_name,
                &self.supported_credential_kinds(),
                Some(self.remote_address.ip()),
                rate_limit_credential_type,
            )
            .await?;
        self.auth_state = Some((state.clone(), target_name.to_string()));
        self.authenticated_pubkeys.clear();
        Ok(state)
    }

    /// SSH counts only password/OTP guesses toward rate-limiting — public-key
    /// offers legitimately fail as clients try each agent key in turn, so they
    /// aren't counted as brute-force attempts.
    const fn rate_limited_credential_type(credential: &AuthCredential) -> Option<&'static str> {
        match credential {
            AuthCredential::Password(_) => Some("password"),
            AuthCredential::Otp(_) => Some("otp"),
            _ => None,
        }
    }

    async fn record_failed_login_attempt(&mut self, username: &str, credential_type: &str) {
        self.probe = ProbeState::Settled;
        let _ = self
            .services
            .login_protection
            .record_failed_attempt(FailedAttemptInfo {
                username: username.to_string(),
                remote_ip: self.remote_address.ip(),
                protocol: crate::PROTOCOL_NAME,
                credential_type: credential_type.to_string(),
            })
            .await;
    }

    fn note_probe(&mut self, selector: &AuthSelector, method: &'static str) {
        if let AuthSelector::User { username, .. } = selector
            && !matches!(self.probe, ProbeState::Settled)
        {
            self.probe = ProbeState::Probe {
                username: username.clone(),
                method,
            };
        }
    }

    /// At session end, record a failure if session only did
    /// unsuccessful probes
    async fn settle_failed_probe(&mut self) {
        if self.user_info.is_some() {
            return;
        }
        if let ProbeState::Probe { username, method } = &self.probe {
            let (username, method) = (username.clone(), *method);
            self.record_failed_login_attempt(&username, method).await;
        }
    }

    pub fn make_logging_span(&self) -> tracing::Span {
        let client_ip = self.remote_address.ip().to_string();
        if let Some(user_info) = &self.user_info {
            info_span!("SSH", session=%self.id, session_username=%user_info.username, %client_ip)
        } else {
            info_span!("SSH", session=%self.id, %client_ip)
        }
    }

    fn map_channel(&self, ch: ServerChannelId) -> Result<Uuid, WarpgateError> {
        self.channels
            .uuid_for(ch)
            .ok_or(WarpgateError::InconsistentState(
                "Tried to map unknown channel ID".into(),
            ))
    }

    fn map_channel_reverse(&self, ch: &Uuid) -> Result<ServerChannelId> {
        self.channels
            .get(ch)
            .and_then(Channel::server_id)
            .ok_or_else(|| anyhow::anyhow!("Channel not known"))
    }

    /// The client-facing handle and channel id a target-side channel writes
    /// to. `None` once the client session is gone — everything queued for it
    /// is dropped, so callers just skip the write.
    fn client_channel(&self, channel: &Uuid) -> Result<Option<(russh::server::Handle, ChannelId)>> {
        let server_channel_id = self.map_channel_reverse(channel)?;
        Ok(self
            .session_handle
            .clone()
            .map(|handle| (handle, server_channel_id.0)))
    }

    /// Opens a server->client channel in the background and delivers the
    /// resulting channel id back into the event loop as an event. Awaiting
    /// the client's confirmation inline would deadlock: the russh session
    /// loop might itself be blocked on a handler event that this event loop
    /// hasn't gotten to yet (#1459). The registry entry created here is what
    /// holds the channel's target-side events back until the open resolves.
    fn open_server_channel_in_background(
        &mut self,
        id: Uuid,
        open: impl Future<Output = Result<russh::Channel<russh::server::Msg>, russh::Error>>
        + Send
        + 'static,
    ) {
        self.channels.begin_server_open(id);
        let sender = self.event_sender.clone();
        tokio::spawn(async move {
            let result = open.await.map(|channel| ServerChannelId(channel.id()));
            let _ = sender
                .send_once(Event::ServerChannelOpenResult(id, result))
                .await;
        });
    }

    pub fn emit_pty_output(&self, data: &[u8]) -> Result<()> {
        let channels = self
            .channels
            .values()
            .filter(|c| c.has_pty())
            .filter_map(Channel::server_id)
            .collect::<Vec<_>>();
        for channel in channels {
            if let Some(session) = self.session_handle.clone() {
                self.channel_writer.write(session, channel.0, data, None)?;
            }
        }
        Ok(())
    }

    pub fn emit_service_message(&self, msg: &str) -> Result<()> {
        debug!("Service message: {}", msg);

        let _ = self.emit_pty_output(self.service_output.erase_display().as_bytes());
        let output = format!(
            "{} {}\r\n",
            paint_fg(Color::Blue, false, "● Warpgate:"),
            msg.replace('\n', "\r\n")
        );
        self.emit_pty_output(output.as_bytes())
    }

    pub fn emit_pty_error(&self, msg: &str) -> Result<()> {
        if self.service_output.progress_visible() {
            self.service_output.stop_progress();
            let _ = self.emit_pty_output(self.service_output.erase_display().as_bytes());
        }
        let output = format!("{} {msg}\r\n", paint_fg(Color::Red, false, "● Warpgate:"));
        self.emit_pty_output(output.as_bytes())
    }

    async fn fail_on_channel_writer_error(&mut self, error: anyhow::Error) -> Result<()> {
        warn!(?error, "Failed to send SSH channel data");
        self.request_disconnect();
        self.disconnect_server().await;
        Err(error)
    }

    /// Start connecting to the target if we aren't already.
    ///
    /// Timing of this call is important because if the client connection is
    /// an interactive session *in principle* (e.g a normal interactive OpenSSH
    /// session but maybe with some port forwards or agent)
    /// Ideally, it needs to be called by the time we already have the interactive
    /// channel open if we will ever have one to prevent bugs like
    /// https://github.com/warp-tech/warpgate/issues/1286
    /// where a PTY channel is required for the host key prompt, but we've connected
    /// faster than the client could open one.
    pub async fn maybe_connect_remote(&mut self) -> Result<()> {
        // A refused session never reaches the target, whichever caller asks.
        if self.recording_refused {
            return Err(WarpgateError::SessionNotRecorded.into());
        }
        if self.rc_state != RCState::NotInitialized {
            return Ok(());
        }

        let admitted = match std::mem::replace(&mut self.target, TargetSelection::None) {
            TargetSelection::None => {
                anyhow::bail!("Invalid session state (target not set)")
            }
            TargetSelection::Menu => {
                self.target = TargetSelection::Menu;
                return Ok(());
            }
            TargetSelection::NotFound(name) => {
                self.emit_service_message(&format!("Selected target not found: {name}"))?;
                self.disconnect_server().await;
                anyhow::bail!("Target not found: {name}");
            }
            // Claim the attempt: the gate runs off to the side with the
            // authorization, and the selection state is the claim. Resumes in
            // the `Event::AdminApprovalResolved` handler.
            TargetSelection::PendingApproval(authorization) => {
                self.target = TargetSelection::AwaitingApproval;
                self.spawn_admin_approval_gate(authorization);
                return Ok(());
            }
            // Nothing to dial while the gate holds the session.
            TargetSelection::AwaitingApproval => {
                self.target = TargetSelection::AwaitingApproval;
                return Ok(());
            }
            TargetSelection::Found(admitted) => admitted,
            TargetSelection::Connected => {
                self.target = TargetSelection::Connected;
                return Ok(());
            }
        };

        self.connect_remote(admitted).await?;
        self.target = TargetSelection::Connected;
        Ok(())
    }

    /// Wait for approval in a background task, report back via Event::AdminApprovalResolved
    fn spawn_admin_approval_gate(&mut self, authorization: TargetAuthorization<TargetSSHOptions>) {
        let services = self.services.clone();
        let session_id = self.id;
        let remote_ip = self.remote_address.ip();
        let cancel = self.disconnect_token.clone();
        let event_sender = self.event_sender.clone();
        let notify_sender = self.event_sender.clone();
        let auth_state = self.auth_state.as_ref().map(|(state, _)| state.clone());

        tokio::spawn(async move {
            let credentials = match auth_state {
                Some(state) => state.lock().await.remembered_by(),
                None => RememberApprovalBy::Nothing,
            };
            let gate = services.require_admin_approval(
                authorization,
                session_id,
                GatedConnection {
                    remote_ip: Some(remote_ip),
                    credentials,
                },
                || async move {
                    let _ = notify_sender.send_once(Event::AdminApprovalPending).await;
                    Ok::<_, WarpgateError>(())
                },
            );

            let approved = tokio::select! {
                () = cancel.cancelled() => None,
                outcome = gate => outcome.map_or_else(
                    |error| {
                        error!(%error, "Failed to hold the session for administrator approval");
                        None
                    },
                    GateOutcome::approved,
                ),
            };
            let _ = event_sender
                .send_once(Event::AdminApprovalResolved { approved })
                .await;
        });
    }

    /// The dial consumes the capability minted when the target session started.
    async fn connect_remote(&mut self, admitted: AdmittedTarget<TargetSSHOptions>) -> Result<()> {
        let ssh_chain = resolve_approved_ssh_chain(&self.services, admitted).await?;

        let visual_chain = self.make_visual_connection_chain(&ssh_chain[..]).await?;
        self.rc_state = RCState::Connecting;
        self.send_command(RCCommand::Connect(
            ssh_chain.into_iter().map(|x| x.ssh_options).collect(),
        ))
        .map_err(|_| anyhow::anyhow!("cannot send command"))?;
        self.emit_pty_output(b"\r\n")?;
        self.service_output.start_progress(visual_chain).await;
        Ok(())
    }

    async fn make_visual_connection_chain(
        &self,
        ssh_chain: &[ResolvedSshChainHost],
    ) -> Result<Vec<VisualConnectionChainItem>, WarpgateError> {
        let maybe_ext_url =
            construct_external_url(None, &*self.services.config.lock().await, None).await;
        let warpgate_item = match maybe_ext_url {
            Ok(url) => VisualConnectionChainItem::Link {
                text: "Warpgate".into(),
                url: url.to_string(),
            },
            Err(_) => VisualConnectionChainItem::Text("Warpgate".into()),
        };

        let mut display = vec![VisualConnectionChainItem::Text("You".into()), warpgate_item];
        display.extend(
            ssh_chain
                .iter()
                .map(|host| VisualConnectionChainItem::Text(host.name.clone())),
        );

        Ok(display)
    }

    async fn handle_menu_event(&mut self, action: MenuEvent) -> Result<()> {
        match action {
            MenuEvent::Render(data) => {
                self.emit_pty_output(&data)?;
            }
            MenuEvent::Abort => {
                self.emit_service_message("Session closed")?;
                self.request_disconnect();
                self.disconnect_server().await;
            }
            MenuEvent::Selected(target_id) => {
                // The proof stored when the login's auth state was accepted;
                // absent for ticket sessions, which never reach the menu.
                let identity =
                    self.authorized_identity
                        .clone()
                        .ok_or(WarpgateError::InconsistentState(
                            "No authorized identity".into(),
                        ))?;
                // The menu may have been open for a long time: role, approval
                // requirement, connection options or the target's very
                // existence may have changed since, so authorize the current row.
                let config_provider = self.services.config_provider.as_ref();
                let authorization = match config_provider.get_target_by_id(target_id).await? {
                    Some(target) => authorize_for_target(config_provider, &identity, target)
                        .await?
                        .and_then(|a| a.narrow::<TargetSSHOptions>().ok()),
                    None => None,
                };
                let Some(authorization) = authorization else {
                    warn!(
                        "Target {} not authorized for user {}",
                        target_id, identity.username
                    );
                    self.emit_service_message("Access denied")?;
                    self.request_disconnect();
                    self.disconnect_server().await;
                    return Ok(());
                };
                let started = self
                    .server_handle
                    .lock()
                    .await
                    .start_target_session(authorization)
                    .await?;
                match started {
                    TargetSessionStart::Started(admitted) => {
                        self.stamp_approved_target(admitted).await;
                    }
                    TargetSessionStart::NeedsApproval(authorization) => {
                        self.target = TargetSelection::PendingApproval(authorization);
                    }
                }
                // clear screen ; cursor to 1;1
                self.emit_pty_output(b"\x1b[2J\x1b[H")?;
                self.maybe_connect_remote().await?;
            }
        }

        Ok(())
    }

    fn handle_event<'a>(
        &'a mut self,
        event: Event,
    ) -> Pin<Box<dyn Future<Output = Result<(), WarpgateError>> + Send + 'a>> {
        async move {
            match event {
                Event::Client(RCEvent::Done) => Err(WarpgateError::SessionEnd)?,
                Event::ServerHandler(ServerHandlerEvent::Disconnect) => {
                    Err(WarpgateError::SessionEnd)?;
                }
                Event::Client(e) => {
                    let e = if let Some(ch) = e.channel()
                        && let Some(channel) = self.channels.get_mut(&ch)
                    {
                        match channel.try_defer(e) {
                            Ok(()) => {
                                debug!(channel=%ch, "Deferring event until the channel open resolves");
                                return Ok(());
                            }
                            Err(e) => e,
                        }
                    } else {
                        e
                    };
                    debug!(event=?e, "Event");
                    let span = self.make_logging_span();
                    if let Err(err) = self.handle_remote_event(e).instrument(span).await {
                        error!("Client event handler error: {:?}", err);
                        // break;
                    }
                }
                Event::ServerHandler(e) => {
                    // An event for a channel id no registered channel carries can
                    // only refer to a pending server-initiated open: the client
                    // learns of such channels no earlier than from the confirmation
                    // that resolves the open. Without any open in flight an unknown
                    // id is simply bogus and is left to the handler to reject.
                    if let Some(ch) = e.existing_channel()
                        && self.channels.uuid_for(ch).is_none()
                        && self.channels.has_opening()
                    {
                        debug!(channel=%ch.0, event=?e, "Deferring event until the channel open resolves");
                        self.deferred_server_events.push(e);
                        return Ok(());
                    }
                    let span = self.make_logging_span();
                    if let Err(err) = self.handle_server_handler_event(e).instrument(span).await {
                        error!("Server event handler error: {:?}", err);
                        // break;
                    }
                }
                Event::Command(command) => {
                    debug!(?command, "Session control");
                    if let Err(err) = self.handle_session_control(command).await {
                        error!("Command handler error: {:?}", err);
                        // break;
                    }
                }
                Event::ServiceOutput(data) => {
                    if let Some(frame) = self.service_output.take_frame(&data) {
                        let _ = self.emit_pty_output(&frame);
                    }
                }
                Event::Menu(action) => {
                    if let Err(err) = self.handle_menu_event(action).await {
                        error!(?err, "Menu loop action handler error");
                    }
                }
                Event::AdminApprovalPending => {
                    self.emit_service_message(
                        "Waiting for an administrator to approve this session...",
                    )?;
                }
                Event::AdminApprovalResolved { approved } => {
                    if !matches!(self.target, TargetSelection::AwaitingApproval) {
                        // The user has aborted the wait by now
                        return Ok(());
                    }
                    self.target = TargetSelection::None;
                    let Some(approved) = approved else {
                        self.emit_service_message("Session was not approved by an administrator")?;
                        self.request_disconnect();
                        self.disconnect_server().await;
                        return Ok(());
                    };
                    let admitted = self
                        .server_handle
                        .lock()
                        .await
                        .register_approved_target_session(approved)
                        .await?;

                    self.stamp_approved_target(admitted).await;
                    self.maybe_connect_remote().await?;
                }
                Event::ServerChannelOpenResult(id, result) => {
                    match result {
                        Ok(server_channel_id) => {
                            if self.channels.assign_server_id(id, server_channel_id) {
                                self.confirm_channel_open(id).await?;
                            } else {
                                debug!(channel=%id, "Open resolved for an already-closed channel");
                                self.replay_deferred_server_events().await?;
                            }
                        }
                        Err(error) => {
                            warn!(channel=%id, ?error, "Failed to open a channel to the client");
                            // Tear the entry down now — its deferred events die
                            // with the open they were waiting on, and the
                            // target's eventual Close reply must find no
                            // Opening entry to be deferred onto.
                            self.channels.close(id);
                            let _ =
                                self.send_command(RCCommand::Channel(id, ChannelOperation::Close));
                            self.replay_deferred_server_events().await?;
                        }
                    }
                }
                Event::MenuRedraw(_, _) | Event::ConsoleInput(_) => (),
            }
            Ok(())
        }
        .boxed()
    }

    async fn stamp_approved_target(&mut self, admitted: AdmittedTarget<TargetSSHOptions>) {
        self.target_session_id = Some(admitted.id());
        self.recording_owner = RecordingOwner {
            user: admitted.user_info().username.clone(),
            target: admitted.target().name.clone(),
            ..ssh_recording_owner()
        };
        self.target_env = admitted.options().env.clone();
        self.target = TargetSelection::Found(admitted);
        self.start_pending_recordings().await;
    }

    /// Confirm `channel` as open and re-dispatch everything held back while its
    /// open was in flight. Events whose channel is still opening are deferred
    /// again by [`Self::handle_event`], so overlapping opens replay safely.
    async fn confirm_channel_open(&mut self, channel: Uuid) -> Result<(), WarpgateError> {
        for event in self.channels.confirm(channel).unwrap_or_default() {
            self.handle_event(Event::Client(event)).await?;
        }
        self.replay_deferred_server_events().await
    }

    async fn replay_deferred_server_events(&mut self) -> Result<(), WarpgateError> {
        for event in std::mem::take(&mut self.deferred_server_events) {
            self.handle_event(Event::ServerHandler(event)).await?;
        }
        Ok(())
    }

    async fn start_target_selection_menu(&self, channel_id: Uuid) -> Result<()> {
        let menu_event_subscription = self
            .hub
            .subscribe(|e| matches!(e, Event::MenuRedraw(_, _) | Event::ConsoleInput(_)))
            .await;

        let username = self
            .user_info
            .as_ref()
            .map(|u| u.username.as_str())
            .ok_or(WarpgateError::InconsistentState("No username".into()))?;

        let ssh_targets = {
            self.services
                .config_provider
                .list_targets()
                .await?
                .into_iter()
                .filter_map(|target| match target.options.clone() {
                    TargetOptions::Ssh(options) => Some((target, options)),
                    _ => None,
                })
                .collect::<Vec<_>>()
        };

        let mut authorized_targets = Vec::new();

        for (target, mut ssh_options) in ssh_targets {
            let is_authorized = self
                .services
                .config_provider
                .authorize_target(username, &target.name)
                .await?;

            if is_authorized {
                if ssh_options.username.is_empty() {
                    ssh_options.username = username.to_string();
                }
                authorized_targets.push((target, ssh_options));
            }
        }

        authorized_targets.sort_by(|(left, _), (right, _)| left.name.cmp(&right.name));

        let (terminal_width, terminal_height) = self
            .channels
            .get(&channel_id)
            .and_then(|c| c.pty_size.as_ref())
            .map_or((220, 24), PtyRequest::screen_size);

        spawn_target_menu_loop(
            self.id,
            username.to_string(),
            authorized_targets,
            menu_event_subscription,
            self.event_sender.clone(),
            terminal_width,
            terminal_height,
        )?;
        Ok(())
    }

    async fn maybe_start_target_selection_menu(&self, channel_id: Uuid) -> Result<()> {
        if matches!(self.target, TargetSelection::Menu)
            && self.channels.get(&channel_id).is_some_and(Channel::has_pty)
        {
            self.start_target_selection_menu(channel_id).await?;
        }

        Ok(())
    }

    async fn handle_server_handler_event(&mut self, event: ServerHandlerEvent) -> Result<()> {
        match event {
            ServerHandlerEvent::Authenticated(handle) => {
                self.session_handle = Some(handle.0);
            }

            ServerHandlerEvent::ChannelOpenSession(server_channel_id, reply) => {
                info!(channel=%server_channel_id.0, "Opening session channel");
                self._channel_open(
                    server_channel_id,
                    ChannelOperation::OpenShell,
                    None,
                    reply.0,
                )
                .await?;
            }

            ServerHandlerEvent::SubsystemRequest(server_channel_id, name, reply) => {
                return match self
                    ._channel_subsystem_request(server_channel_id, name)
                    .await
                {
                    Ok(()) => {
                        let _ = reply.send(true);
                        Ok(())
                    }
                    Err(SshClientError::Russh(russh::Error::ChannelOpenFailure(_))) => {
                        let _ = reply.send(false);
                        Ok(())
                    }
                    Err(x) => Err(x.into()),
                };
            }

            ServerHandlerEvent::PtyRequest(server_channel_id, request, reply) => {
                let channel_id = self.map_channel(server_channel_id)?;
                let Some(channel_state) = self.channels.get_mut(&channel_id) else {
                    return Err(WarpgateError::InconsistentState(
                        "PTY requested for a channel that was never opened".into(),
                    )
                    .into());
                };
                channel_state.pty_size = Some(request.clone());
                if channel_state.audit.on_resize(&request).await.is_break() {
                    self.close_on_recording_failure().await;
                    return Ok(());
                }

                self.send_command_and_wait(RCCommand::Channel(
                    channel_id,
                    ChannelOperation::RequestPty(request),
                ))
                .await?;
                let handle = self
                    .session_handle
                    .clone()
                    .context("Invalid session state")?;
                let _ = self
                    .channel_writer
                    .channel_success(handle, server_channel_id.0);
                // Waiting for the target above pumps the event loop, so the
                // channel may have been closed in the meantime — hence the
                // re-lookup instead of holding the entry across the await.
                if let Some(channel_state) = self.channels.get_mut(&channel_id) {
                    channel_state.mark_pty();
                }
                let _ = reply.send(());
            }

            ServerHandlerEvent::ShellRequest(server_channel_id, reply) => {
                let channel_id = self.map_channel(server_channel_id)?;
                // The recording starts before anything reaches the target, so a
                // refused session is never dialled and never gets the shell.
                if self
                    .start_terminal_recording(
                        channel_id,
                        shell_recording_metadata(server_channel_id),
                    )
                    .await
                    .is_break()
                {
                    let _ = reply.send(false);
                    return Ok(());
                }
                self.end_request_wait(channel_id);
                self.maybe_connect_remote().await?;
                self.maybe_start_target_selection_menu(channel_id).await?;

                self.inject_own_env(channel_id);

                let _ = self.send_command(RCCommand::Channel(
                    channel_id,
                    ChannelOperation::RequestShell,
                ));

                self.maybe_start_command_detector(channel_id);

                info!(%channel_id, "Opening shell");

                let handle = self
                    .session_handle
                    .clone()
                    .context("Invalid session state")?;
                let _ = self
                    .channel_writer
                    .channel_success(handle, server_channel_id.0);

                let _ = reply.send(true);
            }

            ServerHandlerEvent::AuthPublicKey(username, key, reply) => {
                let _ = reply.send(self._auth_publickey(username, key).await);
            }

            ServerHandlerEvent::AuthPublicKeyOffer(username, key, reply) => {
                let _ = reply.send(self._auth_publickey_offer(username, key).await);
            }

            ServerHandlerEvent::AuthPassword(username, password, reply) => {
                let _ = reply.send(self._auth_password(username, password).await);
            }

            ServerHandlerEvent::AuthKeyboardInteractive(username, responses, reply) => {
                let _ = reply.send(self._auth_keyboard_interactive(username, responses).await?);
            }

            ServerHandlerEvent::Data(channel, data, reply) => {
                self._data(channel, data).await?;
                let _ = reply.send(());
            }

            ServerHandlerEvent::ExtendedData(channel, data, code, reply) => {
                self._extended_data(channel, code, data)?;
                let _ = reply.send(());
            }

            ServerHandlerEvent::ChannelClose(channel, reply) => {
                self._channel_close(channel).await?;
                let _ = reply.send(());
            }

            ServerHandlerEvent::ChannelStalled(channel, reply) => {
                self._channel_stalled(channel);
                let _ = reply.send(());
            }

            ServerHandlerEvent::ChannelEof(channel, reply) => {
                self._channel_eof(channel)?;
                let _ = reply.send(());
            }

            ServerHandlerEvent::WindowChangeRequest(channel, request, reply) => {
                self._window_change_request(channel, request).await?;
                let _ = reply.send(());
            }

            ServerHandlerEvent::Signal(channel, signal, reply) => {
                self._channel_signal(channel, signal).await?;
                let _ = reply.send(());
            }

            ServerHandlerEvent::ExecRequest(channel, data, reply) => {
                let accepted = self._channel_exec_request(channel, data).await?;
                let _ = reply.send(accepted);
            }

            ServerHandlerEvent::ChannelOpenDirectTcpIp(channel, params, reply) => {
                self._channel_open_direct_tcpip(channel, params, reply.0)
                    .await?;
            }

            ServerHandlerEvent::ChannelOpenDirectStreamlocal(channel, path, reply) => {
                self._channel_open_direct_streamlocal(channel, path, reply.0)
                    .await?;
            }

            ServerHandlerEvent::EnvRequest(channel, name, value, reply) => {
                self._channel_env_request(channel, name, value).await?;
                let _ = reply.send(());
            }

            ServerHandlerEvent::X11Request(channel, request, reply) => {
                self._channel_x11_request(channel, request).await?;
                let _ = reply.send(());
            }

            ServerHandlerEvent::TcpIpForward(address, port, reply) => {
                self._tcpip_forward(address, port).await?;
                let _ = reply.send(true);
            }

            ServerHandlerEvent::CancelTcpIpForward(address, port, reply) => {
                self._cancel_tcpip_forward(address, port).await?;
                let _ = reply.send(true);
            }

            ServerHandlerEvent::StreamlocalForward(socket_path, reply) => {
                self._streamlocal_forward(socket_path).await?;
                let _ = reply.send(true);
            }

            ServerHandlerEvent::CancelStreamlocalForward(socket_path, reply) => {
                self._cancel_streamlocal_forward(socket_path).await?;
                let _ = reply.send(true);
            }

            ServerHandlerEvent::AgentForward(channel, reply) => {
                self._agent_forward(channel).await?;
                let _ = reply.send(true);
            }

            ServerHandlerEvent::Disconnect => (),
        }

        Ok(())
    }

    pub async fn handle_session_control(&mut self, command: SessionHandleCommand) -> Result<()> {
        match command {
            SessionHandleCommand::Close => {
                let _ = self.emit_service_message("Session closed by admin");
                info!("Session closed by admin");
                self.request_disconnect();
                self.disconnect_server().await;
            }
        }
        Ok(())
    }

    pub async fn handle_remote_event(&mut self, event: RCEvent) -> Result<()> {
        match event {
            RCEvent::HopConnected => {
                self.service_output.notify_hop_connected().await;
            }
            RCEvent::State(state) => {
                self.rc_state = state;
                match &self.rc_state {
                    RCState::Connected => {
                        let msg = self
                            .service_output
                            .render_final_success_static_frame()
                            .await;
                        let _ = self.emit_pty_output(msg.as_bytes());
                    }
                    RCState::Disconnected => {
                        self.service_output.stop_progress();
                        self.disconnect_server().await;
                    }
                    _ => {}
                }
            }
            RCEvent::ConnectionError(error) => {
                self.service_output.stop_progress();

                match error {
                    ConnectionError::HostKeyMismatch {
                        received_key_type,
                        received_key_base64,
                        known_key_type,
                        known_key_base64,
                    } => {
                        let _ = self.emit_pty_error("Host key doesn't match the stored one.");
                        let msg = format!(
                            concat!("Stored key   ({}): {}\n", "Received key ({}): {}",),
                            known_key_type,
                            known_key_base64,
                            received_key_type,
                            received_key_base64
                        );
                        self.emit_service_message(&msg)?;
                        self.emit_service_message(
                            "If you know that the key is correct (e.g. it has been changed),",
                        )?;
                        self.emit_service_message(
                            "you can remove the old key in the Warpgate management UI and try again",
                        )?;
                    }
                    ConnectionError::Authentication => {
                        let _ = self.emit_pty_error(
                            "SSH target rejected Warpgate's authentication request",
                        );
                    }
                    error => {
                        let _ = self.emit_pty_error(&format!(
                            "Target connection failed: {}",
                            error.user_facing_reason()
                        ));
                    }
                }
            }
            RCEvent::Error(e) => {
                self.service_output.stop_progress();
                let _ = self.emit_pty_error(&format!("Error: {}", e.user_facing_reason()));
                self.disconnect_server().await;
            }
            RCEvent::Output(channel, data) => {
                let mut recording_failed = false;
                if let Some(channel_state) = self.channels.get_mut(&channel) {
                    recording_failed = channel_state.audit.on_output(&data).await.is_break();

                    if let Some(recorder) = channel_state.traffic_recorder.as_mut()
                        && let Err(error) = recorder.write_rx(&data).await
                    {
                        recording_failed |= recorder.write_failed(&format_args!("{error:#}"));
                        channel_state.traffic_recorder = None;
                    }
                }
                // Closed before the unrecorded output reaches the client.
                if recording_failed {
                    self.close_on_recording_failure().await;
                    return Ok(());
                }

                let slot = self.intake.take_slot();
                if let Some((handle, id)) = self.client_channel(&channel)?
                    && let Err(error) = self.channel_writer.write(handle, id, data, slot)
                {
                    return self.fail_on_channel_writer_error(error).await;
                }
            }
            RCEvent::Opened(channel) => {
                // From here the target is expected to take the channel's
                // input, so the stall clock may start.
                if let Some(server_id) = self.channels.get(&channel).and_then(Channel::server_id) {
                    self.channel_inputs.live(u32::from(server_id.0));
                }
            }
            RCEvent::Success(channel) => {
                if let Some((handle, id)) = self.client_channel(&channel)? {
                    self.channel_writer.channel_success(handle, id)?;
                }
            }
            RCEvent::ChannelFailure(channel) => {
                if let Some((handle, id)) = self.client_channel(&channel)? {
                    self.channel_writer.channel_failure(handle, id)?;
                }
            }
            RCEvent::Close(channel) => {
                match self.client_channel(&channel) {
                    Ok(Some((handle, id))) => self.channel_writer.close(handle, id)?,
                    Ok(None) => {}
                    Err(error) => {
                        // Not necessarily a bug: this is reached from both
                        // sides, so the client half may have closed first.
                        debug!(%channel, ?error, "Target closed a channel already gone from the registry");
                    }
                }
                // The registry entry is the only record of the client-side
                // channel number. If the client half has already gone (its own
                // close removed it, and removed its input state with it), no
                // input can still be waiting, so there is nothing to signal
                // and nothing to leave behind.
                if let Some(server_id) = self.channels.get(&channel).and_then(Channel::server_id) {
                    self.channel_inputs.target_closed(u32::from(server_id.0));
                }
                self.channels.close(channel);
            }
            RCEvent::Eof(channel) => {
                if let Some((handle, id)) = self.client_channel(&channel)? {
                    self.channel_writer.eof(handle, id)?;
                }
            }
            RCEvent::ExitStatus(channel, code) => {
                if let Some((handle, id)) = self.client_channel(&channel)? {
                    self.channel_writer.exit_status(handle, id, code)?;
                }
            }
            RCEvent::ExitSignal {
                channel,
                signal_name,
                core_dumped,
                error_message,
                lang_tag,
            } => {
                if let Some((handle, id)) = self.client_channel(&channel)? {
                    self.channel_writer.exit_signal(
                        handle,
                        id,
                        signal_name,
                        core_dumped,
                        error_message,
                        lang_tag,
                    )?;
                }
            }
            RCEvent::ExtendedData { channel, data, ext } => {
                if let Some(channel_state) = self.channels.get_mut(&channel)
                    && channel_state.audit.on_error_output(&data).await.is_break()
                {
                    self.close_on_recording_failure().await;
                    return Ok(());
                }
                let slot = self.intake.take_slot();
                if let Some((handle, id)) = self.client_channel(&channel)?
                    && let Err(error) = self
                        .channel_writer
                        .write_extended(handle, id, ext, data, slot)
                {
                    return self.fail_on_channel_writer_error(error).await;
                }
            }
            RCEvent::Done | RCEvent::HostKeyReceived(..) => {}
            RCEvent::HostKeyUnknown(key, _, _, reply) => {
                self.handle_unknown_host_key(key, reply).await?;
            }
            RCEvent::ForwardedTcpIp(id, params) => {
                // The recorder exists before the channel is opened to the
                // client, so a refused session never carries the forward.
                let key = TrafficRecorderKey::Tcp(
                    params.originator_address.clone(),
                    params.originator_port,
                );
                let metadata = SshRecordingMetadata::ForwardedTcpIp {
                    host: params.originator_address.clone(),
                    port: params.originator_port as u16,
                };
                if self
                    .prepare_traffic_recorder(&key, metadata)
                    .await
                    .is_break()
                {
                    return Ok(());
                }
                #[allow(clippy::unwrap_used)]
                let connection_params = TrafficConnectionParams::Tcp {
                    dst_addr: Ipv4Addr::from_str("2.2.2.2").unwrap(),
                    dst_port: params.connected_port as u16,
                    src_addr: Ipv4Addr::from_str("1.1.1.1").unwrap(),
                    src_port: params.originator_port as u16,
                };
                let ControlFlow::Continue(recorder) = self
                    .connect_traffic_recorder(&key, connection_params)
                    .await
                else {
                    return Ok(());
                };
                if let Some(session) = self.session_handle.clone() {
                    let open_params = params.clone();
                    self.open_server_channel_in_background(id, async move {
                        session
                            .channel_open_forwarded_tcpip(
                                open_params.connected_address,
                                open_params.connected_port,
                                open_params.originator_address,
                                open_params.originator_port,
                            )
                            .await
                    });
                    self.attach_traffic_recorder(id, recorder);
                }
            }
            RCEvent::ForwardedStreamlocal(id, params) => {
                let key = TrafficRecorderKey::Socket(params.socket_path.clone());
                let metadata = SshRecordingMetadata::ForwardedSocket {
                    path: params.socket_path.clone(),
                };
                if self
                    .prepare_traffic_recorder(&key, metadata)
                    .await
                    .is_break()
                {
                    return Ok(());
                }
                let connection_params = TrafficConnectionParams::Socket {
                    socket_path: params.socket_path.clone(),
                };
                let ControlFlow::Continue(recorder) = self
                    .connect_traffic_recorder(&key, connection_params)
                    .await
                else {
                    return Ok(());
                };
                if let Some(session) = self.session_handle.clone() {
                    let socket_path = params.socket_path;
                    self.open_server_channel_in_background(id, async move {
                        session
                            .channel_open_forwarded_streamlocal(socket_path)
                            .await
                    });
                    self.attach_traffic_recorder(id, recorder);
                }
            }
            RCEvent::ForwardedAgent(id) => {
                if let Some(session) = self.session_handle.clone() {
                    self.open_server_channel_in_background(id, async move {
                        session.channel_open_agent().await
                    });
                }
            }
            RCEvent::X11(id, originator_address, originator_port) => {
                if let Some(session) = self.session_handle.clone() {
                    self.open_server_channel_in_background(id, async move {
                        session
                            .channel_open_x11(originator_address, originator_port)
                            .await
                    });
                }
            }
        }
        Ok(())
    }

    async fn handle_unknown_host_key(
        &self,
        key: PublicKey,
        reply: oneshot::Sender<bool>,
    ) -> Result<()> {
        let mode = Parameters::Entity::get(&self.services.db)
            .await?
            .ssh_host_key_verification;

        // `Ignore` never gets here - the key is accepted without a lookup.
        if mode == SshHostKeyVerificationMode::AutoAccept {
            let _ = reply.send(true);
            info!("Accepted untrusted host key (auto-accept is enabled)");
            return Ok(());
        }

        if mode == SshHostKeyVerificationMode::AutoReject {
            let _ = reply.send(false);
            info!("Rejected untrusted host key (auto-reject is enabled)");
            return Ok(());
        }

        self.service_output.stop_progress();

        if !self.channels.values().any(Channel::has_pty) {
            warn!(
                "Target host key is not trusted, but there is no active PTY channel to show the trust prompt on."
            );
            warn!(
                "Connect to this target with an interactive session once to accept the host key."
            );
            self.request_disconnect();
            anyhow::bail!("No PTY channel to show an interactive prompt on")
        }

        self.emit_service_message(&format!(
            "Host key ({}): {}",
            key.algorithm(),
            key.public_key_base64()
        ))?;
        self.emit_service_message(&format!(
            "There is no trusted {} key for this host.",
            key.algorithm()
        ))?;
        self.emit_service_message("Trust this key? (y/n)")?;

        let mut sub = self
            .hub
            .subscribe(|e| matches!(e, Event::ConsoleInput(_)))
            .await;

        self.host_key_trust_prompt_active
            .store(true, Ordering::SeqCst);

        let service_output = self.service_output.clone();
        let prompt_active = self.host_key_trust_prompt_active.clone();
        tokio::spawn(async move {
            loop {
                match sub.recv().await {
                    Some(Event::ConsoleInput(data)) => {
                        if &data[..] == b"y" {
                            let _ = reply.send(true);
                            break;
                        } else if &data[..] == b"n" {
                            let _ = reply.send(false);
                            break;
                        }
                    }
                    None => break,
                    _ => (),
                }
            }
            prompt_active.store(false, Ordering::SeqCst);
            service_output.show_progress();
        });

        Ok(())
    }

    async fn _channel_open_direct_tcpip(
        &mut self,
        channel: ServerChannelId,
        params: DirectTCPIPParams,
        open_handle: impl OpenReply,
    ) -> Result<()> {
        info!(%channel, "Opening direct TCP/IP channel from {}:{} to {}:{}", params.originator_address, params.originator_port, params.host_to_connect, params.port_to_connect);
        let key = TrafficRecorderKey::Tcp(params.host_to_connect.clone(), params.port_to_connect);
        let metadata = SshRecordingMetadata::DirectTcpIp {
            host: params.host_to_connect.clone(),
            port: params.port_to_connect as u16,
        };
        #[allow(clippy::unwrap_used)]
        let connection_params = TrafficConnectionParams::Tcp {
            dst_addr: Ipv4Addr::from_str("2.2.2.2").unwrap(),
            dst_port: params.port_to_connect as u16,
            src_addr: Ipv4Addr::from_str("1.1.1.1").unwrap(),
            src_port: params.originator_port as u16,
        };
        self._channel_open_forward(
            channel,
            ChannelOperation::OpenDirectTCPIP(params),
            (key, metadata, connection_params),
            open_handle,
        )
        .await
    }

    async fn _channel_open_direct_streamlocal(
        &mut self,
        channel: ServerChannelId,
        path: String,
        open_handle: impl OpenReply,
    ) -> Result<()> {
        info!(%channel, "Opening direct streamlocal channel to {}", path);
        let key = TrafficRecorderKey::Socket(path.clone());
        let metadata = SshRecordingMetadata::DirectSocket { path: path.clone() };
        let connection_params = TrafficConnectionParams::Socket {
            socket_path: path.clone(),
        };
        self._channel_open_forward(
            channel,
            ChannelOperation::OpenDirectStreamlocal(path),
            (key, metadata, connection_params),
            open_handle,
        )
        .await
    }

    /// A direct forward: its recorder is made before anything reaches the
    /// target, and a refusal rejects the open.
    async fn _channel_open_forward(
        &mut self,
        channel: ServerChannelId,
        operation: ChannelOperation,
        (key, metadata, connection_params): (
            TrafficRecorderKey,
            SshRecordingMetadata,
            TrafficConnectionParams,
        ),
        open_handle: impl OpenReply,
    ) -> Result<()> {
        if self
            .prepare_traffic_recorder(&key, metadata)
            .await
            .is_break()
        {
            open_handle
                .reject(ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        }
        // The connection's first record is written before the open goes out, so
        // a recorder for this key that has died since it was made is seen here.
        let ControlFlow::Continue(recorder) = self
            .connect_traffic_recorder(&key, connection_params)
            .await
        else {
            open_handle
                .reject(ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        };
        // Unlike a session channel — whose later shell/exec/subsystem request
        // dials the target — a direct channel is the whole interaction, so the
        // connection must be initiated here.
        let _ = self.maybe_connect_remote().await;
        self._channel_open(channel, operation, recorder, open_handle)
            .await
    }

    /// Open a client-initiated channel towards the target and send the client
    /// its open confirmation from here, the session task. The
    /// [`ChannelState::Opening`] entry holds the target's output back until
    /// `accept()` has queued the confirmation, so server-speaks-first bytes
    /// never precede `CHANNEL_OPEN_CONFIRMATION` (#2328).
    async fn _channel_open(
        &mut self,
        channel: ServerChannelId,
        operation: ChannelOperation,
        recorder: Option<ConnectionRecorder>,
        open_handle: impl OpenReply,
    ) -> Result<()> {
        let session = matches!(operation, ChannelOperation::OpenShell);
        let uuid = self.channels.begin_client_open(channel);
        if let Some(channel_state) = self.channels.get_mut(&uuid) {
            channel_state.awaits_request = session;
        }

        match self
            .send_command_and_wait(RCCommand::Channel(uuid, operation))
            .await
        {
            Ok(()) => {
                open_handle.accept().await;

                // The recorder is attached before the deferred output is
                // replayed, so the target's first bytes are recorded too.
                self.attach_traffic_recorder(uuid, recorder);

                self.confirm_channel_open(uuid).await?;
                Ok(())
            }
            // No reply from a stuck target connection: already logged by
            // `send_command_and_wait`; the client gets a failed open.
            Err(
                SshClientError::Russh(russh::Error::ChannelOpenFailure(_))
                | SshClientError::NoReply(_),
            ) => {
                open_handle.reject(ChannelOpenFailure::ConnectFailed).await;
                self.channels.close(uuid);
                Ok(())
            }
            // Dropping `open_handle` auto-rejects the open, so the client always
            // gets a reply even on unexpected errors.
            Err(x) => {
                self.channels.close(uuid);
                Err(x.into())
            }
        }
    }

    async fn _window_change_request(
        &mut self,
        server_channel_id: ServerChannelId,
        request: PtyRequest,
    ) -> Result<()> {
        let channel_id = self.map_channel(server_channel_id)?;
        let Some(channel_state) = self.channels.get_mut(&channel_id) else {
            return Err(WarpgateError::InconsistentState(
                "Window change for a channel that was never opened".into(),
            )
            .into());
        };
        channel_state.pty_size = Some(request.clone());
        if channel_state.audit.on_resize(&request).await.is_break() {
            self.close_on_recording_failure().await;
            return Ok(());
        }

        if matches!(self.target, TargetSelection::Menu) {
            let (cols, rows) = request.screen_size();
            let _ = self
                .event_sender
                .try_send_once(Event::MenuRedraw(cols, rows))
                .await;
        }

        if self.rc_state != RCState::Connected {
            return Ok(());
        }

        self.send_command_and_wait(RCCommand::Channel(
            channel_id,
            ChannelOperation::ResizePty(request),
        ))
        .await?;
        Ok(())
    }

    /// `false` when the exec was refused because its recording could not start.
    async fn _channel_exec_request(
        &mut self,
        server_channel_id: ServerChannelId,
        data: Bytes,
    ) -> Result<bool> {
        let channel_id = self.map_channel(server_channel_id)?;
        let command = std::str::from_utf8(&data).inspect_err(|_| {
            error!(channel=%channel_id, ?data, "Requested exec - invalid UTF-8");
        })?;
        info!(channel=%channel_id, command=%command, "Exec command");

        let is_scp = command == "scp" || command.starts_with("scp ");
        let should_record = if is_scp {
            let db = &self.services.db;
            let should_record = Parameters::Entity::get(db)
                .await
                .map_or(true, |p| p.record_scp);

            if !should_record {
                info!(channel=%channel_id, "Not recording SCP exec session, command was '{command}'");
            }

            should_record
        } else {
            true
        };

        // The recording starts before anything reaches the target, so a
        // refused session is never dialled and never runs the command.
        if should_record
            && self
                .start_terminal_recording(
                    channel_id,
                    SshRecordingMetadata::Exec {
                        // HACK russh ChannelId is opaque except via Display
                        channel: server_channel_id.0.to_string().parse().unwrap_or_default(),
                    },
                )
                .await
                .is_break()
        {
            return Ok(false);
        }
        self.end_request_wait(channel_id);

        let _ = self.maybe_connect_remote().await;
        self.maybe_start_target_selection_menu(channel_id).await?;
        self.inject_own_env(channel_id);
        let _ = self.send_command(RCCommand::Channel(
            channel_id,
            ChannelOperation::RequestExec(command.to_string()),
        ));
        if should_record {
            self.maybe_start_command_detector(channel_id);
        }
        Ok(true)
    }

    /// Starts the terminal recording for `channel_id`. `Break` when it failed
    /// and the session was refused (see [`Self::refuse_unrecorded_session`]):
    /// the caller must then send nothing to the target.
    async fn start_terminal_recording(
        &mut self,
        channel_id: Uuid,
        metadata: SshRecordingMetadata,
    ) -> ControlFlow<()> {
        // A recording row must reference a target session. Before one exists —
        // the target-selection menu is open, or an approval gate is holding the
        // session — the request is parked and replayed on stamp, so a command
        // run through an approved gate is recorded like any other.
        let Some(target_session_id) = self.target_session_id else {
            self.pending_recordings.push((channel_id, metadata));
            return ControlFlow::Continue(());
        };
        let started = self
            .services
            .recordings
            .start_for::<TerminalRecorder, _>(
                &self.recording_owner,
                &target_session_id,
                None,
                metadata,
            )
            .await;
        self.attach_terminal_recording(channel_id, started).await
    }

    /// [`Self::start_terminal_recording`] once the recording has started (or
    /// failed to): seeds it with the channel's terminal size and, when unrecorded
    /// sessions are refused, waits for its first writes to reach the files, so a
    /// recording that cannot be written closes the session before anything of
    /// the channel reaches the target.
    async fn attach_terminal_recording(
        &mut self,
        channel_id: Uuid,
        started: warpgate_core::recordings::Result<Option<TerminalRecorder>>,
    ) -> ControlFlow<()> {
        let required = self.services.recordings.refuses_unrecorded_sessions();
        let recorder = match started {
            Ok(Some(recorder)) => {
                let seeded = match self
                    .channels
                    .get(&channel_id)
                    .and_then(|c| c.pty_size.as_ref())
                {
                    Some(request) => {
                        recorder
                            .write_pty_resize(request.col_width, request.row_height)
                            .await
                    }
                    None => Ok(()),
                };
                let seeded = match seeded {
                    Ok(()) if required => recorder.write_header().await,
                    seeded => seeded,
                };
                match seeded {
                    Ok(()) => Ok(Some(recorder)),
                    // Started, then failed: reported once by the recorder.
                    Err(error) => {
                        if recorder.write_failed(&error) {
                            self.close_on_recording_failure().await;
                            return ControlFlow::Break(());
                        }
                        Ok(None)
                    }
                }
            }
            other => other,
        };
        match recorder {
            Ok(Some(recorder)) => {
                // Starting the recording awaits, so the channel can be gone by
                // now — e.g. target selection failed and tore the session down.
                if let Some(channel_state) = self.channels.get_mut(&channel_id) {
                    channel_state.audit.set_recorder(recorder);
                } else {
                    debug!(channel=%channel_id, "Recording started for a channel that is already gone");
                }
            }
            Ok(None) => (),
            // Logged by `start_for`.
            Err(_) => return self.refuse_unrecorded_session().await,
        }
        ControlFlow::Continue(())
    }

    /// A recording failed to start (already logged). With unrecorded sessions
    /// refused, tell the client, close the connection and return `Break`;
    /// otherwise (the default) the session continues unrecorded.
    async fn refuse_unrecorded_session(&mut self) -> ControlFlow<()> {
        if !self.services.recordings.refuses_unrecorded_sessions() {
            return ControlFlow::Continue(());
        }
        self.recording_refused = true;
        let reason = WarpgateError::SessionNotRecorded.to_string();
        warn!(session = %self.id, "Closing the connection: its recording could not be started");
        let _ = self.emit_pty_error(&reason);
        self.disconnect_description = reason;
        self.request_disconnect();
        self.disconnect_server().await;
        ControlFlow::Break(())
    }

    /// A recording failed mid-session (already logged by its recorder) and
    /// unrecorded sessions are refused: tell the client and close the connection.
    /// The caller returns without forwarding the data it could not record.
    async fn close_on_recording_failure(&mut self) {
        self.recording_refused = true;
        let reason = WarpgateError::SessionRecordingFailed.to_string();
        warn!(session = %self.id, "Closing the connection: its recording failed");
        let _ = self.emit_pty_error(&reason);
        self.disconnect_description = reason;
        self.request_disconnect();
        self.disconnect_server().await;
    }

    /// Starts the recordings parked while no target session existed yet — the
    /// selection menu's shell, and any exec/subsystem dispatched through an
    /// approval gate before it resolved. Called when the target session is
    /// stamped; channels opening later record against the now-present session.
    async fn start_pending_recordings(&mut self) {
        for (channel_id, metadata) in std::mem::take(&mut self.pending_recordings) {
            // A refusal sets `recording_refused`, so the callers' connect that
            // follows the stamp does not dial the target.
            if self
                .start_terminal_recording(channel_id, metadata)
                .await
                .is_break()
            {
                return;
            }
        }
    }

    fn maybe_start_command_detector(&mut self, channel_id: Uuid) {
        let Some(channel_state) = self.channels.get_mut(&channel_id) else {
            return;
        };
        if !channel_state.has_pty() {
            return;
        }
        let (cols, rows) = channel_state
            .pty_size
            .as_ref()
            .map_or((80, 24), PtyRequest::screen_size);
        channel_state.audit.start_command_detection(cols, rows);
    }

    async fn _channel_x11_request(
        &mut self,
        server_channel_id: ServerChannelId,
        request: X11Request,
    ) -> Result<()> {
        let channel_id = self.map_channel(server_channel_id)?;
        debug!(channel=%channel_id, "Requested X11");
        let _ = self.maybe_connect_remote().await;
        self.send_command_and_wait(RCCommand::Channel(
            channel_id,
            ChannelOperation::RequestX11(request),
        ))
        .await?;
        Ok(())
    }

    async fn _channel_env_request(
        &mut self,
        server_channel_id: ServerChannelId,
        name: String,
        value: String,
    ) -> Result<()> {
        let channel_id = self.map_channel(server_channel_id)?;
        if is_reserved_env_name(&name) {
            // Logged without the value: the client chose it, and nothing
            // downstream should ever see it.
            warn!(channel=%channel_id, %name, "Dropping a client-sent environment variable in Warpgate's reserved WARPGATE_ namespace");
            return Ok(());
        }
        debug!(channel=%channel_id, %name, %value, "Environment");
        self.send_command_and_wait(RCCommand::Channel(
            channel_id,
            ChannelOperation::RequestEnv(name, value),
        ))
        .await?;
        Ok(())
    }

    /// Inject Warpgate identity and custom environment variables into the downstream SSH session.
    /// Mirrors inject_own_headers() in the HTTP proxy.
    fn inject_own_env(&mut self, channel_id: Uuid) {
        // Collect all env vars first to avoid borrow conflicts with send_command
        let mut env_vars: Vec<(String, String)> = Vec::new();

        // Built-in: WARPGATE_USERNAME
        if let Some(ref user_info) = self.user_info {
            env_vars.push(("WARPGATE_USERNAME".to_string(), user_info.username.clone()));
        }

        // Built-in: WARPGATE_AUTHENTICATION_TYPE
        if let Some(ref auth_type) = self.authentication_type {
            env_vars.push((
                "WARPGATE_AUTHENTICATION_TYPE".to_string(),
                auth_type.clone(),
            ));
        }

        // Custom env vars from target SSH config
        if let Some(ref env) = self.target_env {
            for (name, value) in env {
                env_vars.push((name.clone(), value.clone()));
            }
        }

        // Send all env vars
        for (name, value) in env_vars {
            let _ = self.send_command(RCCommand::Channel(
                channel_id,
                ChannelOperation::RequestEnv(name, value),
            ));
        }
    }

    /// Makes sure the traffic recorder for `key` exists before a forward opens,
    /// so a refused session never reaches the target. `Break` when the forward
    /// must not open: the recording failed to start and the session was refused,
    /// or unrecorded sessions are refused and there is no target session yet to
    /// record against (a direct forward behind an approval gate).
    async fn prepare_traffic_recorder(
        &mut self,
        key: &TrafficRecorderKey,
        metadata: SshRecordingMetadata,
    ) -> ControlFlow<()> {
        if self.traffic_recorders.contains_key(key) {
            return ControlFlow::Continue(());
        }
        let Some(target_session_id) = self.target_session_id else {
            if self.services.recordings.refuses_unrecorded_sessions()
                && self.recordings_enabled().await
            {
                warn!(
                    ?key,
                    "Refusing a forward opened before its target session exists: it cannot be recorded"
                );
                return ControlFlow::Break(());
            }
            error!(?key, "No target session for traffic recording");
            return ControlFlow::Continue(());
        };
        match self
            .services
            .recordings
            .start_for(&self.recording_owner, &target_session_id, None, metadata)
            .await
        {
            Ok(Some(recorder)) => {
                self.traffic_recorders.insert(key.clone(), recorder);
            }
            Ok(None) => (),
            // Logged by `start_for`.
            Err(_) => return self.refuse_unrecorded_session().await,
        }
        ControlFlow::Continue(())
    }

    /// Whether recording is switched on in the settings. An unreadable setting
    /// counts as on, so a refusal that depends on it fails closed.
    async fn recordings_enabled(&self) -> bool {
        Parameters::Entity::get(&self.services.db)
            .await
            .map_or(true, |p| p.recordings_enable)
    }

    /// Starts a connection on the recorder [`Self::prepare_traffic_recorder`]
    /// made for `key`, if there is one, and writes its setup record. Called
    /// before the forward opens, so a recorder for the key that has died since
    /// it was made is seen before anything reaches the target or the client.
    /// `Break` when that write failed and the session was closed (unrecorded
    /// sessions refused): the forward must not open. `Continue(None)` when there
    /// is no recorder, or its write failed and the forward goes on unrecorded.
    async fn connect_traffic_recorder(
        &mut self,
        key: &TrafficRecorderKey,
        connection_params: TrafficConnectionParams,
    ) -> ControlFlow<(), Option<ConnectionRecorder>> {
        let Some(recorder) = self.traffic_recorders.get(key) else {
            return ControlFlow::Continue(None);
        };
        let mut recorder = recorder.connection(connection_params);
        let required = self.services.recordings.refuses_unrecorded_sessions();
        // When required, the setup record is waited for: queued writes would
        // otherwise let the forward open before its file is seen to fail.
        let written = match recorder.write_connection_setup().await {
            Ok(()) if required => recorder.flush().await.map_err(anyhow::Error::from),
            written => written,
        };
        if let Err(error) = written {
            if recorder.write_failed(&format_args!("{error:#}")) {
                self.close_on_recording_failure().await;
                return ControlFlow::Break(());
            }
            return ControlFlow::Continue(None);
        }
        ControlFlow::Continue(Some(recorder))
    }

    /// Attach a connection [`Self::connect_traffic_recorder`] started to `channel`.
    fn attach_traffic_recorder(&mut self, channel: Uuid, recorder: Option<ConnectionRecorder>) {
        if let Some(recorder) = recorder
            && let Some(channel_state) = self.channels.get_mut(&channel)
        {
            channel_state.traffic_recorder = Some(recorder);
        }
    }

    pub async fn _channel_subsystem_request(
        &mut self,
        server_channel_id: ServerChannelId,
        name: String,
    ) -> Result<(), SshClientError> {
        let channel_id = self.map_channel(server_channel_id)?;
        info!(channel=%channel_id, "Requesting subsystem {}", &name);
        self.end_request_wait(channel_id);
        let _ = self.maybe_connect_remote().await;
        self.send_command_and_wait(RCCommand::Channel(
            channel_id,
            ChannelOperation::RequestSubsystem(name),
        ))
        .await?;
        Ok(())
    }

    async fn _data(&mut self, server_channel_id: ServerChannelId, data: Bytes) -> Result<()> {
        let channel_id = self.map_channel(server_channel_id)?;
        debug!(channel=%server_channel_id.0, ?data, "Data");
        let has_pty = self.channels.get(&channel_id).is_some_and(Channel::has_pty);
        // Only a terminal turns Ctrl-C into a 0x03 byte. On a forwarded
        // connection it's payload — RDP's first packet starts with 0x03, and
        // with `ssh -N` it arrives while the target is still connecting (#2658).
        if has_pty
            && (
                // aborting connection
                self.rc_state == RCState::Connecting
                // aborting admin approval wait
                || matches!(self.target, TargetSelection::AwaitingApproval)
            )
            && data.first() == Some(&3)
        {
            info!(channel=%channel_id, "User requested connection abort (Ctrl-C)");
            let was_held = matches!(self.target, TargetSelection::AwaitingApproval);
            if was_held {
                self.target = TargetSelection::None;
            }
            self.disconnect_token.cancel();
            self.request_disconnect();
            if was_held {
                self.emit_service_message("Session closed")?;
                self.disconnect_server().await;
            }
            return Ok(());
        }

        if self.drops_unrecordable_input(channel_id) {
            return Ok(());
        }

        let mut recording_failed = false;
        if let Some(channel_state) = self.channels.get_mut(&channel_id) {
            recording_failed = channel_state.audit.on_input(&data).await.is_break();

            if let Some(recorder) = channel_state.traffic_recorder.as_mut()
                && let Err(error) = recorder.write_tx(&data).await
            {
                recording_failed |= recorder.write_failed(&format_args!("{error:#}"));
                channel_state.traffic_recorder = None;
            }
        }
        // Closed before the unrecorded input reaches the target.
        if recording_failed {
            self.close_on_recording_failure().await;
            return Ok(());
        }

        if has_pty {
            let _ = self
                .event_sender
                // A copy, not a clone: `data` holds its share of the
                // channel's input budget until dropped, and an idle event
                // subscriber must not keep that share.
                .try_send_once(Event::ConsoleInput(Bytes::copy_from_slice(&data)))
                .await;

            // While a host-key trust prompt is waiting for 'y'/'n', do not forward
            // PTY input to the target channel. Otherwise the prompt-reply byte is
            // queued on the target channel and replays into the shell once the
            // target session opens. Note this runs ahead of the deliberate
            // early-stdin forward below (#2065) — that path exists for exec/scp
            // payloads, which never carry a PTY.
            if self.host_key_trust_prompt_active.load(Ordering::SeqCst) {
                return Ok(());
            }
        }

        // While the target selection menu is open, keystrokes drive the menu
        // (handled above) and there's no target to forward them to.
        // Otherwise forward the data even before the target connection is
        // established: the remote client buffers channel operations and
        // replays them in order once connected, so early stdin (e.g. rsync,
        // scp or Ansible pipelining payloads sent right after the exec
        // request) must not be dropped (#2065).
        if matches!(self.target, TargetSelection::Menu) {
            return Ok(());
        }

        let _ = self.send_command(RCCommand::Channel(channel_id, ChannelOperation::Data(data)));
        Ok(())
    }

    fn _extended_data(
        &self,
        server_channel_id: ServerChannelId,
        code: u32,
        data: Bytes,
    ) -> Result<()> {
        let channel_id = self.map_channel(server_channel_id)?;
        debug!(channel=%server_channel_id.0, ?data, "Data");
        // Extended data from the client is never recorded, at any point of the
        // channel: with unrecorded sessions refused it is dropped. OpenSSH's
        // server discards it on a session channel anyway.
        if self.services.recordings.refuses_unrecorded_sessions() {
            debug!(channel=%channel_id, "Dropping the client's extended data: it cannot be recorded");
            return Ok(());
        }
        let _ = self.send_command(RCCommand::Channel(
            channel_id,
            ChannelOperation::ExtendedData { ext: code, data },
        ));
        Ok(())
    }

    /// The channel's shell, exec or subsystem request has been accepted: from
    /// here its data goes to the recording that request started, if any.
    fn end_request_wait(&mut self, channel_id: Uuid) {
        if let Some(channel_state) = self.channels.get_mut(&channel_id) {
            channel_state.awaits_request = false;
        }
    }

    /// Data on a session channel before its shell, exec or subsystem request
    /// has no recording to go to, yet the target's session channel is already
    /// open and some servers hand such data to the command's stdin. With
    /// unrecorded sessions refused it is dropped, as OpenSSH's server does.
    fn drops_unrecordable_input(&self, channel_id: Uuid) -> bool {
        let drop = self.services.recordings.refuses_unrecorded_sessions()
            && self
                .channels
                .get(&channel_id)
                .is_some_and(|c| c.awaits_request);
        if drop {
            debug!(channel=%channel_id, "Dropping data sent before the channel's request: it cannot be recorded");
        }
        drop
    }

    async fn _tcpip_forward(&mut self, address: String, port: u32) -> Result<()> {
        info!(%address, %port, "Remote port forwarding requested");
        let _ = self.maybe_connect_remote().await;
        self.send_command_and_wait(RCCommand::ForwardTCPIP(address, port))
            .await
            .map_err(anyhow::Error::from)
    }

    pub async fn _cancel_tcpip_forward(&mut self, address: String, port: u32) -> Result<()> {
        info!(%address, %port, "Remote port forwarding cancelled");
        self.send_command_and_wait(RCCommand::CancelTCPIPForward(address, port))
            .await
            .map_err(anyhow::Error::from)
    }

    async fn _streamlocal_forward(&mut self, socket_path: String) -> Result<()> {
        info!(%socket_path, "Remote UNIX socket forwarding requested");
        let _ = self.maybe_connect_remote().await;
        self.send_command_and_wait(RCCommand::StreamlocalForward(socket_path))
            .await
            .map_err(anyhow::Error::from)
    }

    pub async fn _cancel_streamlocal_forward(&mut self, socket_path: String) -> Result<()> {
        info!(%socket_path, "Remote UNIX socket forwarding cancelled");
        self.send_command_and_wait(RCCommand::CancelStreamlocalForward(socket_path))
            .await
            .map_err(anyhow::Error::from)
    }

    async fn _agent_forward(&mut self, server_channel_id: ServerChannelId) -> Result<()> {
        let channel_id = self.map_channel(server_channel_id)?;
        debug!(channel=%channel_id, "Requested Agent Forwarding");
        self.send_command_and_wait(RCCommand::Channel(
            channel_id,
            ChannelOperation::AgentForward,
        ))
        .await?;
        Ok(())
    }

    async fn _auth_publickey_offer(
        &mut self,
        ssh_username: Secret<String>,
        key: PublicKey,
    ) -> russh::server::Auth {
        let selector: AuthSelector = ssh_username.expose_secret().into();

        info!(
            "Client offers public key auth as {selector:?} with key {}",
            key.public_key_base64()
        );
        self.note_probe(&selector, "public_key");

        if !self.allowed_auth_methods.contains(&MethodKind::PublicKey) {
            warn!("Client attempted public key auth even though it was not advertised");
            return russh::server::Auth::reject();
        }

        // Tickets aren't authenticated with public keys, and the eager auth path
        // consumes a ticket use. Running it here — during the unauthenticated
        // offer/query phase — would drain the ticket before the client actually
        // authenticates, so reject and let auth proceed via another method.
        if let AuthSelector::Ticket { .. } = selector {
            return russh::server::Auth::reject();
        }

        if matches!(
            self.try_validate_public_key_offer(
                &selector,
                Some(AuthCredential::PublicKey {
                    kind: key.algorithm(),
                    public_key_bytes: Bytes::from(key.public_key_bytes()),
                }),
            )
            .await,
            Ok(true)
        ) {
            return russh::server::Auth::Accept;
        }

        match self.try_auth_lazy(&selector, None).await {
            Ok(AuthResult::Need(kinds)) => russh::server::Auth::Reject {
                proceed_with_methods: Some(self.get_remaining_auth_methods(kinds)),
                partial_success: false,
            },
            _ => russh::server::Auth::reject(),
        }
    }

    async fn _auth_publickey(
        &mut self,
        ssh_username: Secret<String>,
        key: PublicKey,
    ) -> russh::server::Auth {
        let selector: AuthSelector = ssh_username.expose_secret().into();

        info!(
            "Public key auth as {selector:?} with key {}",
            key.public_key_base64()
        );
        self.note_probe(&selector, "public_key");

        if !self.allowed_auth_methods.contains(&MethodKind::PublicKey) {
            warn!("Client attempted public key auth even though it was not advertised");
            return russh::server::Auth::reject();
        }

        let key = Some(AuthCredential::PublicKey {
            kind: key.algorithm(),
            public_key_bytes: Bytes::from(key.public_key_bytes()),
        });

        let result = self.try_auth_lazy(&selector, key.clone()).await;

        match result {
            Ok(AuthResult::Accepted { .. }) => {
                // Update last_used timestamp
                if let Err(err) = self
                    .services
                    .config_provider
                    .update_public_key_last_used(key.clone())
                    .await
                {
                    warn!(?err, "Failed to update last_used for public key");
                }
                russh::server::Auth::Accept
            }
            Ok(AuthResult::Rejected) => {
                reject_with_allowed_auth_methods(self.allowed_auth_methods.clone())
            }
            Ok(AuthResult::Need(kinds)) => russh::server::Auth::Reject {
                proceed_with_methods: Some(self.get_remaining_auth_methods(kinds)),
                partial_success: false,
            },
            Err(error) => {
                error!(?error, "Failed to verify credentials");
                russh::server::Auth::Reject {
                    proceed_with_methods: None,
                    partial_success: false,
                }
            }
        }
    }

    async fn _auth_password(
        &mut self,
        ssh_username: Secret<String>,
        password: Secret<String>,
    ) -> russh::server::Auth {
        let selector: AuthSelector = ssh_username.expose_secret().into();
        info!("Password auth as {selector:?}");
        self.note_probe(&selector, "password");

        if !self.allowed_auth_methods.contains(&MethodKind::Password) {
            warn!("Client attempted password auth even though it was not advertised");
            if let AuthSelector::User { username, .. } = &selector {
                self.record_failed_login_attempt(username, "password").await;
            }
            return russh::server::Auth::reject();
        }

        let result = self
            .try_auth_lazy(&selector, Some(AuthCredential::Password(password)))
            .await;

        match result {
            Ok(AuthResult::Accepted { .. }) => russh::server::Auth::Accept,
            Ok(AuthResult::Rejected) => russh::server::Auth::reject(),
            Ok(AuthResult::Need(kinds)) => russh::server::Auth::Reject {
                proceed_with_methods: Some(self.get_remaining_auth_methods(kinds)),
                partial_success: false,
            },
            Err(error) => {
                error!(?error, "Failed to verify credentials");
                russh::server::Auth::Reject {
                    proceed_with_methods: None,
                    partial_success: false,
                }
            }
        }
    }

    async fn _auth_keyboard_interactive(
        &mut self,
        ssh_username: Secret<String>,
        responses: Vec<Secret<String>>,
    ) -> Result<russh::server::Auth> {
        let selector: AuthSelector = ssh_username.expose_secret().into();
        info!("Keyboard-interactive auth as {:?}", selector);
        self.note_probe(&selector, "keyboard_interactive");

        if !self
            .allowed_auth_methods
            .contains(&MethodKind::KeyboardInteractive)
        {
            warn!("Client attempted keyboard-interactive auth even though it was not advertised");
            return Ok(russh::server::Auth::reject());
        }

        let keyboard_interactive_state = self.keyboard_interactive_state.take();
        let maybe_otp_cred = if keyboard_interactive_state
            .as_ref()
            .is_some_and(|s| s.otp_prompt_sent)
        {
            responses.into_iter().next().map(AuthCredential::Otp)
        } else {
            None
        };
        // Destructure the taken struct exactly once and move its carried fields
        // forward, so an in-flight wait's broadcast receiver is not dropped at
        // the start of every round.
        let mut next_pending = keyboard_interactive_state
            .map_or_else(PendingKeyboardInteractiveAuth::fresh, carry_forward);

        Ok(match self.try_auth_lazy(&selector, maybe_otp_cred).await {
            Ok(AuthResult::Accepted { .. }) => russh::server::Auth::Accept,
            Ok(AuthResult::Rejected) => russh::server::Auth::reject(),
            Ok(AuthResult::Need(kinds)) => {
                let mut auth_name = "Warpgate authentication".to_string();
                let mut auth_instructions = String::new();
                let mut auth_prompts = vec![];

                // Cloned, not borrowed: everything the round needs afterwards
                // wants `&mut self`, so no borrow of `self` may outlive this
                // point.
                let Some((auth_state, _)) = self.auth_state.clone() else {
                    return Ok(russh::server::Auth::Reject {
                        proceed_with_methods: None,
                        partial_success: false,
                    });
                };

                if kinds.contains(&CredentialKind::Totp) {
                    next_pending.otp_prompt_sent = true;
                    auth_name = "Two-factor authentication".into();
                    auth_prompts.push(("One-time password: ".into(), true));
                }

                if kinds.contains(&CredentialKind::WebUserApproval) {
                    // Two implementations, selected at configuration level.
                    // Within a connection there is no fallback: auto-continue
                    // never degrades to a manual prompt mid-flight, because a
                    // rarely-exercised degrade branch rots undetected.
                    let auto_continue = self
                        .services
                        .config
                        .lock()
                        .await
                        .store
                        .ssh
                        .web_auth_auto_continue;

                    let outcome = if auto_continue {
                        self.web_approval_round_auto(
                            &auth_state,
                            &selector,
                            &kinds,
                            &mut auth_name,
                            &mut auth_instructions,
                            &mut auth_prompts,
                            &mut next_pending,
                        )
                        .await?
                    } else {
                        self.web_approval_round_manual(
                            &auth_state,
                            &mut auth_instructions,
                            &mut auth_prompts,
                        )
                        .await
                    };

                    if let WebApprovalRoundOutcome::Return(auth) = outcome {
                        return Ok(auth);
                    }
                }

                if auth_prompts.is_empty() {
                    russh::server::Auth::Reject {
                        proceed_with_methods: None,
                        partial_success: false,
                    }
                } else {
                    self.keyboard_interactive_state = Some(next_pending);
                    russh::server::Auth::Partial {
                        name: auth_name.into(),
                        instructions: auth_instructions.into(),
                        prompts: auth_prompts.into(),
                    }
                }
            }
            Err(error) => {
                error!(?error, "Failed to verify credentials");
                russh::server::Auth::Reject {
                    proceed_with_methods: None,
                    partial_success: false,
                }
            }
        })
    }

    /// Auto-continue web-approval round (`ssh.web_auth_auto_continue` on).
    ///
    /// Each round is one keyboard-interactive exchange. RFC 4256 §3.2 permits
    /// `num-prompts == 0` and §3.4 *requires* the client to answer with a
    /// zero-response message, so the client auto-acknowledges with no user
    /// interaction and hands the server a fresh round to work with. That is the
    /// whole point of this path: an AI agent or any other non-interactive SSH
    /// client never has to answer a `Press Enter when done: ` prompt.
    ///
    /// The four blocks below are mutually exclusive and each ends in a return.
    /// Read as sequential `if`s instead, the TOTP-plus-web case would fall out
    /// of the TOTP block into the new-wait test, find a matching wait and emit a
    /// zero-prompt round *instead of* the OTP prompt — so those users could
    /// never log in at all.
    #[allow(clippy::too_many_arguments)]
    async fn web_approval_round_auto(
        &mut self,
        auth_state: &Arc<Mutex<AuthState>>,
        selector: &AuthSelector,
        kinds: &HashSet<CredentialKind>,
        auth_name: &mut String,
        auth_instructions: &mut String,
        auth_prompts: &mut Vec<(Cow<'static, str>, bool)>,
        next_pending: &mut PendingKeyboardInteractiveAuth,
    ) -> Result<WebApprovalRoundOutcome> {
        let pending_wait = next_pending.web_approval_wait.take();
        // Copied out so no `AuthState` guard is alive past this statement.
        let identification_string = auth_state.lock().await.identification_string().to_owned();
        let totp_outstanding = kinds.contains(&CredentialKind::Totp);

        // Charged on wait *creation*, never per round: a per-round increment
        // against a cap of 3 would reject real users after roughly 30 s, make the
        // configured budget unreachable and turn the farewell path into dead
        // code. Charged here, ahead of every block that creates one, so the cap
        // counts waits regardless of which block created them — and ahead of
        // `subscribe()` and any auth-state allocation, so a capped client stops
        // allocating. The count lives on `ServerSession`, so a client alternating
        // usernames to force the discard path below inherits it rather than
        // resetting it.
        if round_creates_wait(
            pending_wait.as_ref(),
            &identification_string,
            totp_outstanding,
        ) {
            let (used, capped) = bump_waits(self.web_auth_waits_used);
            self.web_auth_waits_used = used;
            if capped {
                warn!(
                    waits_used = used,
                    "Too many browser-approval waits on this connection"
                );
                // Deliberately no `self.auth_state = None`: keeping
                // `get_auth_state`'s memoization means a capped client stops
                // allocating auth states, each of which the store retains for
                // ten minutes.
                return Ok(WebApprovalRoundOutcome::Return(
                    russh::server::Auth::reject(),
                ));
            }
        }

        // 1. The not-confirmed message went out last round. Reject now, on the
        //    client's automatic empty response. Emitting no `Partial` is what
        //    stops this looping.
        if pending_wait.as_ref().is_some_and(|wait| wait.farewell) {
            return Ok(WebApprovalRoundOutcome::Return(
                russh::server::Auth::reject(),
            ));
        }

        // 2. TOTP is still outstanding, so this round keeps today's shape: the
        //    OTP prompt the caller queued, plus the URL in the instructions.
        //    Owned here rather than delegated to the manual round, because
        //    delegating would mean `subscribe()` never happens.
        if totp_outstanding {
            // The budget for this wait was charged above.
            // Subscribed on the state itself: at v0.28.6 the change signal lives
            // on `AuthState`, not in a store-wide map, and sends happen under
            // the state's own lock — so subscribing here cannot miss a
            // transition and no signal entry is left behind to be vacuumed.
            let receiver = auth_state.lock().await.subscribe();
            let instructions = self.web_auth_instructions(auth_state).await;

            auth_instructions.push_str(&instructions);
            next_pending.web_approval_wait = Some(WebApprovalWait {
                receiver: Some(receiver),
                identification_string: identification_string.clone(),
                // Left unset: the budget starts at the first zero-prompt round,
                // so time spent typing the OTP does not eat it.
                deadline: None,
                round: 1,
                // This round printed the URL, so the first zero-prompt round
                // must suppress it or it goes out twice.
                url_shown: true,
                farewell: false,
            });

            return Ok(self.emit_round(
                std::mem::take(auth_name),
                std::mem::take(auth_instructions),
                std::mem::take(auth_prompts),
                next_pending,
            ));
        }

        // 3. No wait yet, or the carried one belongs to a different principal —
        //    `get_auth_state` mints a new `AuthState` when the username changes,
        //    while the carried receiver still points at the old channel. The
        //    mismatched wait is dropped here and a new one starts at round 1.
        let Some(mut wait) = wait_for_state(pending_wait, &identification_string) else {
            // The budget for this wait was charged above.
            let receiver = auth_state.lock().await.subscribe();
            let instructions = self.web_auth_instructions(auth_state).await;

            auth_instructions.push_str(&instructions);
            next_pending.web_approval_wait = Some(WebApprovalWait {
                receiver: Some(receiver),
                identification_string,
                deadline: None,
                round: 1,
                url_shown: true,
                farewell: false,
            });

            return Ok(self.emit_round(
                std::mem::take(auth_name),
                std::mem::take(auth_instructions),
                // Zero prompts, and returning the reply from here is what keeps
                // it away from the caller's `auth_prompts.is_empty()` branch,
                // which rejects.
                std::mem::take(auth_prompts),
                next_pending,
            ));
        };

        // 4. Rounds 2..N: wait for the approval, then re-evaluate.
        //
        //    Nothing may be held across the wait — no mutex guard and no borrow
        //    of `self`. Awaiting inside the `AuthState` guard would block the
        //    browser's approve POST on the very lock this round is waiting for,
        //    and because the approve path takes the global `auth_state_store`
        //    lock while reaching for the per-state lock, one waiting SSH session
        //    would freeze SSH, HTTP, MySQL and Postgres auth gateway-wide.
        let web_auth_wait_timeout = self
            .services
            .config
            .lock()
            .await
            .store
            .ssh
            .web_auth_wait_timeout;

        let deadline = wait
            .deadline
            .unwrap_or_else(|| Instant::now() + web_auth_wait_timeout);
        wait.deadline = Some(deadline);

        // Clamped so a round never overruns the budget.
        let sleep_for =
            WEB_AUTH_POLL_CADENCE.min(deadline.saturating_duration_since(Instant::now()));

        // The signal is only an early-wake optimisation — the auth state is the
        // source of truth. A lost signal costs at most one round of latency,
        // never a hang and never a wrong verdict.
        match wait.receiver.as_mut() {
            Some(receiver) => {
                tokio::select! {
                    signal = receiver.recv() => {
                        if matches!(signal, Err(broadcast::error::RecvError::Closed)) {
                            // A closed receiver returns instantly from `select!`
                            // on every later round — spinning rounds at client
                            // RTT. Drop it and fall through to a plain clamped
                            // sleep. Nothing is lost: broadcast delivers a
                            // buffered value before reporting `Closed`, and the
                            // verdict below reads the state regardless.
                            // `Lagged` deliberately falls through instead: it
                            // means a transition was missed, and re-verifying is
                            // exactly the right response.
                            wait.receiver = None;
                        }
                    }
                    () = tokio::time::sleep(sleep_for) => {}
                }
            }
            None => tokio::time::sleep(sleep_for).await,
        }

        // Authoritative. The completion signal fires on a browser *rejection*
        // too, so being woken is not evidence of approval — only this verdict
        // can accept. Re-running the real path also keeps the `last_sso_at`
        // stamp exactly as it is today.
        let verdict = self.try_auth_lazy(selector, None).await?;

        match next_web_auth_step(Instant::now(), Some(deadline), wait.url_shown, &verdict) {
            WebAuthStep::Accept => Ok(WebApprovalRoundOutcome::Return(russh::server::Auth::Accept)),
            WebAuthStep::Reject { message: None } => Ok(WebApprovalRoundOutcome::Return(
                russh::server::Auth::reject(),
            )),
            WebAuthStep::Reject {
                message: Some(message),
            } => {
                // Two rounds, because `Auth::Reject` has no text field: the
                // message travels in a final zero-prompt `Partial` and block 1
                // rejects the client's automatic empty response.
                wait.farewell = true;
                next_pending.web_approval_wait = Some(wait);
                Ok(self.emit_round(String::new(), message, vec![], next_pending))
            }
            WebAuthStep::PollAgain { include_url } => {
                let instructions = if include_url {
                    self.web_auth_instructions(auth_state).await
                } else {
                    // Empty name and instructions: OpenSSH prints neither when
                    // they are empty, while PuTTY and Paramiko print the
                    // instruction field on *every* round — so a repeated URL
                    // would be printed once per round.
                    String::new()
                };
                wait.round = wait.round.saturating_add(1);
                wait.url_shown = true;
                next_pending.web_approval_wait = Some(wait);
                Ok(self.emit_round(String::new(), instructions, vec![], next_pending))
            }
        }
    }

    /// Build the browser-approval instructions block, with the login URL when
    /// one can be constructed.
    ///
    /// Every guard it takes is released before it returns, so it is safe to call
    /// on either side of a round wait — but never during one.
    async fn web_auth_instructions(&self, auth_state: &Arc<Mutex<AuthState>>) -> String {
        let identification_string = auth_state.lock().await.identification_string().to_owned();

        let ext_url = construct_control_plane_url(&*self.services.config.lock().await)
            .await
            .inspect_err(|error| {
                warn!(?error, "Failed to construct external URL");
            })
            .ok();

        let auth_state = auth_state.lock().await;
        let login_url = ext_url.map(|ext_url| auth_state.construct_web_approval_url(ext_url));

        format_web_auth_instructions(login_url, &identification_string)
    }

    /// Store the pending state for the next round and emit the `Partial` that
    /// carries it.
    fn emit_round(
        &mut self,
        name: String,
        instructions: String,
        prompts: Vec<(Cow<'static, str>, bool)>,
        next_pending: &mut PendingKeyboardInteractiveAuth,
    ) -> WebApprovalRoundOutcome {
        self.keyboard_interactive_state = Some(std::mem::replace(
            next_pending,
            PendingKeyboardInteractiveAuth::fresh(),
        ));
        WebApprovalRoundOutcome::Return(russh::server::Auth::Partial {
            name: name.into(),
            instructions: instructions.into(),
            prompts: prompts.into(),
        })
    }

    /// Today's Press-Enter web-approval round, behaviour unchanged.
    ///
    /// `subscribe()` is deliberately never called on this path: doing so would
    /// create a `completion_signals` entry on every stale-pubkey login, which
    /// lives until `complete()` or `vacuum()` — a behavioural delta from today.
    async fn web_approval_round_manual(
        &mut self,
        auth_state: &Arc<Mutex<AuthState>>,
        auth_instructions: &mut String,
        auth_prompts: &mut Vec<(Cow<'static, str>, bool)>,
    ) -> WebApprovalRoundOutcome {
        // Charged first, so a capped client stops doing auth-state work. This
        // is the same per-connection budget the auto path charges — see
        // `MAX_WEB_AUTH_WAITS`.
        let is_retry = self.web_auth_waits_used > 0;
        let (used, capped) = bump_waits(self.web_auth_waits_used);
        self.web_auth_waits_used = used;
        if capped {
            warn!(
                waits_used = used,
                "Too many browser-approval waits on this connection"
            );
            self.auth_state = None;
            return WebApprovalRoundOutcome::Return(russh::server::Auth::reject());
        }

        let identification_string = auth_state.lock().await.identification_string().to_owned();

        let ext_url = construct_control_plane_url(&*self.services.config.lock().await)
            .await
            .inspect_err(|error| {
                warn!(?error, "Failed to construct external URL");
            })
            .ok();

        let auth_state = auth_state.lock().await;
        let login_url = ext_url.map(|ext_url| auth_state.construct_web_approval_url(ext_url));

        auth_instructions.push_str(&format_web_auth_instructions(
            login_url,
            &identification_string,
        ));
        auth_prompts.push(("Press Enter when done: ".into(), true));

        if is_retry {
            auth_instructions.push_str(WEB_AUTH_NOT_CONFIRMED_MESSAGE);
        }

        WebApprovalRoundOutcome::Continue
    }

    fn get_remaining_auth_methods(&self, kinds: HashSet<CredentialKind>) -> MethodSet {
        let mut m = MethodSet::empty();

        for cred_kind in kinds {
            let method_kind = match cred_kind {
                CredentialKind::Password => MethodKind::Password,
                CredentialKind::Totp | CredentialKind::WebUserApproval | CredentialKind::Sso => {
                    MethodKind::KeyboardInteractive
                }
                CredentialKind::PublicKey => MethodKind::PublicKey,
                CredentialKind::Certificate => {
                    // Certificate authentication is not supported for SSH protocol
                    // This credential type is primarily for Kubernetes
                    continue;
                }
            };
            if self.allowed_auth_methods.contains(&method_kind) {
                m.push(method_kind);
            }
        }

        if m.contains(&MethodKind::KeyboardInteractive) {
            // Ensure keyboard-interactive is always the last method
            m.push(MethodKind::KeyboardInteractive);
        }

        m
    }

    async fn try_validate_public_key_offer(
        &self,
        selector: &AuthSelector,
        credential: Option<AuthCredential>,
    ) -> Result<bool> {
        match selector {
            AuthSelector::User { username, .. } => {
                let cp = self.services.config_provider.clone();

                if let Some(credential) = credential {
                    // The offer phase only asks whether the key would work;
                    // nothing is added to the auth state here.
                    return Ok(cp
                        .validate_credential(username, &credential)
                        .await?
                        .is_some());
                }

                Ok(false)
            }
            AuthSelector::Ticket { .. } => Ok(false),
        }
    }

    /// As try_auth_lazy is called multiple times, this memoization prevents
    /// consuming the ticket multiple times, depleting its uses.
    async fn try_auth_lazy(
        &mut self,
        selector: &AuthSelector,
        credential: Option<AuthCredential>,
    ) -> Result<AuthResult> {
        if let AuthSelector::Ticket { secret } = selector {
            if let Some(ref csta) = self.cached_successful_ticket_auth {
                // Only if the client hasn't maliciously changed the username
                // between auth attempts
                if &csta.ticket == secret {
                    return Ok(AuthResult::Accepted {
                        user_info: csta.user_info.clone(),
                    });
                }
            }

            let result = self.try_auth_eager(selector, credential).await?;
            if let AuthResult::Accepted { ref user_info } = result {
                self.cached_successful_ticket_auth = Some(CachedSuccessfulTicketAuth {
                    ticket: secret.clone(),
                    user_info: user_info.clone(),
                });
            }

            return Ok(result);
        }
        self.try_auth_eager(selector, credential).await
    }

    async fn try_auth_eager(
        &mut self,
        selector: &AuthSelector,
        credential: Option<AuthCredential>,
    ) -> Result<AuthResult> {
        let remote_ip = self.remote_address.ip();

        // Login protection applies to every auth path, tickets included:
        // reject attempts from blocked IPs before evaluating anything.
        if self
            .services
            .login_protection
            .check_ip_blocked(&remote_ip)
            .await?
            .is_some()
        {
            warn!(ip = %remote_ip, "SSH auth from blocked IP");
            return Ok(AuthResult::Rejected);
        }

        match selector {
            AuthSelector::User {
                username,
                target_name,
            } => {
                if self
                    .services
                    .login_protection
                    .check_user_locked(username)
                    .await?
                    .is_some()
                {
                    warn!(username = %username, "SSH auth for locked user");
                    return Ok(AuthResult::Rejected);
                }

                // Resolve default SSH target when no target is specified
                let resolved_target_name = if target_name.is_empty() {
                    let config = self.services.config.lock().await;
                    if let Some(ref default) = config.store.ssh.default_target {
                        info!("No target specified, using default SSH target: {}", default);
                        default.clone()
                    } else {
                        target_name.clone()
                    }
                } else {
                    target_name.clone()
                };

                let state_arc = self
                    .get_auth_state(
                        username,
                        target_name,
                        credential
                            .as_ref()
                            .and_then(Self::rate_limited_credential_type),
                    )
                    .await?;
                let mut state = state_arc.lock().await;

                if let Some(credential) = credential {
                    let credential_type = Self::rate_limited_credential_type(&credential);
                    // The fingerprint of the key the client signed with, taken
                    // before the credential is consumed.
                    let presented_fingerprint = match &credential {
                        AuthCredential::PublicKey {
                            public_key_bytes, ..
                        } => public_key_fingerprint(public_key_bytes),
                        _ => None,
                    };
                    let outcome = submit_credential(
                        &mut state,
                        credential,
                        self.services.config_provider.as_ref(),
                        &self.services.login_protection,
                    )
                    .await?;

                    if outcome.is_valid() {
                        self.probe = ProbeState::Settled;
                        // The state is locked since the submission, so the
                        // last matched key row is the one it just matched.
                        if let (Some(fingerprint), Some(row_id)) = (
                            presented_fingerprint,
                            state.matched_public_key_ids().last().copied(),
                        ) {
                            self.authenticated_pubkeys.push(AuthenticatedKey {
                                row_id,
                                fingerprint,
                            });
                        }
                    } else if let Some(credential_type) = credential_type {
                        self.record_failed_login_attempt(username, credential_type)
                            .await;
                    }
                }

                if matches!(state.verify(), AuthResult::Need(ref kinds) if kinds.contains(&CredentialKind::WebUserApproval))
                {
                    drop(state);
                    // An explicit decision recorded for this session wins over
                    // a remembered grant, so it is pulled first.
                    self.services.apply_recorded_user_decision(&self.id).await?;
                    self.services.try_web_approval_bypass(&state_arc).await?;
                    state = state_arc.lock().await;
                }

                let user_auth_result = state.verify();

                match user_auth_result {
                    AuthResult::Accepted { user_info } => {
                        // Successful auth clears the failed-attempt counters.
                        let _ = self
                            .services
                            .login_protection
                            .clear_failed_attempts(&remote_ip, &user_info.username)
                            .await;

                        // Step-up freshness gate (per-pubkey). If the config
                        // has `step_up_interval.ssh` set and a pubkey matched,
                        // require a `WebUserApproval` handshake at most every
                        // `interval`. A real WebUserApproval already present in
                        // valid_credentials (the user just finished the web
                        // approval in the keyboard-interactive loop) satisfies
                        // the gate and lets us stamp `last_sso_at` below.
                        //
                        // The matched row comes from upstream's
                        // `StoredCredential`. Defensive: anything other than
                        // exactly one matched key row is treated as stale, so
                        // we force a fresh handshake rather than silently pass.
                        //
                        // Snapshot what the gate needs and drop the AuthState
                        // guard before taking the config lock, so AuthState
                        // stays the innermost lock in this module.
                        // The same key listed twice is still one key.
                        let mut matched_pubkey_ids = state.matched_public_key_ids();
                        matched_pubkey_ids.sort_unstable();
                        matched_pubkey_ids.dedup();
                        let valid_kinds = state.valid_credential_kinds();
                        // A `WebUserApproval` that the grace-period bypass
                        // injected from a remembered approval is not proof that
                        // this attempt did an SSO handshake, so it must not
                        // satisfy the gate or move the clock below.
                        let approval_was_bypassed = state.web_approval_from_grace_bypass();
                        drop(state);

                        let step_up_config = {
                            let cfg = self.services.config.lock().await;
                            cfg.store.step_up_interval.clone()
                        };
                        let step_up_ssh = step_up_config.as_ref().and_then(|s| s.ssh);
                        // Set, with the fingerprints of the keys it was
                        // decided on, when `step_up_interval.exempt_users`
                        // lets this key sign-in skip the check below.
                        let mut exempt_fingerprints: Option<Vec<String>> = None;
                        if let (Some(interval), Some(step_up_config)) =
                            (step_up_ssh, step_up_config.as_ref())
                        {
                            let has_stepup = web_approval_proves_step_up(
                                valid_kinds.contains(&CredentialKind::WebUserApproval),
                                approval_was_bypassed,
                            );
                            let pubkey_used = valid_kinds.contains(&CredentialKind::PublicKey);
                            // The exemption is looked at only for a key
                            // sign-in that would otherwise face the check; it
                            // reads the user's credentials from the database
                            // and logs why it did not apply. The fingerprints
                            // it returns are kept to end the connection if a
                            // reload stops listing it or a key changes.
                            if pubkey_used && !has_stepup {
                                // Deliberate defence in depth: the exemption
                                // check re-verifies the same condition inside
                                // `presented_keys_match_rows` (step_up.rs).
                                // This gate is unit-tested only as a pure
                                // function; the e2e test
                                // `tests/test_ssh_step_up_exempt_users.py`
                                // covers its wiring here.
                                if !presented_keys_recorded(
                                    &matched_pubkey_ids,
                                    &self.authenticated_pubkeys,
                                ) {
                                    debug!(
                                        username = %user_info.username,
                                        "step-up exemption not considered: no presented key \
                                         fingerprint recorded for a matched key"
                                    );
                                } else if let StepUpExemption::Applies(fingerprints) =
                                    ssh_step_up_exemption(
                                        &self.services.db,
                                        step_up_config,
                                        user_info.id,
                                        &user_info.username,
                                        &matched_pubkey_ids,
                                        &self.authenticated_pubkeys,
                                        &resolved_target_name,
                                    )
                                    .await?
                                {
                                    exempt_fingerprints = Some(fingerprints);
                                }
                            }
                            if pubkey_used && !has_stepup && exempt_fingerprints.is_none() {
                                // Every matched key must be fresh; no matched
                                // key at all is stale.
                                let mut all_fresh = !matched_pubkey_ids.is_empty();
                                for pubkey_id in &matched_pubkey_ids {
                                    let last =
                                        get_pubkey_last_sso_at(&self.services.db, *pubkey_id)
                                            .await?;
                                    all_fresh &=
                                        is_fresh(last, interval, OffsetDateTime::now_utc());
                                }
                                if !all_fresh {
                                    info!(
                                        username = %user_info.username,
                                        "SSH step-up required: pubkey last_sso_at is stale or missing"
                                    );
                                    // Flip the AuthState into step-up mode so
                                    // verify() reports Need(WebUserApproval) to
                                    // the browser approve page and to the
                                    // approval-request forwarder. Without this
                                    // the UI sees Accepted, hides the Authorize
                                    // button, and SSH keyboard-interactive loops
                                    // until the client gives up.
                                    state_arc.lock().await.require_step_up();
                                    return Ok(AuthResult::Need(
                                        [CredentialKind::WebUserApproval].into_iter().collect(),
                                    ));
                                }
                            }
                        }

                        // Re-acquire for the rest of the accept path.
                        let state = state_arc.lock().await;

                        // The state is `Accepted` here, so this yields the sealed proof.
                        let Some(identity) = AuthorizedIdentity::from_auth_state(&state) else {
                            return Ok(AuthResult::Rejected);
                        };
                        let authorization = if resolved_target_name.is_empty() {
                            None
                        } else {
                            let Some(authorization) = authorize_for_target_by_name(
                                self.services.config_provider.as_ref(),
                                &identity,
                                &resolved_target_name,
                            )
                            .await?
                            else {
                                warn!(
                                    "Target {} not authorized for user {}",
                                    resolved_target_name, username
                                );
                                return Ok(AuthResult::Rejected);
                            };
                            Some(authorization)
                        };
                        // Refused when the user was removed, or their
                        // allowed ranges changed to leave this address out,
                        // while the sign-in was in progress.
                        if let Err(error) = self
                            .admit_user_sign_in(identity, user_info.clone(), authorization)
                            .await
                        {
                            if matches!(error, WarpgateError::UserNoLongerAdmitted) {
                                return Ok(AuthResult::Rejected);
                            }
                            return Err(error.into());
                        }
                        self.authentication_type = Some("user".to_string());

                        // Every key login is tracked, so step-up switched on
                        // later still applies; the check does nothing while
                        // step-up is off.
                        //
                        // An exempt sign-in has no SSO stamp to expire against;
                        // it is tracked by its grant instead.
                        if let Some(fingerprints) = exempt_fingerprints {
                            info!(
                                session = %self.id,
                                remote_ip = %self.remote_address.ip(),
                                username = %user_info.username,
                                key_fingerprint = %fingerprints.join(","),
                                target = %if resolved_target_name.is_empty() {
                                    "unknown"
                                } else {
                                    resolved_target_name.as_str()
                                },
                                "SSH sign-in allowed by step-up exemption"
                            );
                            self.step_up_exempt = Some(ExemptGrant {
                                username: user_info.username.clone(),
                                user_id: user_info.id,
                                pubkey_ids: matched_pubkey_ids.clone(),
                                fingerprints,
                                target: resolved_target_name.clone(),
                                granted_at: Instant::now(),
                            });
                            self.step_up_recheck = Some(Instant::now() + STEP_UP_RECHECK_MIN);
                        } else if valid_kinds.contains(&CredentialKind::PublicKey) {
                            self.step_up_pubkeys = Some(matched_pubkey_ids.clone());
                            self.step_up_recheck = Some(Instant::now());
                        }

                        // Stamp last_sso_at on the exact pubkey row only when
                        // this accept was itself gated on a step-up - i.e. a
                        // real WebUserApproval was presented alongside the
                        // pubkey. Accepts that bypass the gate (step-up
                        // disabled, or still within a fresh window) must NOT
                        // refresh the clock, else the window gets silently
                        // extended on every reconnect and step-up never fires.
                        // That includes an approval injected by the web-approval
                        // grace period: it was granted for an earlier attempt.
                        if step_up_ssh.is_some()
                            && web_approval_proves_step_up(
                                valid_kinds.contains(&CredentialKind::WebUserApproval),
                                approval_was_bypassed,
                            )
                        {
                            for pubkey_id in &matched_pubkey_ids {
                                if let Err(error) = update_pubkey_last_sso_at(
                                    &self.services.db,
                                    *pubkey_id,
                                    OffsetDateTime::now_utc(),
                                )
                                .await
                                {
                                    warn!(
                                        %error,
                                        %pubkey_id,
                                        username = %user_info.username,
                                        "Failed to stamp pubkey last_sso_at"
                                    );
                                }
                            }
                        }

                        Ok(AuthResult::Accepted { user_info })
                    }
                    x => Ok(x),
                }
            }
            AuthSelector::Ticket { secret } => {
                match authorize_and_spend_ticket(
                    &self.services.db,
                    &self.services.login_protection,
                    secret,
                    Some(remote_ip),
                    crate::PROTOCOL_NAME,
                )
                .await?
                {
                    Some(authorization) => {
                        info!(
                            "Authorized for {} with a ticket",
                            authorization.target().name
                        );
                        let user_info = authorization.user_info().clone();
                        // The ticket's use was spent above, before this
                        // check, so a sign-in refused here has used one up.
                        // That is accepted: it only happens while a change to
                        // the user is in progress.
                        if let Err(error) = self
                            ._auth_accept(user_info.clone(), Some(authorization))
                            .await
                        {
                            if matches!(error, WarpgateError::UserNoLongerAdmitted) {
                                return Ok(AuthResult::Rejected);
                            }
                            return Err(error.into());
                        }
                        self.authentication_type = Some("ticket".to_string());

                        Ok(AuthResult::Accepted { user_info })
                    }
                    None => Ok(AuthResult::Rejected),
                }
            }
        }
    }

    /// Completes a key sign-in at the connection's handle, then records the
    /// identity the target menu authorizes against. The identity is recorded
    /// only once [`Self::_auth_accept`] has succeeded, so any error from it,
    /// a refusal or not, leaves it unset.
    async fn admit_user_sign_in(
        &mut self,
        identity: AuthorizedIdentity,
        user_info: AuthStateUserInfo,
        authorization: Option<TargetAuthorization>,
    ) -> Result<(), WarpgateError> {
        self._auth_accept(user_info, authorization).await?;
        self.authorized_identity = Some(identity);
        Ok(())
    }

    async fn _auth_accept(
        &mut self,
        user_info: AuthStateUserInfo,
        authorization: Option<TargetAuthorization>,
    ) -> Result<(), WarpgateError> {
        // Set only once the sign-in is admitted where it completes.
        self.server_handle
            .lock()
            .await
            .set_user_info(user_info.clone())
            .await?;
        self.user_info = Some(user_info.clone());

        let Some(authorization) = authorization else {
            self.target = TargetSelection::Menu;
            return Ok(());
        };

        // The authorization already carries the resolved target; all that's left is
        // that it be reachable over SSH.
        let target_name = authorization.target().name.clone();
        let Ok(authorization) = authorization.narrow::<TargetSSHOptions>() else {
            self.target = TargetSelection::NotFound(target_name);
            warn!("Selected target is not an SSH target");
            return Ok(());
        };

        let started = self
            .server_handle
            .lock()
            .await
            .start_target_session(authorization)
            .await?;
        match started {
            TargetSessionStart::Started(admitted) => {
                self.stamp_approved_target(admitted).await;
            }
            TargetSessionStart::NeedsApproval(authorization) => {
                self.target = TargetSelection::PendingApproval(authorization);
            }
        }
        Ok(())
    }

    async fn _channel_close(&mut self, server_channel_id: ServerChannelId) -> Result<()> {
        if self.rc_state == RCState::Disconnected || self.session_handle.is_none() {
            debug!(channel=%server_channel_id.0, "Ignoring close after backend shutdown");
            return Ok(());
        }

        let Ok(channel_id) = self.map_channel(server_channel_id) else {
            debug!(channel=%server_channel_id.0, "Channel already closed");
            return Ok(());
        };
        debug!(channel=%channel_id, "Closing channel");
        self.send_command_and_wait(RCCommand::Channel(channel_id, ChannelOperation::Close))
            .await?;
        self.channels.close(channel_id);
        Ok(())
    }

    /// The target stopped taking this channel's input. Ends the channel at the
    /// target without waiting for the input queued before it; the target-side
    /// close that follows closes the client's channel the usual way.
    fn _channel_stalled(&self, server_channel_id: ServerChannelId) {
        if self.rc_state == RCState::Disconnected || self.session_handle.is_none() {
            return;
        }
        let Ok(channel_id) = self.map_channel(server_channel_id) else {
            debug!(channel=%server_channel_id.0, "Stalled channel already closed");
            return;
        };
        warn!(channel=%channel_id, "Closing the channel: the target stopped taking its input");
        let _ = self.send_command(RCCommand::Channel(channel_id, ChannelOperation::Abort));
    }

    fn _channel_eof(&self, server_channel_id: ServerChannelId) -> Result<()> {
        if self.rc_state == RCState::Disconnected || self.session_handle.is_none() {
            debug!(channel=%server_channel_id.0, "Ignoring eof after backend shutdown");
            return Ok(());
        }

        let channel_id = self.map_channel(server_channel_id)?;
        debug!(channel=%channel_id, "EOF");
        let _ = self.send_command(RCCommand::Channel(channel_id, ChannelOperation::Eof));
        Ok(())
    }

    pub async fn _channel_signal(
        &mut self,
        server_channel_id: ServerChannelId,
        signal: Sig,
    ) -> Result<()> {
        if self.rc_state == RCState::Disconnected || self.session_handle.is_none() {
            debug!(channel=%server_channel_id.0, ?signal, "Ignoring signal after backend shutdown");
            return Ok(());
        }

        let channel_id = self.map_channel(server_channel_id)?;
        debug!(channel=%channel_id, ?signal, "Signal");
        self.send_command_and_wait(RCCommand::Channel(
            channel_id,
            ChannelOperation::Signal(signal),
        ))
        .await?;
        Ok(())
    }

    fn send_command(&self, command: RCCommand) -> Result<(), RCCommand> {
        self.rc_tx.send((command, None)).map_err(|e| e.0.0)
    }

    /// Send a command to the target and consume events until its reply arrives
    /// on the oneshot.
    ///
    /// Consuming keeps the queue moving so the reply can't deadlock on
    /// backpressure; the events themselves wait in [`Self::pending_events`] for
    /// the main loop. Dispatching them here would let a handler await a command
    /// of its own and take the next event one stack frame deeper — a client
    /// that opens its channels in a burst, every open queued behind the same
    /// unanswered command, walks that chain until the worker stack overflows.
    /// Holding them back is safe because no reply depends on anything the
    /// session does: the client task answers commands from a loop that never
    /// waits on the session, not even for the unknown-host-key prompt.
    ///
    /// The wait is bounded ([`reply_limit`]): a target connection that has
    /// stopped sending (russh#789) never answers a channel open, and without a
    /// bound the client's open would hang silently for the life of the
    /// session. Past the bound the command fails with
    /// [`SshClientError::NoReply`], so the caller rejects the open.
    async fn send_command_and_wait(&mut self, command: RCCommand) -> Result<(), SshClientError> {
        let kind = command_kind(&command);
        let limit = reply_limit(&command);
        let opening = match &command {
            RCCommand::Channel(
                id,
                ChannelOperation::OpenShell
                | ChannelOperation::OpenDirectTCPIP(_)
                | ChannelOperation::OpenDirectStreamlocal(_),
            ) => Some(*id),
            _ => None,
        };
        let (tx, rx) = oneshot::channel();
        let cmd = match self.rc_tx.send((command, Some(tx))) {
            Ok(()) => PendingCommand::Waiting(rx),
            Err(_) => PendingCommand::Failed,
        };

        let result = wait_for_reply(cmd, limit, &mut self.intake, &mut self.pending_events).await;
        if let Err(SshClientError::NoReply(_)) = result {
            warn!(
                command = kind,
                channel = ?opening,
                ?limit,
                "No reply from the target connection; failing the request"
            );
            // Should the open still complete later, close the target-side
            // channel it would leave behind.
            if let Some(id) = opening {
                let _ = self.send_command(RCCommand::Channel(id, ChannelOperation::Close));
            }
        }
        result
    }

    pub fn _disconnect(&self) {
        debug!("Client disconnect requested");
        self.request_disconnect();
    }

    fn request_disconnect(&self) {
        debug!("Disconnecting");
        let _ = self.rc_abort_tx.send(());
        if self.rc_state != RCState::NotInitialized && self.rc_state != RCState::Disconnected {
            let _ = self.send_command(RCCommand::Disconnect);
        }
    }

    async fn disconnect_server(&mut self) {
        // Entries stay in place: several callers return into the running event
        // loop, which still needs the channels to record trailing output and to
        // map target events back to the client. Closing twice is harmless —
        // `session_handle` is cleared below, so the second pass sends nothing.
        let channels = self
            .channels
            .values()
            .filter(|channel| channel.is_open())
            .filter_map(Channel::server_id)
            .collect::<Vec<_>>();

        if let Some(handle) = self.session_handle.clone() {
            for ch in channels {
                let _ = self.channel_writer.close(handle.clone(), ch.0);
            }
        }

        // Bounded: a client whose window is full never lets the queue
        // drain, and this runs on the event loop.
        let flushed = tokio::time::timeout(DISCONNECT_FLUSH_TIMEOUT, self.channel_writer.flush())
            .await
            .is_ok();

        if let Some(socket) = self.client_socket.take() {
            // A flush only proves the messages reached russh's queue, so a
            // client that is reading gets a moment to receive them; one that
            // is not gets nothing more and is cut immediately. Spawned rather
            // than awaited: this can run inside a russh callback, and russh
            // cannot write anything until that callback returns.
            let delay = if flushed {
                DISCONNECT_FLUSH_TIMEOUT
            } else {
                warn!("Client is not reading; closing its connection");
                Duration::ZERO
            };
            // A channel close says nothing about the connection, so a dead
            // target never gives the client a reason to let go of the socket
            // (#2520). It goes only to a client that is still reading, and
            // only after `DISCONNECT_NOTICE_GAP`.
            let handle = flushed.then(|| self.session_handle.clone()).flatten();
            let description = self.disconnect_description.clone();
            tokio::spawn(async move {
                if let Some(handle) = handle {
                    tokio::time::sleep(DISCONNECT_NOTICE_GAP).await;
                    let _ = tokio::time::timeout(
                        DISCONNECT_FLUSH_TIMEOUT,
                        handle.disconnect(
                            russh::Disconnect::ByApplication,
                            description,
                            String::new(),
                        ),
                    )
                    .await;
                }
                tokio::time::sleep(delay.saturating_sub(DISCONNECT_NOTICE_GAP)).await;
                let _ = socket.shutdown(std::net::Shutdown::Both);
            });
        }

        self.session_handle = None;
    }
}

impl Drop for ServerSession {
    fn drop(&mut self) {
        let _ = self.rc_abort_tx.send(());
        info!("Closed session");
        debug!("Dropped");
    }
}

/// How long [`ServerSession::send_command_and_wait`] waits for the target
/// connection to answer a command. A target answers a session channel open
/// or a request within milliseconds; no reply after this long means the
/// target connection has stopped sending.
const TARGET_REPLY_TIMEOUT: Duration = Duration::from_secs(30);

/// A `direct-tcpip` or `direct-streamlocal` open is only answered once the
/// target has connected onwards, which may take until its own TCP connect
/// times out (about two minutes on Linux), so it gets longer.
const TARGET_FORWARD_OPEN_TIMEOUT: Duration = Duration::from_secs(150);

const fn reply_limit(command: &RCCommand) -> Duration {
    match command {
        RCCommand::Channel(
            _,
            ChannelOperation::OpenDirectTCPIP(_) | ChannelOperation::OpenDirectStreamlocal(_),
        ) => TARGET_FORWARD_OPEN_TIMEOUT,
        _ => TARGET_REPLY_TIMEOUT,
    }
}

/// What a command is, for logs: never its arguments (commands, environment
/// values and paths stay out of the log).
const fn command_kind(command: &RCCommand) -> &'static str {
    match command {
        RCCommand::Connect(_) => "connect",
        RCCommand::CheckHostKey { .. } => "check host key",
        RCCommand::Channel(_, operation) => match operation {
            ChannelOperation::OpenShell => "open session channel",
            ChannelOperation::OpenDirectTCPIP(_) => "open direct-tcpip channel",
            ChannelOperation::OpenDirectStreamlocal(_) => "open direct-streamlocal channel",
            ChannelOperation::OpenX11(..) => "open x11 channel",
            ChannelOperation::RequestPty(_) => "pty request",
            ChannelOperation::ResizePty(_) => "window change",
            ChannelOperation::RequestShell => "shell request",
            ChannelOperation::RequestEnv(..) => "env request",
            ChannelOperation::RequestExec(_) => "exec request",
            ChannelOperation::RequestX11(_) => "x11 request",
            ChannelOperation::AgentForward => "agent forwarding request",
            ChannelOperation::RequestSubsystem(_) => "subsystem request",
            ChannelOperation::Data(_) | ChannelOperation::ExtendedData { .. } => "data",
            ChannelOperation::Close => "close",
            ChannelOperation::Abort => "abort",
            ChannelOperation::Eof => "eof",
            ChannelOperation::Signal(_) => "signal",
        },
        RCCommand::ForwardTCPIP(..) => "tcpip-forward",
        RCCommand::CancelTCPIPForward(..) => "cancel-tcpip-forward",
        RCCommand::StreamlocalForward(_) => "streamlocal-forward",
        RCCommand::CancelStreamlocalForward(_) => "cancel-streamlocal-forward",
        RCCommand::Disconnect => "disconnect",
    }
}

/// Wait up to `limit` for `reply`, moving every event that arrives meanwhile
/// into `held` (see [`ServerSession::send_command_and_wait`]).
async fn wait_for_reply<E>(
    mut reply: PendingCommand,
    limit: Duration,
    intake: &mut EventIntake<E>,
    held: &mut VecDeque<E>,
) -> Result<(), SshClientError> {
    let deadline = tokio::time::sleep(limit);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            result = &mut reply => break result,
            () = &mut deadline => break Err(SshClientError::NoReply(limit)),
            event = intake.next() => match event {
                Some(event) => held.push_back(event),
                None => break Err(SshClientError::MpscError),
            },
        }
    }
}

pub enum PendingCommand {
    Waiting(oneshot::Receiver<Result<(), SshClientError>>),
    Failed,
}

impl Future for PendingCommand {
    type Output = Result<(), SshClientError>;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        match self.get_mut() {
            Self::Waiting(rx) => match Pin::new(rx).poll(cx) {
                Poll::Ready(result) => {
                    Poll::Ready(result.unwrap_or(Err(SshClientError::MpscError)))
                }
                Poll::Pending => Poll::Pending,
            },
            Self::Failed => Poll::Ready(Err(SshClientError::MpscError)),
        }
    }
}
