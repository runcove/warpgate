use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use anyhow::Context;
use bytes::Bytes;
use russh::keys::PublicKey;
use russh::server::{Auth, ChannelOpenHandle, Handle, Msg, Session};
use russh::{Channel, ChannelId, Pty, Sig};
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot, watch};
use tokio_util::sync::CancellationToken;
use tracing::*;
use warpgate_common::Secret;

use crate::common::{PtyRequest, ServerChannelId};
use crate::{DirectTCPIPParams, X11Request};

pub struct HandleWrapper(pub Handle);

impl Debug for HandleWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HandleWrapper")
    }
}

/// Carries a channel-open reply handle into the session event loop so the
/// confirmation is sent from the same task that writes channel data, keeping
/// `CHANNEL_OPEN_CONFIRMATION` ahead of the target's first bytes (#2328).
pub struct ChannelOpenHandleWrapper(pub ChannelOpenHandle);

impl Debug for ChannelOpenHandleWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ChannelOpenHandleWrapper")
    }
}

#[derive(Debug)]
pub enum ServerHandlerEvent {
    Authenticated(HandleWrapper),
    ChannelOpenSession(ServerChannelId, ChannelOpenHandleWrapper),
    SubsystemRequest(ServerChannelId, String, oneshot::Sender<bool>),
    PtyRequest(ServerChannelId, PtyRequest, oneshot::Sender<()>),
    ShellRequest(ServerChannelId, oneshot::Sender<bool>),
    AuthPublicKey(Secret<String>, PublicKey, oneshot::Sender<Auth>),
    AuthPublicKeyOffer(Secret<String>, PublicKey, oneshot::Sender<Auth>),
    AuthPassword(Secret<String>, Secret<String>, oneshot::Sender<Auth>),
    AuthKeyboardInteractive(Secret<String>, Vec<Secret<String>>, oneshot::Sender<Auth>),
    Data(ServerChannelId, Bytes, oneshot::Sender<()>),
    ExtendedData(ServerChannelId, Bytes, u32, oneshot::Sender<()>),
    ChannelClose(ServerChannelId, oneshot::Sender<()>),
    /// The target stopped taking this channel's input: end the channel and
    /// drop the input still waiting for it.
    ChannelStalled(ServerChannelId, oneshot::Sender<()>),
    ChannelEof(ServerChannelId, oneshot::Sender<()>),
    WindowChangeRequest(ServerChannelId, PtyRequest, oneshot::Sender<()>),
    Signal(ServerChannelId, Sig, oneshot::Sender<()>),
    ExecRequest(ServerChannelId, Bytes, oneshot::Sender<bool>),
    ChannelOpenDirectTcpIp(ServerChannelId, DirectTCPIPParams, ChannelOpenHandleWrapper),
    ChannelOpenDirectStreamlocal(ServerChannelId, String, ChannelOpenHandleWrapper),
    EnvRequest(ServerChannelId, String, String, oneshot::Sender<()>),
    X11Request(ServerChannelId, X11Request, oneshot::Sender<()>),
    TcpIpForward(String, u32, oneshot::Sender<bool>),
    CancelTcpIpForward(String, u32, oneshot::Sender<bool>),
    StreamlocalForward(String, oneshot::Sender<bool>),
    CancelStreamlocalForward(String, oneshot::Sender<bool>),
    AgentForward(ServerChannelId, oneshot::Sender<bool>),
    Disconnect,
}

impl ServerHandlerEvent {
    /// The already-open channel this event refers to, if any.
    /// Channel open events establish new channels and are not included.
    ///
    /// Deliberately a total match: event deferral during pending channel
    /// opens keys off this (#1459), so a new variant must explicitly decide
    /// whether it names a channel rather than silently defaulting to "no".
    pub(crate) const fn existing_channel(&self) -> Option<ServerChannelId> {
        match self {
            Self::SubsystemRequest(channel, ..)
            | Self::PtyRequest(channel, ..)
            | Self::ShellRequest(channel, ..)
            | Self::Data(channel, ..)
            | Self::ExtendedData(channel, ..)
            | Self::ChannelClose(channel, ..)
            | Self::ChannelStalled(channel, ..)
            | Self::ChannelEof(channel, ..)
            | Self::WindowChangeRequest(channel, ..)
            | Self::Signal(channel, ..)
            | Self::ExecRequest(channel, ..)
            | Self::EnvRequest(channel, ..)
            | Self::X11Request(channel, ..)
            | Self::AgentForward(channel, ..) => Some(*channel),
            Self::Authenticated(_)
            | Self::ChannelOpenSession(..)
            | Self::AuthPublicKey(..)
            | Self::AuthPublicKeyOffer(..)
            | Self::AuthPassword(..)
            | Self::AuthKeyboardInteractive(..)
            | Self::ChannelOpenDirectTcpIp(..)
            | Self::ChannelOpenDirectStreamlocal(..)
            | Self::TcpIpForward(..)
            | Self::CancelTcpIpForward(..)
            | Self::StreamlocalForward(..)
            | Self::CancelStreamlocalForward(..)
            | Self::Disconnect => None,
        }
    }
}

/// How much of one channel's input may be on its way to the target at once
/// (OpenSSH's default channel window). Past it Warpgate stops reading the
/// connection until the target has taken earlier input, so a slow or stalled
/// target slows the upload down (TCP holds the client back) instead of
/// piling it up in memory. A target that takes none of it for the channel
/// stall timeout has the channel closed, which frees the connection again.
pub const CHANNEL_INPUT_BUDGET: usize = 2 * 1024 * 1024;

/// How much input all of one connection's channels together may have on its
/// way to targets at once. Without it, input spread over many channels would
/// add up past any single channel's budget.
pub const CONNECTION_INPUT_BUDGET: usize = 16 * 1024 * 1024;

/// A pool of input room, and a counter that moves whenever room is given back,
/// so a waiter can tell a target that is slow from one that has stopped.
#[derive(Clone)]
struct InputBudget {
    semaphore: Arc<Semaphore>,
    progress: Arc<watch::Sender<u64>>,
}

impl InputBudget {
    fn new(permits: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(permits)),
            progress: Arc::new(watch::channel(0).0),
        }
    }

    /// Room was given back.
    fn freed(&self) {
        self.progress
            .send_modify(|count| *count = count.wrapping_add(1));
    }
}

/// Input bytes that keep their share of the channel's and the connection's
/// budgets until the last copy of them is dropped, which is after they were
/// written to the target (or dropped with the channel).
struct HeldInput {
    data: Vec<u8>,
    channel: InputBudget,
    connection: InputBudget,
    _channel_permit: OwnedSemaphorePermit,
    _connection_permit: OwnedSemaphorePermit,
}

impl AsRef<[u8]> for HeldInput {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl Drop for HeldInput {
    fn drop(&mut self) {
        // Announced before the permits go back (they are dropped after this
        // returns): a waiter that sees the count move simply restarts its
        // clock and then takes the room as soon as it is there.
        self.channel.freed();
        self.connection.freed();
    }
}

/// The outcome of waiting for budget.
enum Acquired {
    Permit(OwnedSemaphorePermit),
    /// No room was given back for the whole stall timeout.
    Stalled,
}

/// Waits for `wanted` of the budget. Gives up only when no room at all has
/// been given back to the budget for `stall`: any room freed restarts the
/// clock, so a target that is slow but taking input is waited for however long
/// that takes. A zero `stall` waits forever.
async fn acquire_while_progressing(
    budget: &InputBudget,
    wanted: u32,
    stall: Duration,
) -> anyhow::Result<Acquired> {
    let mut progress = budget.progress.subscribe();
    let acquire = budget.semaphore.clone().acquire_many_owned(wanted);
    tokio::pin!(acquire);
    if stall.is_zero() {
        return Ok(Acquired::Permit(
            acquire.await.context("input budget closed")?,
        ));
    }
    let timer = tokio::time::sleep(stall);
    tokio::pin!(timer);
    loop {
        tokio::select! {
            biased;
            permit = &mut acquire => {
                return Ok(Acquired::Permit(permit.context("input budget closed")?));
            }
            // Cannot fail: the sender lives in `budget`, which is borrowed.
            Ok(()) = progress.changed() => {
                timer.as_mut().reset(tokio::time::Instant::now() + stall);
            }
            () = &mut timer => return Ok(Acquired::Stalled),
        }
    }
}

/// What came of waiting for room for some input.
enum Held {
    /// The input, which holds its room until its last copy is dropped.
    Input(Bytes),
    /// The target took none of the channel's (or, while waiting for the
    /// connection's room, none of the connection's) input for the stall timeout.
    Stalled,
}

/// Waits until both the channel's and the connection's budgets have room
/// for `data`, then returns it as bytes that hold that room until their last
/// copy is dropped. The channel's share is taken first; the stall timeout
/// applies to each wait on its own budget.
async fn hold_input(
    channel_budget: &InputBudget,
    connection_budget: &InputBudget,
    data: &[u8],
    stall: Duration,
) -> anyhow::Result<Held> {
    let wanted =
        u32::try_from(data.len().min(CHANNEL_INPUT_BUDGET)).context("channel input budget")?;
    let Acquired::Permit(channel_permit) =
        acquire_while_progressing(channel_budget, wanted, stall).await?
    else {
        return Ok(Held::Stalled);
    };
    let Acquired::Permit(connection_permit) =
        acquire_while_progressing(connection_budget, wanted, stall).await?
    else {
        return Ok(Held::Stalled);
    };
    Ok(Held::Input(Bytes::from_owner(HeldInput {
        data: data.to_vec(),
        channel: channel_budget.clone(),
        connection: connection_budget.clone(),
        _channel_permit: channel_permit,
        _connection_permit: connection_permit,
    })))
}

/// One channel's input state: its budget and a token that is cancelled once
/// the channel is closed, so input waiting for budget can stop waiting.
#[derive(Clone)]
struct ChannelInput {
    budget: InputBudget,
    closed: CancellationToken,
}

/// Every channel's input state on one connection. The handler waits on it
/// while the session, which learns of a channel closing from the target, ends
/// those waits through [`Self::target_closed`]. Channels are keyed by their
/// number. The map lives as long as the connection's handler and session, so
/// whatever entries remain are freed with them.
#[derive(Clone, Default)]
pub struct ChannelInputs(Arc<Mutex<HashMap<u32, ChannelInput>>>);

impl ChannelInputs {
    fn get(&self, channel: u32) -> ChannelInput {
        let mut inputs = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        inputs
            .entry(channel)
            .or_insert_with(|| ChannelInput {
                budget: InputBudget::new(CHANNEL_INPUT_BUDGET),
                closed: CancellationToken::new(),
            })
            .clone()
    }

    /// The target closed the channel: ends any input waiting on its budget
    /// and leaves the channel cancelled, so input the client still sends
    /// before its own close is dropped at once. The client's close
    /// ([`Self::close`]) removes the entry.
    ///
    /// This only cancels an entry that exists, and never creates one: the
    /// client's close may already have removed it (it runs in the handler
    /// before the session handles the same close), and an entry created now
    /// would outlive the channel. The entry exists whenever input has been
    /// held on the channel. The remaining gap is a channel that received no
    /// input before the target closed: input arriving after that finds no
    /// entry, so it waits as it did before, ending on the client's close or
    /// the wait limit.
    pub fn target_closed(&self, channel: u32) {
        let inputs = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(input) = inputs.get(&channel) {
            input.closed.cancel();
        }
    }

    /// A channel with this number was just opened: forgets any state left by
    /// an earlier channel of the same number, so the new one starts fresh.
    pub fn opened(&self, channel: u32) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&channel);
    }

    /// The client closed the channel: ends any input waiting on its budget
    /// and forgets the channel, whether or not the target closed it first.
    pub fn close(&self, channel: u32) {
        let removed = self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&channel);
        if let Some(input) = removed {
            input.closed.cancel();
        }
    }
}

/// Like [`hold_input`], but ends with `None` (dropping `data`) as soon as
/// `closed` is cancelled, releasing any share of the budgets already taken.
async fn hold_input_until_closed(
    channel_budget: &InputBudget,
    connection_budget: &InputBudget,
    data: &[u8],
    stall: Duration,
    closed: &CancellationToken,
) -> anyhow::Result<Option<Held>> {
    tokio::select! {
        biased;
        () = closed.cancelled() => Ok(None),
        held = hold_input(channel_budget, connection_budget, data, stall) => held.map(Some),
    }
}

/// A wait for room longer than this is logged.
const LONG_INPUT_WAIT: Duration = Duration::from_secs(1);

pub struct ServerHandler {
    pub event_tx: UnboundedSender<ServerHandlerEvent>,
    /// Optional custom banner shown to the client during authentication.
    pub banner: Option<String>,
    /// Per channel, the input budget still free (see [`CHANNEL_INPUT_BUDGET`]).
    pub channel_inputs: ChannelInputs,
    /// The whole connection's input budget still free (see [`CONNECTION_INPUT_BUDGET`]).
    connection_input_budget: InputBudget,
    /// How long a channel may go without the target taking any of its input
    /// before the channel is closed.
    pub channel_stall_timeout: Duration,
}

#[derive(thiserror::Error, Debug)]
pub enum ServerHandlerError {
    #[error("channel disconnected")]
    ChannelSend,
}

impl ServerHandler {
    pub fn new(
        event_tx: UnboundedSender<ServerHandlerEvent>,
        banner: Option<String>,
        channel_stall_timeout: Duration,
        channel_inputs: ChannelInputs,
    ) -> Self {
        Self {
            event_tx,
            banner,
            channel_inputs,
            connection_input_budget: InputBudget::new(CONNECTION_INPUT_BUDGET),
            channel_stall_timeout,
        }
    }

    /// Waits until the channel's and the connection's budgets have room for
    /// `data`, then returns it as bytes that hold that room until they are
    /// dropped. `None` means the input is dropped: the channel closed
    /// meanwhile, or the target took none of its input for the stall timeout,
    /// in which case the channel is closed here and the rest of the connection
    /// carries on.
    async fn hold_input(
        &mut self,
        channel: ChannelId,
        data: &[u8],
    ) -> anyhow::Result<Option<Bytes>> {
        let number = u32::from(channel);
        let input = self.channel_inputs.get(number);
        let started = std::time::Instant::now();
        let held = hold_input_until_closed(
            &input.budget,
            &self.connection_input_budget,
            data,
            self.channel_stall_timeout,
            &input.closed,
        )
        .await?;
        let waited = started.elapsed();
        if waited > LONG_INPUT_WAIT {
            info!(
                channel = number,
                waited_ms = u64::try_from(waited.as_millis()).unwrap_or(u64::MAX),
                stalled = matches!(held, Some(Held::Stalled)),
                "Input waited for the target to take earlier input"
            );
        }
        match held {
            Some(Held::Input(bytes)) => Ok(Some(bytes)),
            Some(Held::Stalled) => {
                self.close_stalled(channel).await?;
                Ok(None)
            }
            None => Ok(None),
        }
    }

    /// Closes only this channel: input still arriving for it is dropped at
    /// once from now on, and the session ends the channel at the target
    /// without waiting for the input queued before.
    async fn close_stalled(&mut self, channel: ChannelId) -> Result<(), ServerHandlerError> {
        self.channel_inputs.target_closed(u32::from(channel));
        let (tx, rx) = oneshot::channel();
        self.send_event(ServerHandlerEvent::ChannelStalled(
            ServerChannelId(channel),
            tx,
        ))?;
        let _ = rx.await;
        Ok(())
    }

    fn send_event(&self, event: ServerHandlerEvent) -> Result<(), ServerHandlerError> {
        self.event_tx
            .send(event)
            .map_err(|_| ServerHandlerError::ChannelSend)
    }
}

impl russh::server::Handler for ServerHandler {
    type Error = anyhow::Error;

    async fn authentication_banner(&mut self) -> Result<Option<String>, Self::Error> {
        Ok(self.banner.clone())
    }

    async fn auth_succeeded(&mut self, session: &mut Session) -> Result<(), Self::Error> {
        let handle = session.handle();
        self.send_event(ServerHandlerEvent::Authenticated(HandleWrapper(handle)))?;
        Ok(())
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channel_inputs.opened(u32::from(channel.id()));
        self.send_event(ServerHandlerEvent::ChannelOpenSession(
            ServerChannelId(channel.id()),
            ChannelOpenHandleWrapper(reply),
        ))?;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let name = name.to_string();
        let (tx, rx) = oneshot::channel();

        self.send_event(ServerHandlerEvent::SubsystemRequest(
            ServerChannelId(channel),
            name,
            tx,
        ))?;

        if rx.await.unwrap_or(false) {
            session.channel_success(channel)?;
        } else {
            session.channel_failure(channel)?;
        }

        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let term = term.to_string();
        let modes = modes
            .iter()
            .take_while(|x| (x.0 as u8) > 0 && (x.0 as u8) < 160)
            .map(Clone::clone)
            .collect();

        let (tx, rx) = oneshot::channel();

        self.send_event(ServerHandlerEvent::PtyRequest(
            ServerChannelId(channel),
            PtyRequest {
                term,
                col_width,
                row_height,
                pix_width,
                pix_height,
                modes,
            },
            tx,
        ))?;

        let _ = rx.await;
        session.channel_success(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let (tx, rx) = oneshot::channel();

        self.send_event(ServerHandlerEvent::ShellRequest(
            ServerChannelId(channel),
            tx,
        ))?;

        if rx.await.unwrap_or(false) {
            session.channel_success(channel)?;
        } else {
            session.channel_failure(channel)?;
        }

        Ok(())
    }

    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        offer: russh::server::PublicKeyOffer<'_>,
    ) -> Result<Auth, Self::Error> {
        let user = Secret::new(user.to_string());
        let (tx, rx) = oneshot::channel();

        self.send_event(ServerHandlerEvent::AuthPublicKeyOffer(
            user,
            offer.public_key.clone(),
            tx,
        ))?;

        Ok(rx.await.unwrap_or_else(|_| Auth::reject()))
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: russh::server::VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        let user = Secret::new(user.to_string());
        let (tx, rx) = oneshot::channel();

        self.send_event(ServerHandlerEvent::AuthPublicKey(
            user,
            key.public_key.clone(),
            tx,
        ))?;

        let result = rx.await.unwrap_or(Auth::UnsupportedMethod);
        Ok(result)
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        let user = Secret::new(user.to_string());
        let password = Secret::new(password.to_string());

        let (tx, rx) = oneshot::channel();

        self.send_event(ServerHandlerEvent::AuthPassword(user, password, tx))?;

        let result = rx.await.unwrap_or(Auth::UnsupportedMethod);
        Ok(result)
    }

    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        user: &str,
        _submethods: &str,
        response: Option<russh::server::Response<'a>>,
    ) -> Result<Auth, Self::Error> {
        let user = Secret::new(user.to_string());
        let response = response
            .map(|response| {
                response
                    .filter_map(|b| String::from_utf8(b.to_vec()).ok())
                    .map(Secret::new)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let (tx, rx) = oneshot::channel();

        self.send_event(ServerHandlerEvent::AuthKeyboardInteractive(
            user, response, tx,
        ))?;

        let result = rx.await.unwrap_or(Auth::UnsupportedMethod);
        Ok(result)
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(data) = self.hold_input(channel, data).await? else {
            return Ok(());
        };
        let channel = ServerChannelId(channel);

        let (tx, rx) = oneshot::channel();

        self.send_event(ServerHandlerEvent::Data(channel, data, tx))?;

        let _ = rx.await;
        Ok(())
    }

    async fn extended_data(
        &mut self,
        channel: ChannelId,
        code: u32,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(data) = self.hold_input(channel, data).await? else {
            return Ok(());
        };
        let channel = ServerChannelId(channel);
        let (tx, rx) = oneshot::channel();

        self.send_event(ServerHandlerEvent::ExtendedData(channel, data, code, tx))?;
        let _ = rx.await;
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channel_inputs.close(u32::from(channel));
        let channel = ServerChannelId(channel);
        let (tx, rx) = oneshot::channel();
        self.send_event(ServerHandlerEvent::ChannelClose(channel, tx))?;
        let _ = rx.await;
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let (tx, rx) = oneshot::channel();
        self.send_event(ServerHandlerEvent::WindowChangeRequest(
            ServerChannelId(channel),
            PtyRequest {
                term: "".into(),
                col_width,
                row_height,
                pix_width,
                pix_height,
                modes: vec![],
            },
            tx,
        ))?;
        let _ = rx.await;
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let channel = ServerChannelId(channel);
        let (tx, rx) = oneshot::channel();

        self.event_tx
            .send(ServerHandlerEvent::ChannelEof(channel, tx))
            .map_err(|_| ServerHandlerError::ChannelSend)?;

        let _ = rx.await;
        Ok(())
    }

    async fn signal(
        &mut self,
        channel: ChannelId,
        signal_name: russh::Sig,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let (tx, rx) = oneshot::channel();
        self.send_event(ServerHandlerEvent::Signal(
            ServerChannelId(channel),
            signal_name,
            tx,
        ))?;
        let _ = rx.await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let data = Bytes::from(data.to_vec());
        let (tx, rx) = oneshot::channel();
        self.send_event(ServerHandlerEvent::ExecRequest(
            ServerChannelId(channel),
            data,
            tx,
        ))?;

        if rx.await.unwrap_or(false) {
            session.channel_success(channel)?;
        } else {
            session.channel_failure(channel)?;
        }

        Ok(())
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let variable_name = variable_name.to_string();
        let variable_value = variable_value.to_string();
        let (tx, rx) = oneshot::channel();
        self.send_event(ServerHandlerEvent::EnvRequest(
            ServerChannelId(channel),
            variable_name,
            variable_value,
            tx,
        ))?;
        let _ = rx.await;
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let host_to_connect = host_to_connect.to_string();
        let originator_address = originator_address.to_string();
        self.channel_inputs.opened(u32::from(channel.id()));
        self.send_event(ServerHandlerEvent::ChannelOpenDirectTcpIp(
            ServerChannelId(channel.id()),
            DirectTCPIPParams {
                host_to_connect,
                port_to_connect,
                originator_address,
                originator_port,
            },
            ChannelOpenHandleWrapper(reply),
        ))?;
        Ok(())
    }

    async fn channel_open_direct_streamlocal(
        &mut self,
        channel: Channel<Msg>,
        socket_path: &str,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let socket_path = socket_path.to_string();
        self.channel_inputs.opened(u32::from(channel.id()));
        self.send_event(ServerHandlerEvent::ChannelOpenDirectStreamlocal(
            ServerChannelId(channel.id()),
            socket_path,
            ChannelOpenHandleWrapper(reply),
        ))?;
        Ok(())
    }

    async fn x11_request(
        &mut self,
        channel: ChannelId,
        single_conection: bool,
        x11_auth_protocol: &str,
        x11_auth_cookie: &str,
        x11_screen_number: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let x11_auth_protocol = x11_auth_protocol.to_string();
        let x11_auth_cookie = x11_auth_cookie.to_string();
        let (tx, rx) = oneshot::channel();
        self.send_event(ServerHandlerEvent::X11Request(
            ServerChannelId(channel),
            X11Request {
                single_conection,
                x11_auth_protocol,
                x11_auth_cookie,
                x11_screen_number,
            },
            tx,
        ))?;
        let _ = rx.await;
        Ok(())
    }

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let address = address.to_string();
        let port = *port;
        let (tx, rx) = oneshot::channel();
        self.send_event(ServerHandlerEvent::TcpIpForward(address, port, tx))?;
        let allowed = rx.await.unwrap_or(false);
        if allowed {
            session.request_success();
        } else {
            session.request_failure();
        }
        Ok(allowed)
    }

    async fn cancel_tcpip_forward(
        &mut self,
        address: &str,
        port: u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let address = address.to_string();
        let (tx, rx) = oneshot::channel();
        self.send_event(ServerHandlerEvent::CancelTcpIpForward(address, port, tx))?;
        let allowed = rx.await.unwrap_or(false);
        if allowed {
            session.request_success();
        } else {
            session.request_failure();
        }
        Ok(allowed)
    }

    async fn streamlocal_forward(
        &mut self,
        socket_path: &str,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let socket_path = socket_path.to_string();
        let (tx, rx) = oneshot::channel();
        self.send_event(ServerHandlerEvent::StreamlocalForward(socket_path, tx))?;
        let allowed = rx.await.unwrap_or(false);
        if allowed {
            session.request_success();
        } else {
            session.request_failure();
        }
        Ok(allowed)
    }

    async fn cancel_streamlocal_forward(
        &mut self,
        socket_path: &str,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let socket_path = socket_path.to_string();
        let (tx, rx) = oneshot::channel();
        self.send_event(ServerHandlerEvent::CancelStreamlocalForward(
            socket_path,
            tx,
        ))?;
        let allowed = rx.await.unwrap_or(false);
        if allowed {
            session.request_success();
        } else {
            session.request_failure();
        }
        Ok(allowed)
    }

    async fn agent_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let (tx, rx) = oneshot::channel();
        self.send_event(ServerHandlerEvent::AgentForward(
            ServerChannelId(channel),
            tx,
        ))?;
        let allowed = rx.await.unwrap_or(false);
        if allowed {
            session.request_success();
        } else {
            session.request_failure();
        }
        Ok(allowed)
    }
}

impl Drop for ServerHandler {
    fn drop(&mut self) {
        debug!("Dropped");
        let _ = self.event_tx.send(ServerHandlerEvent::Disconnect);
    }
}

impl Debug for ServerHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ServerHandler")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WAIT: Duration = Duration::from_millis(200);

    fn connection() -> InputBudget {
        InputBudget::new(CONNECTION_INPUT_BUDGET)
    }

    fn channel() -> InputBudget {
        InputBudget::new(CHANNEL_INPUT_BUDGET)
    }

    fn available(budget: &InputBudget) -> usize {
        budget.semaphore.available_permits()
    }

    /// The held input, failing the test if the wait stalled instead.
    fn input(held: Held) -> Bytes {
        match held {
            Held::Input(bytes) => bytes,
            Held::Stalled => panic!("the wait stalled"),
        }
    }

    fn stalled(held: &Held) -> bool {
        matches!(held, Held::Stalled)
    }

    /// Input up to the budget goes straight through; past it the next input
    /// waits until earlier input is dropped (written to the target), and it
    /// gets the same bytes either way.
    #[tokio::test]
    async fn channel_input_past_its_budget_waits_for_the_target() {
        let budget = channel();
        let first = input(
            hold_input(&budget, &connection(), &vec![1; CHANNEL_INPUT_BUDGET], WAIT)
                .await
                .unwrap(),
        );
        assert_eq!(available(&budget), 0);

        let next = tokio::spawn({
            let budget = budget.clone();
            async move { hold_input(&budget, &connection(), b"more", Duration::from_secs(5)).await }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!next.is_finished(), "input past the budget must wait");

        let copy = first.clone();
        drop(first);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !next.is_finished(),
            "a copy still being written keeps its share"
        );

        drop(copy);
        let next = input(next.await.unwrap().unwrap());
        assert_eq!(&next[..], b"more");
        drop(next);
        assert_eq!(available(&budget), CHANNEL_INPUT_BUDGET);
    }

    /// Input that the target never takes is reported as stalled after the
    /// stall timeout, instead of holding the connection for ever, and takes
    /// no share of the budget.
    #[tokio::test]
    async fn channel_input_stalls_when_the_target_never_takes_it() {
        let budget = channel();
        let _held = hold_input(&budget, &connection(), &vec![0; CHANNEL_INPUT_BUDGET], WAIT)
            .await
            .unwrap();
        let started = std::time::Instant::now();
        let held = hold_input(&budget, &connection(), b"x", WAIT)
            .await
            .unwrap();
        assert!(stalled(&held));
        assert!(started.elapsed() >= WAIT, "it waited the whole timeout");
        assert_eq!(available(&budget), 0, "a stalled wait keeps no share");
    }

    /// The clock measures time without progress, not total time: while room
    /// keeps being given back the wait goes on, far past the stall timeout,
    /// and ends with the input once there is enough room.
    #[tokio::test]
    async fn a_slow_target_that_keeps_taking_input_is_never_stalled() {
        let budget = channel();
        let piece = CHANNEL_INPUT_BUDGET / 4;
        let mut pieces = Vec::new();
        for _ in 0..4 {
            pieces.push(input(
                hold_input(&budget, &connection(), &vec![0; piece], WAIT)
                    .await
                    .unwrap(),
            ));
        }
        assert_eq!(available(&budget), 0);

        let waiting = tokio::spawn({
            let budget = budget.clone();
            async move { hold_input(&budget, &connection(), &vec![1; CHANNEL_INPUT_BUDGET], WAIT).await }
        });
        // Each piece is taken well inside the timeout; all four together take
        // more than twice as long as it.
        for piece in pieces {
            tokio::time::sleep(WAIT / 2).await;
            assert!(!waiting.is_finished());
            drop(piece);
        }
        let held = waiting.await.unwrap().unwrap();
        assert!(!stalled(&held), "progress must restart the clock");
    }

    /// The same wait does stall once the progress stops.
    #[tokio::test]
    async fn the_wait_stalls_once_the_target_stops_taking_input() {
        let budget = channel();
        let piece = CHANNEL_INPUT_BUDGET / 2;
        let first = input(
            hold_input(&budget, &connection(), &vec![0; piece], WAIT)
                .await
                .unwrap(),
        );
        let _second = input(
            hold_input(&budget, &connection(), &vec![0; piece], WAIT)
                .await
                .unwrap(),
        );

        let waiting = tokio::spawn({
            let budget = budget.clone();
            async move { hold_input(&budget, &connection(), &vec![1; CHANNEL_INPUT_BUDGET], WAIT).await }
        });
        // One piece is taken, which is progress, but the second never is.
        tokio::time::sleep(WAIT / 2).await;
        drop(first);
        let held = tokio::time::timeout(Duration::from_secs(5), waiting)
            .await
            .expect("the wait must end")
            .unwrap()
            .unwrap();
        assert!(stalled(&held));
    }

    /// A zero stall timeout means no limit: the wait goes on until there is room.
    #[tokio::test]
    async fn a_zero_stall_timeout_waits_for_ever() {
        let budget = channel();
        let held = input(
            hold_input(
                &budget,
                &connection(),
                &vec![0; CHANNEL_INPUT_BUDGET],
                Duration::ZERO,
            )
            .await
            .unwrap(),
        );
        let waiting = tokio::spawn({
            let budget = budget.clone();
            async move { hold_input(&budget, &connection(), b"x", Duration::ZERO).await }
        });
        tokio::time::sleep(WAIT * 2).await;
        assert!(!waiting.is_finished());
        drop(held);
        assert!(!stalled(&waiting.await.unwrap().unwrap()));
    }

    /// One packet larger than the whole budget still goes through on an
    /// idle channel rather than waiting for ever.
    #[tokio::test]
    async fn channel_input_larger_than_the_budget_still_passes() {
        let big = vec![7; CHANNEL_INPUT_BUDGET + 1];
        let held = input(
            hold_input(&channel(), &connection(), &big, WAIT)
                .await
                .unwrap(),
        );
        assert_eq!(held.len(), big.len());
    }

    /// Input spread over many channels, each under its own budget, still
    /// stops at the connection's budget: the channel that would go past it
    /// waits, and goes through once earlier input has been written.
    #[tokio::test]
    async fn input_over_many_channels_stops_at_the_connection_budget() {
        let connection = connection();
        let per_channel = CHANNEL_INPUT_BUDGET - 1;
        let fits = CONNECTION_INPUT_BUDGET / per_channel;
        let mut held = Vec::new();
        for _ in 0..fits {
            held.push(input(
                hold_input(&channel(), &connection, &vec![3; per_channel], WAIT)
                    .await
                    .unwrap(),
            ));
        }
        assert!(available(&connection) < per_channel);

        let one_more = tokio::spawn({
            let connection = connection.clone();
            async move {
                hold_input(
                    &channel(),
                    &connection,
                    &vec![4; per_channel],
                    Duration::from_secs(5),
                )
                .await
            }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !one_more.is_finished(),
            "a further channel must wait for the connection's budget"
        );

        held.clear();
        let late = input(one_more.await.unwrap().unwrap());
        assert_eq!(late.len(), per_channel);
        drop(late);
        assert_eq!(available(&connection), CONNECTION_INPUT_BUDGET);
    }

    /// The connection's budget alone also stalls a wait that never gets room.
    #[tokio::test]
    async fn input_stalls_when_the_connection_budget_never_frees() {
        let connection = InputBudget::new(CHANNEL_INPUT_BUDGET);
        let _held = hold_input(
            &channel(),
            &connection,
            &vec![0; CHANNEL_INPUT_BUDGET],
            WAIT,
        )
        .await
        .unwrap();
        let other_channel = channel();
        let held = hold_input(&other_channel, &connection, b"x", WAIT)
            .await
            .unwrap();
        assert!(stalled(&held));
        assert_eq!(
            available(&other_channel),
            CHANNEL_INPUT_BUDGET,
            "a wait that gave up keeps no share of the channel's budget"
        );
    }

    /// Input waiting on a full budget stops waiting, and is dropped, as soon
    /// as its channel closes, long before the stall timeout.
    #[tokio::test]
    async fn channel_input_waiting_for_budget_ends_when_the_channel_closes() {
        let inputs = ChannelInputs::default();
        let channel_number = 1;
        let channel_input = inputs.get(channel_number);
        let _held = hold_input(
            &channel_input.budget,
            &connection(),
            &vec![0; CHANNEL_INPUT_BUDGET],
            WAIT,
        )
        .await
        .unwrap();

        let waiting = tokio::spawn({
            let channel_input = channel_input.clone();
            async move {
                hold_input_until_closed(
                    &channel_input.budget,
                    &connection(),
                    b"more",
                    Duration::from_secs(30),
                    &channel_input.closed,
                )
                .await
            }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!waiting.is_finished(), "input past the budget must wait");

        inputs.close(channel_number);
        let ended = tokio::time::timeout(Duration::from_secs(5), waiting)
            .await
            .expect("a closed channel must end the wait")
            .unwrap()
            .unwrap();
        assert!(ended.is_none());
    }

    /// A wait that ends because its channel closed gives back the shares of
    /// the budgets it had already taken, so the connection's other channels
    /// are not held up by it.
    #[tokio::test]
    async fn closing_a_channel_releases_the_budget_its_waiting_input_took() {
        let inputs = ChannelInputs::default();
        let connection = InputBudget::new(CHANNEL_INPUT_BUDGET);
        let hog = hold_input(
            &channel(),
            &connection,
            &vec![0; CHANNEL_INPUT_BUDGET],
            WAIT,
        )
        .await
        .unwrap();

        // Holds the closing channel's own share, then waits for the
        // connection's.
        let closing = 1;
        let closing_input = inputs.get(closing);
        let waiting = tokio::spawn({
            let closing_input = closing_input.clone();
            let connection = connection.clone();
            async move {
                hold_input_until_closed(
                    &closing_input.budget,
                    &connection,
                    b"more",
                    Duration::from_secs(30),
                    &closing_input.closed,
                )
                .await
            }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!waiting.is_finished());

        inputs.close(closing);
        assert!(waiting.await.unwrap().unwrap().is_none());
        assert_eq!(available(&closing_input.budget), CHANNEL_INPUT_BUDGET);

        drop(hog);
        let other = inputs.get(2);
        let passed = hold_input_until_closed(
            &other.budget,
            &connection,
            &vec![5; CHANNEL_INPUT_BUDGET],
            WAIT,
            &other.closed,
        )
        .await
        .unwrap();
        assert!(
            matches!(passed, Some(Held::Input(_))),
            "another channel must not stay blocked"
        );
    }

    /// Input that arrives after the target closed the channel but before the
    /// client's own close finds the channel already cancelled: it is dropped
    /// at once, without waiting and without taking any budget.
    #[tokio::test]
    async fn input_after_the_target_closed_is_dropped_at_once() {
        let inputs = ChannelInputs::default();
        let channel_number = 1;
        let _held = hold_input(
            &inputs.get(channel_number).budget,
            &connection(),
            &vec![0; CHANNEL_INPUT_BUDGET],
            WAIT,
        )
        .await
        .unwrap();
        inputs.target_closed(channel_number);

        let channel_input = inputs.get(channel_number);
        let connection = connection();
        let dropped = tokio::time::timeout(
            Duration::from_secs(5),
            hold_input_until_closed(
                &channel_input.budget,
                &connection,
                b"late",
                Duration::from_secs(30),
                &channel_input.closed,
            ),
        )
        .await
        .expect("input after the target's close must not wait")
        .unwrap();
        assert!(dropped.is_none());
        assert_eq!(available(&channel_input.budget), 0, "nothing more is taken");
        assert_eq!(available(&connection), CONNECTION_INPUT_BUDGET);
    }

    /// The target's close leaves a cancelled entry only until the client
    /// closes too; a channel number used again afterwards starts fresh.
    #[tokio::test]
    async fn the_clients_close_removes_what_the_targets_close_left() {
        let inputs = ChannelInputs::default();
        let channel = 1;
        inputs.get(channel);
        inputs.target_closed(channel);
        assert!(inputs.get(channel).closed.is_cancelled());

        inputs.close(channel);
        assert!(inputs.0.lock().unwrap().is_empty());
        let fresh = inputs.get(channel);
        assert!(!fresh.closed.is_cancelled());
        assert_eq!(available(&fresh.budget), CHANNEL_INPUT_BUDGET);
    }

    /// The client's close can run before the session handles the target's
    /// close of the same channel; that must not bring the entry back.
    #[tokio::test]
    async fn the_targets_close_after_the_clients_close_leaves_no_entry() {
        let inputs = ChannelInputs::default();
        let channel = 1;
        inputs.get(channel);
        inputs.close(channel);
        inputs.target_closed(channel);
        assert!(inputs.0.lock().unwrap().is_empty());
    }

    /// A channel opened with the number of an earlier, target-closed one
    /// starts with an uncancelled entry and a full budget.
    #[tokio::test]
    async fn a_channel_opened_with_a_reused_number_starts_fresh() {
        let inputs = ChannelInputs::default();
        let channel = 1;
        inputs.get(channel);
        inputs.target_closed(channel);

        inputs.opened(channel);
        let fresh = inputs.get(channel);
        assert!(!fresh.closed.is_cancelled());
        assert_eq!(available(&fresh.budget), CHANNEL_INPUT_BUDGET);
    }

    /// A close for a channel with no entry must not panic or leave one.
    #[tokio::test]
    async fn closing_an_unknown_channel_is_harmless() {
        let inputs = ChannelInputs::default();
        inputs.close(7);
        inputs.target_closed(7);
        inputs.opened(7);
        assert!(inputs.0.lock().unwrap().is_empty());
    }

    /// Closing one channel leaves the others' waits alone, and a channel
    /// that is used again afterwards starts with a fresh budget.
    #[tokio::test]
    async fn closing_a_channel_does_not_touch_other_channels() {
        let inputs = ChannelInputs::default();
        let (one, two) = (1, 2);
        let first = inputs.get(one);
        let second = inputs.get(two);

        inputs.close(one);
        assert!(first.closed.is_cancelled());
        assert!(!second.closed.is_cancelled());
        assert!(!inputs.get(one).closed.is_cancelled());
    }
}
