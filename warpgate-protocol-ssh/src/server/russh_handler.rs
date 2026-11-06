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
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};
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

/// How much of one channel's input may be on its way to the target before
/// that channel's receive window is held back (not replenished). A client
/// that follows the window stops sending on that channel only; the rest of
/// the connection is still read. Strictly below russh's default window
/// ([`CHANNEL_WINDOW`], which this server does not change), so the hold
/// starts before the window would be replenished once more. A channel then
/// holds at most this plus the window it had left, about 3 MiB.
pub const CHANNEL_INPUT_BUDGET: usize = 1024 * 1024;

/// Once a held channel is down to this much input, its window is released.
const CHANNEL_INPUT_RESUME: usize = CHANNEL_INPUT_BUDGET / 2;

/// russh's default receive window per channel (`Config::window_size`).
const CHANNEL_WINDOW: usize = 2 * 1024 * 1024;
const _: () = assert!(CHANNEL_INPUT_BUDGET < CHANNEL_WINDOW);

/// How much input all of one connection's channels together may have on its
/// way to targets at once. This is the hard cap: past it Warpgate stops
/// reading the connection until the target has taken earlier input, so held
/// input per connection stays within it however many channels are open and
/// whether or not the client follows the window.
pub const CONNECTION_INPUT_BUDGET: usize = 16 * 1024 * 1024;

/// Holds (`true`) or releases (`false`) one channel's receive window. Never
/// waits: it goes through the session's priority queue, and fails only once
/// the session is gone.
type WindowHold = Box<dyn Fn(bool) + Send>;

fn window_hold(handle: Handle, channel: ChannelId) -> WindowHold {
    Box::new(move |hold| {
        let _ = handle.hold_window(channel, hold);
    })
}

/// One channel's input not yet written to its target, and its window hold.
#[derive(Default)]
struct ChannelBudget(Mutex<BudgetState>);

#[derive(Default)]
struct BudgetState {
    held: usize,
    /// Set while the channel's window is held back.
    hold: Option<WindowHold>,
}

impl ChannelBudget {
    fn lock(&self) -> std::sync::MutexGuard<'_, BudgetState> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Counts `len` more bytes; at the budget, holds the channel's window.
    fn add(&self, len: usize, window: impl FnOnce() -> WindowHold) {
        let mut state = self.lock();
        state.held += len;
        if state.held >= CHANNEL_INPUT_BUDGET && state.hold.is_none() {
            let hold = window();
            hold(true);
            state.hold = Some(hold);
        }
    }

    /// `len` bytes were written to the target: releases a held window once
    /// the channel is down to the resume level.
    fn sub(&self, len: usize) {
        let mut state = self.lock();
        state.held = state.held.saturating_sub(len);
        if state.held <= CHANNEL_INPUT_RESUME {
            Self::release_locked(&mut state);
        }
    }

    fn release(&self) {
        Self::release_locked(&mut self.lock());
    }

    fn release_locked(state: &mut BudgetState) {
        if let Some(hold) = state.hold.take() {
            hold(false);
        }
    }
}

/// Input bytes that count towards the channel's budget and keep their share
/// of the connection's until the last copy of them is dropped, which is after
/// they were written to the target.
struct HeldInput {
    data: Vec<u8>,
    channel: Arc<ChannelBudget>,
    _connection_permit: OwnedSemaphorePermit,
}

impl Drop for HeldInput {
    fn drop(&mut self) {
        self.channel.sub(self.data.len());
    }
}

impl AsRef<[u8]> for HeldInput {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

/// Waits until the connection's budget has room for `data` (the hard cap),
/// then counts it against the channel and returns it as bytes that hold that
/// room until their last copy is dropped. The channel's budget never makes
/// this wait: a channel at it has its window held back through `window`
/// instead, and only the channel's own client is slowed.
async fn hold_input(
    channel_budget: Arc<ChannelBudget>,
    connection_budget: Arc<Semaphore>,
    data: &[u8],
    wait_limit: Duration,
    window: impl FnOnce() -> WindowHold,
) -> anyhow::Result<Bytes> {
    let wanted = u32::try_from(data.len().min(CONNECTION_INPUT_BUDGET))
        .context("connection input budget")?;
    let connection_permit =
        tokio::time::timeout(wait_limit, connection_budget.acquire_many_owned(wanted))
            .await
            .context("the target did not take the input in time")?
            .context("input budget closed")?;
    channel_budget.add(data.len(), window);
    Ok(Bytes::from_owner(HeldInput {
        data: data.to_vec(),
        channel: channel_budget,
        _connection_permit: connection_permit,
    }))
}

/// One channel's input state: its budget and a token that is cancelled once
/// the channel is closed, so input waiting for budget can stop waiting.
#[derive(Clone)]
struct ChannelInput {
    budget: Arc<ChannelBudget>,
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
                budget: Arc::default(),
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
            input.budget.release();
        }
    }

    /// A channel with this number was just opened: forgets any state left by
    /// an earlier channel of the same number, so the new one starts fresh.
    pub fn opened(&self, channel: u32) {
        self.forget(channel);
    }

    /// Forgets the channel and ends its window hold, so a held window does
    /// not outlive the channel in the session.
    fn forget(&self, channel: u32) -> Option<ChannelInput> {
        let removed = self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&channel);
        if let Some(input) = &removed {
            input.budget.release();
        }
        removed
    }

    /// The client closed the channel: ends any input waiting on its budget
    /// and forgets the channel, whether or not the target closed it first.
    pub fn close(&self, channel: u32) {
        if let Some(input) = self.forget(channel) {
            input.closed.cancel();
        }
    }
}

/// Like [`hold_input`], but ends with `None` (dropping `data`) as soon as
/// `closed` is cancelled, releasing any share of the budgets already taken.
async fn hold_input_until_closed(
    channel_budget: Arc<ChannelBudget>,
    connection_budget: Arc<Semaphore>,
    data: &[u8],
    wait_limit: Duration,
    closed: &CancellationToken,
    window: impl FnOnce() -> WindowHold,
) -> anyhow::Result<Option<Bytes>> {
    tokio::select! {
        biased;
        () = closed.cancelled() => Ok(None),
        held = hold_input(channel_budget, connection_budget, data, wait_limit, window) => {
            held.map(Some)
        }
    }
}

pub struct ServerHandler {
    pub event_tx: UnboundedSender<ServerHandlerEvent>,
    /// Optional custom banner shown to the client during authentication.
    pub banner: Option<String>,
    /// Per channel, the input budget still free (see [`CHANNEL_INPUT_BUDGET`]).
    pub channel_inputs: ChannelInputs,
    /// The whole connection's input budget still free (see [`CONNECTION_INPUT_BUDGET`]).
    pub connection_input_budget: Arc<Semaphore>,
    /// How long input may wait for budget before the connection is dropped.
    pub input_wait_limit: Duration,
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
        input_wait_limit: Duration,
        channel_inputs: ChannelInputs,
    ) -> Self {
        Self {
            event_tx,
            banner,
            channel_inputs,
            connection_input_budget: Arc::new(Semaphore::new(CONNECTION_INPUT_BUDGET)),
            input_wait_limit,
        }
    }

    /// Waits until the channel's and the connection's budgets have room for
    /// `data`, then returns it as bytes that hold that room until they are
    /// dropped. `None` means the channel closed meanwhile and `data` is dropped.
    async fn hold_input(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        handle: &Handle,
    ) -> anyhow::Result<Option<Bytes>> {
        let input = self.channel_inputs.get(u32::from(channel));
        hold_input_until_closed(
            input.budget,
            self.connection_input_budget.clone(),
            data,
            self.input_wait_limit,
            &input.closed,
            || window_hold(handle.clone(), channel),
        )
        .await
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
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(data) = self.hold_input(channel, data, &session.handle()).await? else {
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
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(data) = self.hold_input(channel, data, &session.handle()).await? else {
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

    fn connection() -> Arc<Semaphore> {
        Arc::new(Semaphore::new(CONNECTION_INPUT_BUDGET))
    }

    /// Records the holds (`true`) and releases (`false`) asked of a channel's
    /// window.
    #[derive(Clone, Default)]
    struct Window(Arc<Mutex<Vec<bool>>>);

    impl Window {
        fn calls(&self) -> Vec<bool> {
            self.0.lock().unwrap().clone()
        }

        fn hold(&self) -> impl FnOnce() -> WindowHold + use<> {
            let calls = self.0.clone();
            move || Box::new(move |hold| calls.lock().unwrap().push(hold))
        }
    }

    async fn take(
        budget: &Arc<ChannelBudget>,
        connection: &Arc<Semaphore>,
        len: usize,
        window: &Window,
    ) -> Bytes {
        hold_input(
            budget.clone(),
            connection.clone(),
            &vec![1; len],
            WAIT,
            window.hold(),
        )
        .await
        .unwrap()
    }

    fn held(budget: &ChannelBudget) -> usize {
        budget.lock().held
    }

    /// Input below the budget leaves the window alone; reaching the budget
    /// holds it, once; and it is released when the target has taken enough
    /// to be down to the resume level, not before.
    #[tokio::test]
    async fn a_channel_at_its_budget_has_its_window_held_until_the_target_catches_up() {
        let budget = Arc::new(ChannelBudget::default());
        let (connection, window) = (connection(), Window::default());
        let first = take(&budget, &connection, CHANNEL_INPUT_BUDGET - 1, &window).await;
        assert!(window.calls().is_empty());

        let second = take(&budget, &connection, 1, &window).await;
        let third = take(&budget, &connection, 100, &window).await;
        assert_eq!(window.calls(), vec![true], "held once, not per packet");

        drop(first);
        assert_eq!(window.calls(), vec![true, false]);
        assert_eq!(held(&budget), 101);
        drop((second, third));
        assert_eq!(window.calls(), vec![true, false], "released once");
    }

    /// A copy still being written keeps its share, and the window stays held
    /// above the resume level.
    #[tokio::test]
    async fn the_window_stays_held_above_the_resume_level() {
        let budget = Arc::new(ChannelBudget::default());
        let (connection, window) = (connection(), Window::default());
        let parts: Vec<_> = futures::future::join_all(
            (0..4).map(|_| take(&budget, &connection, CHANNEL_INPUT_BUDGET / 4, &window)),
        )
        .await;
        assert_eq!(window.calls(), vec![true]);
        let mut parts = parts.into_iter();
        let copy = parts.next().unwrap().clone();
        // The first part's original is gone but its copy still counts.
        assert_eq!(held(&budget), CHANNEL_INPUT_BUDGET);
        drop(parts.next());
        assert_eq!(window.calls(), vec![true], "still above the resume level");
        drop(parts.next());
        assert_eq!(window.calls(), vec![true, false]);
        drop((copy, parts));
        assert_eq!(held(&budget), 0);
    }

    /// One channel over its budget does not make another channel wait or hold.
    #[tokio::test]
    async fn one_channel_over_budget_leaves_the_others_alone() {
        let connection = connection();
        let (stuck, stuck_window) = (Arc::new(ChannelBudget::default()), Window::default());
        let _held = take(&stuck, &connection, CHANNEL_INPUT_BUDGET, &stuck_window).await;
        assert_eq!(stuck_window.calls(), vec![true]);

        let (other, other_window) = (Arc::new(ChannelBudget::default()), Window::default());
        let passed = take(&other, &connection, 4096, &other_window).await;
        assert_eq!(passed.len(), 4096);
        assert!(other_window.calls().is_empty());
    }

    /// One packet larger than the whole budget still goes through on an
    /// idle channel rather than waiting for ever, and holds its window.
    #[tokio::test]
    async fn channel_input_larger_than_the_budget_still_passes() {
        let budget = Arc::new(ChannelBudget::default());
        let window = Window::default();
        let held = take(&budget, &connection(), CHANNEL_INPUT_BUDGET + 1, &window).await;
        assert_eq!(held.len(), CHANNEL_INPUT_BUDGET + 1);
        assert_eq!(window.calls(), vec![true]);
    }

    /// Input spread over many channels, each under its own budget, still
    /// stops at the connection's budget (the hard cap): the channel that
    /// would go past it waits, and goes through once earlier input has been
    /// written.
    #[tokio::test]
    async fn input_over_many_channels_stops_at_the_connection_budget() {
        let connection = connection();
        let per_channel = CHANNEL_INPUT_BUDGET - 1;
        let fits = CONNECTION_INPUT_BUDGET / per_channel;
        let mut held = Vec::new();
        for _ in 0..fits {
            let budget = Arc::new(ChannelBudget::default());
            held.push(take(&budget, &connection, per_channel, &Window::default()).await);
        }
        assert!(connection.available_permits() < per_channel);

        let one_more = tokio::spawn({
            let connection = connection.clone();
            async move {
                hold_input(
                    Arc::new(ChannelBudget::default()),
                    connection,
                    &vec![4; per_channel],
                    Duration::from_secs(5),
                    Window::default().hold(),
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
        let late = one_more.await.unwrap().unwrap();
        assert_eq!(late.len(), per_channel);
        drop(late);
        assert_eq!(connection.available_permits(), CONNECTION_INPUT_BUDGET);
    }

    /// Input that never gets room under the connection's budget ends the
    /// wait with an error instead of holding the connection for ever, and
    /// counts nothing against its channel.
    #[tokio::test]
    async fn input_gives_up_when_the_connection_budget_never_frees() {
        let connection = Arc::new(Semaphore::new(CHANNEL_INPUT_BUDGET));
        let _held = take(
            &Arc::new(ChannelBudget::default()),
            &connection,
            CHANNEL_INPUT_BUDGET,
            &Window::default(),
        )
        .await;
        let budget = Arc::new(ChannelBudget::default());
        assert!(
            hold_input(
                budget.clone(),
                connection,
                b"x",
                WAIT,
                Window::default().hold()
            )
            .await
            .is_err()
        );
        assert_eq!(held(&budget), 0);
    }

    /// Input waiting on the connection's full budget stops waiting, and is
    /// dropped, as soon as its channel closes, long before the wait limit.
    #[tokio::test]
    async fn channel_input_waiting_for_budget_ends_when_the_channel_closes() {
        let inputs = ChannelInputs::default();
        let channel = 1;
        let connection = Arc::new(Semaphore::new(1));
        let _hog = take(
            &Arc::new(ChannelBudget::default()),
            &connection,
            1,
            &Window::default(),
        )
        .await;

        let input = inputs.get(channel);
        let waiting = tokio::spawn({
            let input = input.clone();
            async move {
                hold_input_until_closed(
                    input.budget,
                    connection,
                    b"more",
                    Duration::from_secs(30),
                    &input.closed,
                    Window::default().hold(),
                )
                .await
            }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!waiting.is_finished(), "input past the budget must wait");

        inputs.close(channel);
        let ended = tokio::time::timeout(Duration::from_secs(5), waiting)
            .await
            .expect("a closed channel must end the wait")
            .unwrap()
            .unwrap();
        assert!(ended.is_none());
        assert_eq!(held(&input.budget), 0);
    }

    /// Input that arrives after the target closed the channel but before the
    /// client's own close finds the channel already cancelled: it is dropped
    /// at once, without waiting and without taking any budget. The target's
    /// close also releases a held window, so input still on its way is not
    /// left unsent.
    #[tokio::test]
    async fn input_after_the_target_closed_is_dropped_at_once() {
        let inputs = ChannelInputs::default();
        let channel = 1;
        let input = inputs.get(channel);
        let window = Window::default();
        let _held = take(&input.budget, &connection(), CHANNEL_INPUT_BUDGET, &window).await;
        assert_eq!(window.calls(), vec![true]);
        inputs.target_closed(channel);
        assert_eq!(window.calls(), vec![true, false]);

        let connection = connection();
        let dropped = tokio::time::timeout(
            Duration::from_secs(5),
            hold_input_until_closed(
                input.budget.clone(),
                connection.clone(),
                b"late",
                Duration::from_secs(30),
                &input.closed,
                window.hold(),
            ),
        )
        .await
        .expect("input after the target's close must not wait")
        .unwrap();
        assert!(dropped.is_none());
        assert_eq!(held(&input.budget), CHANNEL_INPUT_BUDGET, "nothing more");
        assert_eq!(connection.available_permits(), CONNECTION_INPUT_BUDGET);
    }

    /// The client's close, and a channel number used again, release a held
    /// window, so a hold never outlives its channel in the session.
    #[tokio::test]
    async fn closing_or_reusing_a_channel_releases_its_held_window() {
        let inputs = ChannelInputs::default();
        for end in [ChannelInputs::close, ChannelInputs::opened] {
            let input = inputs.get(1);
            let window = Window::default();
            let _held = take(&input.budget, &connection(), CHANNEL_INPUT_BUDGET, &window).await;
            end(&inputs, 1);
            assert_eq!(window.calls(), vec![true, false]);
        }
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
        assert_eq!(held(&fresh.budget), 0);
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
    /// starts with an uncancelled entry and nothing held.
    #[tokio::test]
    async fn a_channel_opened_with_a_reused_number_starts_fresh() {
        let inputs = ChannelInputs::default();
        let channel = 1;
        inputs.get(channel);
        inputs.target_closed(channel);

        inputs.opened(channel);
        let fresh = inputs.get(channel);
        assert!(!fresh.closed.is_cancelled());
        assert_eq!(held(&fresh.budget), 0);
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

    /// Closing one channel leaves the others alone.
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
