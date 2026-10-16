use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use bytes::Bytes;
use russh::keys::PublicKey;
use russh::server::{Auth, ChannelOpenHandle, Handle, Msg, Session};
use russh::{Channel, ChannelId, Pty, Sig};
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};
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

/// How much of one channel's input may be on its way to the target at once
/// (OpenSSH's default channel window). Past it Warpgate stops reading the
/// connection until the target has taken earlier input, so a slow or stalled
/// target slows the upload down (TCP holds the client back) instead of
/// piling it up in memory.
pub const CHANNEL_INPUT_BUDGET: usize = 2 * 1024 * 1024;

/// How much input all of one connection's channels together may have on its
/// way to targets at once. Without it, input spread over many channels would
/// add up past any single channel's budget.
pub const CONNECTION_INPUT_BUDGET: usize = 16 * 1024 * 1024;

/// Input bytes that keep their share of the channel's and the connection's
/// budgets until the last copy of them is dropped, which is after they were
/// written to the target.
struct HeldInput {
    data: Vec<u8>,
    _channel_permit: OwnedSemaphorePermit,
    _connection_permit: OwnedSemaphorePermit,
}

impl AsRef<[u8]> for HeldInput {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

/// Waits until both the channel's and the connection's budgets have room
/// for `data`, then returns it as bytes that hold that room until their last
/// copy is dropped. The channel's share is taken first; one wait limit covers
/// both.
async fn hold_input(
    channel_budget: Arc<Semaphore>,
    connection_budget: Arc<Semaphore>,
    data: &[u8],
    wait_limit: Duration,
) -> anyhow::Result<Bytes> {
    let wanted =
        u32::try_from(data.len().min(CHANNEL_INPUT_BUDGET)).context("channel input budget")?;
    let (channel_permit, connection_permit) = tokio::time::timeout(wait_limit, async {
        let channel_permit = channel_budget.acquire_many_owned(wanted).await?;
        let connection_permit = connection_budget.acquire_many_owned(wanted).await?;
        Ok::<_, tokio::sync::AcquireError>((channel_permit, connection_permit))
    })
    .await
    .context("the target did not take the input in time")?
    .context("input budget closed")?;
    Ok(Bytes::from_owner(HeldInput {
        data: data.to_vec(),
        _channel_permit: channel_permit,
        _connection_permit: connection_permit,
    }))
}

pub struct ServerHandler {
    pub event_tx: UnboundedSender<ServerHandlerEvent>,
    /// Optional custom banner shown to the client during authentication.
    pub banner: Option<String>,
    /// Per channel, the input budget still free (see [`CHANNEL_INPUT_BUDGET`]).
    pub input_budgets: HashMap<ChannelId, Arc<Semaphore>>,
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
    ) -> Self {
        Self {
            event_tx,
            banner,
            input_budgets: HashMap::new(),
            connection_input_budget: Arc::new(Semaphore::new(CONNECTION_INPUT_BUDGET)),
            input_wait_limit,
        }
    }

    /// Waits until the channel's and the connection's budgets have room for
    /// `data`, then returns it as bytes that hold that room until they are
    /// dropped.
    async fn hold_input(&mut self, channel: ChannelId, data: &[u8]) -> anyhow::Result<Bytes> {
        let budget = self
            .input_budgets
            .entry(channel)
            .or_insert_with(|| Arc::new(Semaphore::new(CHANNEL_INPUT_BUDGET)))
            .clone();
        hold_input(
            budget,
            self.connection_input_budget.clone(),
            data,
            self.input_wait_limit,
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
        key: &russh::keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        let user = Secret::new(user.to_string());
        let (tx, rx) = oneshot::channel();

        self.send_event(ServerHandlerEvent::AuthPublicKeyOffer(
            user,
            key.clone(),
            tx,
        ))?;

        Ok(rx.await.unwrap_or_else(|_| Auth::reject()))
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: &russh::keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        let user = Secret::new(user.to_string());
        let (tx, rx) = oneshot::channel();

        self.send_event(ServerHandlerEvent::AuthPublicKey(user, key.clone(), tx))?;

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
        let data = self.hold_input(channel, data).await?;
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
        let data = self.hold_input(channel, data).await?;
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
        self.input_budgets.remove(&channel);
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

    /// Input up to the budget goes straight through; past it the next input
    /// waits until earlier input is dropped (written to the target), and it
    /// gets the same bytes either way.
    #[tokio::test]
    async fn channel_input_past_its_budget_waits_for_the_target() {
        let budget = Arc::new(Semaphore::new(CHANNEL_INPUT_BUDGET));
        let first = hold_input(
            budget.clone(),
            connection(),
            &vec![1; CHANNEL_INPUT_BUDGET],
            WAIT,
        )
        .await
        .unwrap();
        assert_eq!(budget.available_permits(), 0);

        let next = tokio::spawn({
            let budget = budget.clone();
            async move { hold_input(budget, connection(), b"more", Duration::from_secs(5)).await }
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
        let next = next.await.unwrap().unwrap();
        assert_eq!(&next[..], b"more");
        drop(next);
        assert_eq!(budget.available_permits(), CHANNEL_INPUT_BUDGET);
    }

    /// Input that the target never takes ends the wait with an error instead
    /// of holding the connection for ever.
    #[tokio::test]
    async fn channel_input_gives_up_when_the_target_never_takes_it() {
        let budget = Arc::new(Semaphore::new(CHANNEL_INPUT_BUDGET));
        let _held = hold_input(
            budget.clone(),
            connection(),
            &vec![0; CHANNEL_INPUT_BUDGET],
            WAIT,
        )
        .await
        .unwrap();
        assert!(hold_input(budget, connection(), b"x", WAIT).await.is_err());
    }

    /// One packet larger than the whole budget still goes through on an
    /// idle channel rather than waiting for ever.
    #[tokio::test]
    async fn channel_input_larger_than_the_budget_still_passes() {
        let budget = Arc::new(Semaphore::new(CHANNEL_INPUT_BUDGET));
        let big = vec![7; CHANNEL_INPUT_BUDGET + 1];
        let held = hold_input(budget, connection(), &big, WAIT).await.unwrap();
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
            let channel = Arc::new(Semaphore::new(CHANNEL_INPUT_BUDGET));
            held.push(
                hold_input(channel, connection.clone(), &vec![3; per_channel], WAIT)
                    .await
                    .unwrap(),
            );
        }
        assert!(connection.available_permits() < per_channel);

        let one_more = tokio::spawn({
            let connection = connection.clone();
            async move {
                let channel = Arc::new(Semaphore::new(CHANNEL_INPUT_BUDGET));
                hold_input(
                    channel,
                    connection,
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
        let late = one_more.await.unwrap().unwrap();
        assert_eq!(late.len(), per_channel);
        drop(late);
        assert_eq!(connection.available_permits(), CONNECTION_INPUT_BUDGET);
    }

    /// The connection's budget alone also ends a wait that never gets room.
    #[tokio::test]
    async fn input_gives_up_when_the_connection_budget_never_frees() {
        let connection = Arc::new(Semaphore::new(CHANNEL_INPUT_BUDGET));
        let _held = hold_input(
            Arc::new(Semaphore::new(CHANNEL_INPUT_BUDGET)),
            connection.clone(),
            &vec![0; CHANNEL_INPUT_BUDGET],
            WAIT,
        )
        .await
        .unwrap();
        let other_channel = Arc::new(Semaphore::new(CHANNEL_INPUT_BUDGET));
        assert!(
            hold_input(other_channel.clone(), connection, b"x", WAIT)
                .await
                .is_err()
        );
        assert_eq!(
            other_channel.available_permits(),
            CHANNEL_INPUT_BUDGET,
            "a wait that gave up keeps no share of the channel's budget"
        );
    }
}
