use std::ops::ControlFlow;

use anyhow::Result;
use bytes::Bytes;
use russh::client::Msg;
use russh::{Channel, ChannelReadHalf, ChannelWriteHalf};
use tokio::sync::mpsc::{Sender, UnboundedReceiver};
use tracing::*;
use uuid::Uuid;
use warpgate_common::UserSessionId;

use super::channel_pump::{TargetWriter, pump};
use super::error::SshClientError;
use crate::{ChannelOperation, RCEvent};

pub struct SessionChannel {
    read_half: ChannelReadHalf,
    write_half: ChannelWriteHalf<Msg>,
    channel_id: Uuid,
    ops_rx: UnboundedReceiver<ChannelOperation>,
    events_tx: Sender<RCEvent>,
    session_id: UserSessionId,
    closed: bool,
}

impl SessionChannel {
    pub fn new(
        client_channel: Channel<Msg>,
        channel_id: Uuid,
        ops_rx: UnboundedReceiver<ChannelOperation>,
        events_tx: Sender<RCEvent>,
        session_id: UserSessionId,
    ) -> Self {
        let (read_half, write_half) = client_channel.split();
        Self {
            read_half,
            write_half,
            channel_id,
            ops_rx,
            events_tx,
            session_id,
            closed: false,
        }
    }

    /// The client's operations and the target's events run as two directions
    /// of one [`pump`], so a write that waits for the target's window never
    /// stops its output being read.
    pub async fn run(mut self) -> Result<(), SshClientError> {
        pump(
            &self.write_half,
            &mut self.ops_rx,
            forward_target_events(&mut self.read_half, &self.events_tx, self.channel_id),
        )
        .await?;
        self.close_and_wait().await;
        Ok(())
    }

    /// Delivers the close, rather than attempting it.
    ///
    /// `events_tx` holds 1024 events and every chunk of target output takes one
    /// of them, so a session that has just streamed a large amount leaves the
    /// queue full at exactly the moment the channel ends. `try_send` then fails,
    /// the close is discarded, and the client is never told its channel is over.
    async fn close_and_wait(&mut self) {
        if !self.closed {
            let _ = self.events_tx.send(RCEvent::Close(self.channel_id)).await;
            self.closed = true;
        }
    }

    /// The same, for `Drop`, where there is nothing to await with.
    fn close(&mut self) {
        if !self.closed {
            let _ = self.events_tx.try_send(RCEvent::Close(self.channel_id));
            self.closed = true;
        }
    }
}

impl TargetWriter for ChannelWriteHalf<Msg> {
    async fn apply(
        &self,
        operation: ChannelOperation,
    ) -> Result<ControlFlow<()>, SshClientError> {
        match operation {
            ChannelOperation::Data(data) => {
                self.data(&*data).await?;
            }
            ChannelOperation::ExtendedData { ext, data } => {
                self.extended_data(ext, &*data).await?;
            }
            ChannelOperation::RequestPty(request) => {
                self.request_pty(
                    true,
                    &request.term,
                    request.col_width,
                    request.row_height,
                    request.pix_width,
                    request.pix_height,
                    &request.modes,
                )
                .await?;
            }
            ChannelOperation::ResizePty(request) => {
                self.window_change(
                    request.col_width,
                    request.row_height,
                    request.pix_width,
                    request.pix_height,
                )
                .await?;
            }
            ChannelOperation::RequestShell => {
                self.request_shell(true).await?;
            }
            ChannelOperation::RequestEnv(name, value) => {
                self.set_env(false, name, value).await?;
            }
            ChannelOperation::RequestExec(command) => {
                self.exec(false, command).await?;
            }
            ChannelOperation::RequestSubsystem(name) => {
                self.request_subsystem(false, &name).await?;
            }
            ChannelOperation::Eof => {
                self.eof().await?;
            }
            ChannelOperation::Signal(signal) => {
                self.signal(signal).await?;
            }
            ChannelOperation::OpenShell
            | ChannelOperation::OpenDirectTCPIP { .. }
            | ChannelOperation::OpenDirectStreamlocal { .. }
            | ChannelOperation::OpenX11 { .. } => unreachable!(),
            ChannelOperation::RequestX11(request) => {
                self.request_x11(
                    true,
                    request.single_conection,
                    request.x11_auth_protocol,
                    request.x11_auth_cookie,
                    request.x11_screen_number,
                )
                .await?;
            }
            ChannelOperation::AgentForward => {
                self.agent_forward(true).await?;
            }
            ChannelOperation::Close => return Ok(ControlFlow::Break(())),
        }
        Ok(ControlFlow::Continue(()))
    }
}

/// Passes on what the target sends until it closes the channel.
async fn forward_target_events(
    read_half: &mut ChannelReadHalf,
    events_tx: &Sender<RCEvent>,
    channel_id: Uuid,
) -> Result<(), SshClientError> {
    loop {
        match read_half.wait().await {
            Some(russh::ChannelMsg::Data { data }) => {
                let bytes: &[u8] = &data;
                debug!("channel data: {bytes:?}");
                events_tx
                    .send(RCEvent::Output(channel_id, Bytes::from(bytes.to_vec())))
                    .await
                    .map_err(|_| SshClientError::MpscError)?;
            }
            Some(russh::ChannelMsg::Close) | None => return Ok(()),
            Some(russh::ChannelMsg::Success) => {
                events_tx
                    .send(RCEvent::Success(channel_id))
                    .await
                    .map_err(|_| SshClientError::MpscError)?;
            }
            Some(russh::ChannelMsg::Failure) => {
                events_tx
                    .send(RCEvent::ChannelFailure(channel_id))
                    .await
                    .map_err(|_| SshClientError::MpscError)?;
            }
            Some(russh::ChannelMsg::Eof) => {
                events_tx
                    .send(RCEvent::Eof(channel_id))
                    .await
                    .map_err(|_| SshClientError::MpscError)?;
            }
            Some(russh::ChannelMsg::ExitStatus { exit_status }) => {
                events_tx
                    .send(RCEvent::ExitStatus(channel_id, exit_status))
                    .await
                    .map_err(|_| SshClientError::MpscError)?;
            }
            Some(russh::ChannelMsg::ExitSignal {
                core_dumped,
                error_message,
                lang_tag,
                signal_name,
            }) => {
                events_tx
                    .send(RCEvent::ExitSignal {
                        channel: channel_id,
                        core_dumped,
                        error_message,
                        lang_tag,
                        signal_name,
                    })
                    .await
                    .map_err(|_| SshClientError::MpscError)?;
            }
            Some(
                russh::ChannelMsg::WindowAdjusted { .. } | russh::ChannelMsg::XonXoff { .. },
            ) => {}
            Some(russh::ChannelMsg::ExtendedData { data, ext }) => {
                let data: &[u8] = &data;
                events_tx
                    .send(RCEvent::ExtendedData {
                        channel: channel_id,
                        data: Bytes::from(data.to_vec()),
                        ext,
                    })
                    .await
                    .map_err(|_| SshClientError::MpscError)?;
            }
            Some(msg) => {
                warn!("unhandled channel message: {:?}", msg);
            }
        }
    }
}

impl Drop for SessionChannel {
    fn drop(&mut self) {
        let () = self.close();
        info!(channel=%self.channel_id, session=%self.session_id, "Closed");
    }
}
