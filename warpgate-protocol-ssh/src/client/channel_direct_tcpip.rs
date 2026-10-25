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

pub struct DirectTCPIPChannel {
    read_half: ChannelReadHalf,
    writer: DirectTCPIPWriter,
    channel_id: Uuid,
    ops_rx: UnboundedReceiver<ChannelOperation>,
    events_tx: Sender<RCEvent>,
    session_id: UserSessionId,
}

struct DirectTCPIPWriter {
    write_half: ChannelWriteHalf<Msg>,
    channel_id: Uuid,
    session_id: UserSessionId,
}

impl TargetWriter for DirectTCPIPWriter {
    async fn apply(
        &self,
        operation: ChannelOperation,
    ) -> Result<ControlFlow<()>, SshClientError> {
        match operation {
            ChannelOperation::Data(data) => {
                self.write_half.data(&*data).await?;
            }
            ChannelOperation::Eof => {
                self.write_half.eof().await?;
            }
            ChannelOperation::Close => return Ok(ControlFlow::Break(())),
            operation => {
                warn!(client_channel=%self.channel_id, ?operation, session=%self.session_id, "unexpected client_channel operation");
            }
        }
        Ok(ControlFlow::Continue(()))
    }
}

impl DirectTCPIPChannel {
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
            writer: DirectTCPIPWriter {
                write_half,
                channel_id,
                session_id,
            },
            channel_id,
            ops_rx,
            events_tx,
            session_id,
        }
    }

    /// Exactly one `RCEvent::Close` is delivered for the channel however the pump ends —
    /// the target closing it, Warpgate closing it, or an error — so the client side of a
    /// forwarded connection is never left open.
    pub async fn run(mut self) -> Result<(), SshClientError> {
        let result = self.pump().await;
        let _ = self.events_tx.send(RCEvent::Close(self.channel_id)).await;
        result
    }

    async fn pump(&mut self) -> Result<(), SshClientError> {
        pump(
            &self.writer,
            &mut self.ops_rx,
            forward_target_events(
                &mut self.read_half,
                &self.events_tx,
                self.channel_id,
                self.session_id,
            ),
        )
        .await
    }
}

/// Passes on what the target sends until it closes the channel.
async fn forward_target_events(
    read_half: &mut ChannelReadHalf,
    events_tx: &Sender<RCEvent>,
    channel_id: Uuid,
    session_id: UserSessionId,
) -> Result<(), SshClientError> {
    loop {
        match read_half.wait().await {
            Some(russh::ChannelMsg::Data { data }) => {
                let bytes: &[u8] = &data;
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
            Some(russh::ChannelMsg::Eof) => {
                events_tx
                    .send(RCEvent::Eof(channel_id))
                    .await
                    .map_err(|_| SshClientError::MpscError)?;
            }
            Some(operation) => {
                warn!(client_channel=%channel_id, ?operation, session=%session_id, "unexpected client_channel operation");
            }
        }
    }
}

impl Drop for DirectTCPIPChannel {
    fn drop(&mut self) {
        info!(client_channel=%self.channel_id, session=%self.session_id, "Closed");
    }
}
