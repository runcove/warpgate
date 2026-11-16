use std::ops::ControlFlow;

use tracing::info;
use uuid::Uuid;
use warpgate_core::recordings::{TerminalRecorder, TerminalRecordingStreamId};

use crate::command_detector::CommandDetector;
use crate::common::PtyRequest;

/// Encapsulates channel recording and command detection
pub struct ChannelAudit {
    channel_id: Uuid,
    recorder: Option<TerminalRecorder>,
    detector: Option<CommandDetector>,
}

impl ChannelAudit {
    pub const fn new(channel_id: Uuid) -> Self {
        Self {
            channel_id,
            recorder: None,
            detector: None,
        }
    }

    pub fn set_recorder(&mut self, recorder: TerminalRecorder) {
        self.recorder = Some(recorder);
    }

    pub fn start_command_detection(&mut self, cols: u16, rows: u16) {
        self.detector = Some(CommandDetector::new(cols, rows));
    }

    // Each `on_*` returns `Break` when the recording just failed and unrecorded
    // sessions are refused: the caller must then close the session without
    // forwarding the data. The failure itself is logged (once per recording) by
    // the recorder; the channel goes on unrecorded otherwise.

    pub async fn on_input(&mut self, data: &[u8]) -> ControlFlow<()> {
        let flow = self.record(TerminalRecordingStreamId::Input, data).await;
        if let Some(detector) = self.detector.as_mut() {
            detector.on_input(data);
        }
        flow
    }

    pub async fn on_output(&mut self, data: &[u8]) -> ControlFlow<()> {
        let flow = self.record(TerminalRecordingStreamId::Output, data).await;
        if let Some(detector) = self.detector.as_mut()
            && let Some(command) = detector.on_output(data)
        {
            info!(channel_id=%self.channel_id, %command, "Shell command");
        }
        flow
    }

    pub async fn on_error_output(&mut self, data: &[u8]) -> ControlFlow<()> {
        self.record(TerminalRecordingStreamId::Error, data).await
    }

    pub async fn on_resize(&mut self, pty: &PtyRequest) -> ControlFlow<()> {
        let result = match self.recorder.as_ref() {
            Some(recorder) => {
                recorder
                    .write_pty_resize(pty.col_width, pty.row_height)
                    .await
            }
            None => Ok(()),
        };
        if let Some(detector) = self.detector.as_mut() {
            let (cols, rows) = pty.screen_size();
            detector.on_resize(cols, rows);
        }
        self.check(result)
    }

    async fn record(&mut self, stream: TerminalRecordingStreamId, data: &[u8]) -> ControlFlow<()> {
        let result = match self.recorder.as_ref() {
            Some(recorder) => recorder.write(stream, data).await,
            None => Ok(()),
        };
        self.check(result)
    }

    /// A failed write reports the recording's failure and stops recording the channel.
    fn check(&mut self, result: warpgate_core::recordings::Result<()>) -> ControlFlow<()> {
        let Err(error) = result else {
            return ControlFlow::Continue(());
        };
        let Some(recorder) = self.recorder.take() else {
            return ControlFlow::Continue(());
        };
        if recorder.write_failed(&error) {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    }
}
