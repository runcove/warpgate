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
    /// Input received while the recording waits to start (see
    /// [`Self::await_recorder`]); `None` otherwise.
    pending_input: Option<Vec<u8>>,
    detector: Option<CommandDetector>,
}

impl ChannelAudit {
    pub const fn new(channel_id: Uuid) -> Self {
        Self {
            channel_id,
            recorder: None,
            pending_input: None,
            detector: None,
        }
    }

    /// The channel's recording starts later, once its target session exists.
    /// Input received until then still reaches the target, so it is held and
    /// written to the recording when it starts (see
    /// [`Self::take_pending_input`]).
    pub fn await_recorder(&mut self) {
        if self.recorder.is_none() && self.pending_input.is_none() {
            self.pending_input = Some(vec![]);
        }
    }

    /// The input held since [`Self::await_recorder`], and stop holding it.
    /// The caller writes it to the recording before attaching it, or drops it
    /// when the recording did not start.
    pub fn take_pending_input(&mut self) -> Vec<u8> {
        self.pending_input.take().unwrap_or_default()
    }

    pub fn set_recorder(&mut self, recorder: TerminalRecorder) {
        self.pending_input = None;
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

    /// Waits for the recording's first writes to reach its files (see
    /// [`TerminalRecorder::write_header`]); `Break` as for the `on_*` calls.
    pub async fn write_recording_header(&mut self) -> ControlFlow<()> {
        let result = match self.recorder.as_ref() {
            Some(recorder) => recorder.write_header().await,
            None => Ok(()),
        };
        self.check(result)
    }

    async fn record(&mut self, stream: TerminalRecordingStreamId, data: &[u8]) -> ControlFlow<()> {
        let result = match (self.recorder.as_ref(), self.pending_input.as_mut(), stream) {
            (Some(recorder), _, stream) => recorder.write(stream, data).await,
            (None, Some(input), TerminalRecordingStreamId::Input) => {
                input.extend_from_slice(data);
                Ok(())
            }
            _ => Ok(()),
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

#[cfg(test)]
mod tests {
    use std::ops::ControlFlow;

    use uuid::Uuid;

    use super::ChannelAudit;

    #[tokio::test]
    async fn input_is_held_only_while_the_recording_is_awaited() {
        let mut audit = ChannelAudit::new(Uuid::new_v4());
        assert_eq!(audit.on_input(b"before").await, ControlFlow::Continue(()));
        audit.await_recorder();
        assert_eq!(audit.on_input(b"ab").await, ControlFlow::Continue(()));
        assert_eq!(audit.on_output(b"output").await, ControlFlow::Continue(()));
        assert_eq!(audit.on_input(b"cd").await, ControlFlow::Continue(()));
        assert_eq!(audit.take_pending_input(), b"abcd");
        // Taken: no longer held.
        assert_eq!(audit.on_input(b"after").await, ControlFlow::Continue(()));
        assert!(audit.take_pending_input().is_empty());
    }
}
