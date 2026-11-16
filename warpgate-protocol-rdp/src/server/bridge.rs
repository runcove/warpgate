//! Target-side bridging: once auth succeeds, dial the target, pump its framebuffer to the
//! viewer-facing RDP server, and record the session.

use std::sync::Arc;

use anyhow::Result;
use tokio::sync::Notify;
use tokio::sync::mpsc::Sender;
use tracing::{Instrument as _, info, warn};
use warpgate_common::TargetRdpOptions;
use warpgate_core::recordings::DesktopRecorder;
use warpgate_core::{AdmittedTarget, DesktopClientHandles, DesktopEvent, DesktopState, Services};

use super::BackendBridge;
use super::protocol::Input as ServerInput;

/// Bridge target-side desktop events to the viewer-facing RDP server. Every framebuffer
/// update is a delta rectangle, so none may be dropped — a lost tile leaves that region
/// stale until it next changes. `server_in` is bounded, so a slow viewer applies
/// backpressure here, which propagates to the target via IronRDP's frame acknowledgements
/// (the target paces to the slowest consumer instead of us discarding pixels).
///
/// Recording runs on its own task so its (serialising) `write_event` never gates live frame
/// delivery — `DesktopEvent` clones are cheap (`RawImage` holds ref-counted `Bytes`). The
/// recorder is also shared with `control_loop` (viewer input); the recording finalises once
/// every handle drops.
///
/// A failed recording write is reported once and recording stops; when unrecorded
/// sessions are refused the viewer is shut down. A frame dropped under overload (below)
/// is not a failure: the recording is best-effort under load by design.
async fn frame_bridge(
    mut event_rx: tokio::sync::mpsc::Receiver<DesktopEvent>,
    server_in: Sender<ServerInput>,
    recorder: Option<Arc<DesktopRecorder>>,
) {
    // Holds a permit once the recording failed and the session must close.
    let recording_failed = Arc::new(Notify::new());
    let record_tx = recorder.map(|recorder| {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<DesktopEvent>(256);
        let recording_failed = recording_failed.clone();
        tokio::spawn(
            async move {
                while let Some(event) = rx.recv().await {
                    if let Err(error) = recorder.write_event(&event).await {
                        if recorder.write_failed(&error) {
                            recording_failed.notify_one();
                        }
                        return;
                    }
                }
            }
            .in_current_span(),
        );
        tx
    });

    loop {
        let event = tokio::select! {
            biased;
            () = recording_failed.notified() => {
                warn!("Closing the RDP session: its recording failed");
                let _ = server_in.send(ServerInput::Shutdown).await;
                return;
            }
            event = event_rx.recv() => event,
        };
        let Some(event) = event else {
            break;
        };
        if let Some(record_tx) = &record_tx {
            // Best-effort: recording must never stall the live path, so drop under overload.
            let _ = record_tx.try_send(event.clone());
        }

        let message = match event {
            DesktopEvent::Resize { width, height } => ServerInput::Resize { width, height },
            DesktopEvent::RawImage { rect, data } => ServerInput::Frame {
                x: rect.x,
                y: rect.y,
                width: rect.width,
                height: rect.height,
                // `data` is ref-counted `Bytes` — moved into the frame, no framebuffer copy.
                data,
            },
            DesktopEvent::Cursor { rect, data } => ServerInput::Cursor {
                // As in RFB, the rect's origin is the hotspot.
                hotspot_x: rect.x,
                hotspot_y: rect.y,
                width: rect.width,
                height: rect.height,
                data,
            },
            DesktopEvent::CursorDefault => ServerInput::CursorDefault,
            DesktopEvent::CursorHidden => ServerInput::CursorHidden,
            DesktopEvent::Clipboard(text) => ServerInput::Clipboard(text),
            DesktopEvent::State(DesktopState::Disconnected) => {
                let _ = server_in.send(ServerInput::Shutdown).await;
                return;
            }
            DesktopEvent::Error(message) => {
                warn!(%message, "RDP target reported an error");
                continue;
            }
            DesktopEvent::State(state @ (DesktopState::Connecting | DesktopState::Connected)) => {
                info!(?state, "RDP target");
                continue;
            }
            // The client never emits the remaining framebuffer variants
            _ => continue,
        };

        if server_in.send(message).await.is_err() {
            return;
        }
    }
}

/// Connect to the target and start bridging its framebuffer, once auth is complete.
pub(super) async fn connect_backend(
    services: &Services,
    server_in_tx: &Sender<ServerInput>,
    admitted: AdmittedTarget<TargetRdpOptions>,
    screen: warpgate_desktop_ui::Screen,
) -> Result<BackendBridge> {
    info!(target=%admitted.target().name, "Authorized");

    let owner = warpgate_desktop_auth::recording_owner("rdp", &admitted);
    let recorder = warpgate_desktop_auth::start_recording(services, &admitted.id(), owner)
        .await?
        .map(Arc::new);

    let DesktopClientHandles {
        event_rx,
        input_tx,
        abort_tx,
        logon_state,
    } = crate::connect(
        admitted,
        (screen.width, screen.height),
        services.secret_backends.clone(),
    )?;
    if let Some(recorder) = &recorder {
        recorder.track_logon_state(logon_state);
    }
    let frame_bridge = tokio::spawn(
        frame_bridge(event_rx, server_in_tx.clone(), recorder.clone()).in_current_span(),
    );
    Ok(BackendBridge {
        input_tx,
        abort_tx,
        frame_bridge,
        recorder,
        dialed_at: Some(screen),
    })
}
