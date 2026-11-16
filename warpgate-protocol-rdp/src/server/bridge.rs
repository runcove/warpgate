//! Target-side bridging: once auth succeeds, dial the target, pump its framebuffer to the
//! viewer-facing RDP server, and record the session.

use std::sync::Arc;

use anyhow::Result;
use tokio::sync::Notify;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::{Receiver, Sender, UnboundedSender};
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
/// sessions are refused the session is closed (see [`close_for_recording_failure`]).
/// With the setting off, a frame is dropped from the recording under overload: the
/// recording is best-effort under load by design. With it on, a full queue is a
/// recording failure (see [`queue_for_recording`]).
async fn frame_bridge(
    event_rx: Receiver<DesktopEvent>,
    server_in: Sender<ServerInput>,
    abort_tx: UnboundedSender<()>,
    recorder: Option<Arc<DesktopRecorder>>,
    required: bool,
) {
    // Holds a permit once the recording failed and the session must close.
    let recording_failed = Arc::new(Notify::new());
    let record = recorder.map(|recorder| {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<DesktopEvent>(RECORD_QUEUE_CAPACITY);
        let recording_failed = recording_failed.clone();
        let task_recorder = recorder.clone();
        tokio::spawn(
            async move {
                while let Some(event) = rx.recv().await {
                    if let Err(error) = task_recorder.write_event(&event).await {
                        if task_recorder.write_failed(&error) {
                            recording_failed.notify_one();
                        }
                        return;
                    }
                }
            }
            .in_current_span(),
        );
        (tx, recorder)
    });
    forward_frames(
        event_rx,
        &server_in,
        &abort_tx,
        record.as_ref(),
        required,
        &recording_failed,
    )
    .await;
}

/// [`frame_bridge`]'s loop. `record` is the queue to the recording task and its
/// recorder; `recording_failed` holds a permit once that task found the recording
/// failed and the session must close.
async fn forward_frames(
    mut event_rx: Receiver<DesktopEvent>,
    server_in: &Sender<ServerInput>,
    abort_tx: &UnboundedSender<()>,
    record: Option<&(Sender<DesktopEvent>, Arc<DesktopRecorder>)>,
    required: bool,
    recording_failed: &Notify,
) {
    loop {
        let event = tokio::select! {
            biased;
            () = recording_failed.notified() => break,
            event = event_rx.recv() => event,
        };
        let Some(event) = event else {
            return;
        };
        if let Some((record_tx, recorder)) = record
            && !queue_for_recording(record_tx, recorder, required, event.clone())
        {
            break;
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

        // A viewer that has stopped reading blocks this send; a recording failure
        // must still close the session.
        let sent = tokio::select! {
            biased;
            () = recording_failed.notified() => break,
            sent = server_in.send(message) => sent,
        };
        if sent.is_err() {
            return;
        }
    }
    close_for_recording_failure(event_rx, abort_tx, server_in).await;
}

/// Depth of the queue to the recording task.
const RECORD_QUEUE_CAPACITY: usize = 256;

/// Queues `event` for the recording task, which must never stall the live path.
/// `false` when the session must close: unrecorded sessions are refused and the
/// queue is full, so the recording has fallen behind and the frame would reach the
/// viewer unrecorded; that is reported as the recording's failure. With the setting
/// off the frame is dropped from the recording. A closed queue is a recording that
/// already failed, and was reported by the recording task.
fn queue_for_recording(
    record_tx: &Sender<DesktopEvent>,
    recorder: &DesktopRecorder,
    required: bool,
    event: DesktopEvent,
) -> bool {
    match record_tx.try_send(event) {
        Ok(()) | Err(TrySendError::Closed(_)) => true,
        Err(TrySendError::Full(_)) if required => {
            recorder.write_failed(&"the recording fell behind the session (its queue is full)");
            false
        }
        Err(TrySendError::Full(_)) => true,
    }
}

/// The recording failed and unrecorded sessions are refused. The target is told to
/// disconnect and its frames are no longer taken before the viewer is shut down, so
/// a viewer that has stopped reading cannot hold the target connection open.
async fn close_for_recording_failure(
    event_rx: Receiver<DesktopEvent>,
    abort_tx: &UnboundedSender<()>,
    server_in: &Sender<ServerInput>,
) {
    warn!("Closing the RDP session: its recording failed");
    let _ = abort_tx.send(());
    drop(event_rx);
    let _ = server_in.send(ServerInput::Shutdown).await;
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
        frame_bridge(
            event_rx,
            server_in_tx.clone(),
            abort_tx.clone(),
            recorder.clone(),
            services.recordings.refuses_unrecorded_sessions(),
        )
        .in_current_span(),
    );
    Ok(BackendBridge {
        input_tx,
        abort_tx,
        frame_bridge,
        recorder,
        dialed_at: Some(screen),
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use sea_orm::ActiveValue::Set;
    use sea_orm::{ActiveModelTrait, Database, IntoActiveModel};
    use tokio::sync::Mutex;
    use tokio::sync::mpsc::{UnboundedReceiver, channel, unbounded_channel};
    use uuid::Uuid;
    use warpgate_common::{GlobalParams, TargetSessionId};
    use warpgate_core::cluster::Cluster;
    use warpgate_core::rate_limiting::RateLimiterRegistry;
    use warpgate_core::recordings::{
        DesktopRecordingMetadata, RecordingOwner, SessionRecordings, test_support,
    };
    use warpgate_core::{SessionHandle, State, UserSessionStateInit};
    use warpgate_db_entities::Parameters::{
        self, ConfigMigrationValues, RecordingsDiskConfig, RecordingsStorageConfig,
        set_config_migration_values,
    };
    use warpgate_db_migrations::migrate_database;

    use super::*;

    struct NoopHandle;

    impl SessionHandle for NoopHandle {
        fn close(&mut self) {}
    }

    /// A native RDP session's recording, started on a real disk root.
    struct Recording {
        recorder: Arc<DesktopRecorder>,
        recordings: Arc<SessionRecordings>,
        id: TargetSessionId,
        _dir: tempfile::TempDir,
    }

    async fn recording(refuse: bool) -> Recording {
        test_support::log_events();
        let dir = tempfile::tempdir().unwrap();
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        let mut parameters = Parameters::Entity::get(&db)
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
        parameters.update(&db).await.unwrap();
        let params = GlobalParams::new(dir.path().join("warpgate.yaml"), false)
            .unwrap()
            .with_refuse_unrecorded_sessions(refuse);
        let recordings = Arc::new(SessionRecordings::new(db.clone(), &params));

        let registry = Arc::new(Mutex::new(RateLimiterRegistry::new(db.clone())));
        let cluster = Cluster::new(db.clone(), 0).await.unwrap();
        let state = State::new(&db, &registry, cluster.node_id);
        let server_handle = State::register_node_local_user_session(
            &state,
            warpgate_common::Protocol::Rdp,
            UserSessionStateInit {
                remote_address: None,
                handle: Box::new(NoopHandle),
            },
        )
        .await
        .unwrap();
        let user_session = server_handle.lock().await.user_session_id();
        let id = TargetSessionId(Uuid::new_v4());
        warpgate_db_entities::TargetSession::ActiveModel {
            id: Set(id),
            user_session_id: Set(user_session),
            target_snapshot: Set("{}".into()),
            target_id: Set(Uuid::new_v4()),
            started: Set(time::OffsetDateTime::now_utc()),
            ..Default::default()
        }
        .insert(&db)
        .await
        .unwrap();
        let owner = RecordingOwner {
            protocol: "rdp",
            user: "alice".into(),
            target: "desktop".into(),
        };
        let recorder = recordings
            .start_for::<DesktopRecorder, _>(&owner, &id, None, DesktopRecordingMetadata::Desktop)
            .await
            .unwrap()
            .unwrap();
        Recording {
            recorder: Arc::new(recorder),
            recordings,
            id,
            _dir: dir,
        }
    }

    fn resize() -> DesktopEvent {
        DesktopEvent::Resize {
            width: 800,
            height: 600,
        }
    }

    /// Whether the target was told to disconnect within a few seconds.
    async fn aborted(abort_rx: &mut UnboundedReceiver<()>) -> bool {
        tokio::time::timeout(Duration::from_secs(5), abort_rx.recv())
            .await
            .is_ok_and(|aborted| aborted.is_some())
    }

    /// A recording task that has fallen behind (its queue is full). Required: that
    /// is the recording's failure, reported once with the pinned line, and the
    /// session closes before the frame reaches the viewer. Not required: the frame
    /// is dropped from the recording, reaches the viewer, and nothing is logged.
    #[tokio::test]
    async fn a_full_recording_queue_follows_the_setting() {
        for required in [true, false] {
            let r = recording(required).await;
            // Nobody reads the recording queue: the recording task is stalled.
            let (record_tx, _record_rx) = channel(1);
            record_tx.try_send(resize()).unwrap();
            let (event_tx, event_rx) = channel(16);
            let (server_in, mut viewer) = channel(16);
            let (abort_tx, mut abort_rx) = unbounded_channel();
            let recording_failed = Notify::new();
            event_tx.send(resize()).await.unwrap();
            // Not required: the target then ends, so the bridge returns.
            let event_tx = required.then_some(event_tx);
            let record = (record_tx, r.recorder.clone());
            forward_frames(
                event_rx,
                &server_in,
                &abort_tx,
                Some(&record),
                required,
                &recording_failed,
            )
            .await;

            let shown = std::iter::from_fn(|| viewer.try_recv().ok()).collect::<Vec<_>>();
            let lines = test_support::failed_recording_lines(&r.id);
            if required {
                assert!(
                    matches!(shown.as_slice(), [ServerInput::Shutdown]),
                    "only the shutdown reached the viewer ({} items)", shown.len()
                );
                assert!(aborted(&mut abort_rx).await, "the target was cut off");
                assert!(
                    event_tx.is_some_and(|tx| tx.is_closed()),
                    "target frames are no longer taken"
                );
                assert_eq!(r.recordings.failed_recordings(), 1);
                assert_eq!(lines.len(), 1, "{lines:?}");
                assert_eq!(lines[0]["protocol"], "rdp");
                assert_eq!(lines[0]["stage"], "write");
                assert_eq!(lines[0]["required"], "true");
            } else {
                assert!(
                    matches!(shown.as_slice(), [ServerInput::Resize { .. }]),
                    "the frame reached the viewer ({} items)", shown.len()
                );
                assert!(abort_rx.try_recv().is_err(), "the target stays connected");
                assert_eq!(r.recordings.failed_recordings(), 0);
                assert!(lines.is_empty(), "{lines:?}");
            }
        }
    }

    /// A recording that fails while the viewer has stopped reading (the bridge is
    /// blocked sending it a frame) still closes the session: the target is told to
    /// disconnect and its frames are no longer taken, without waiting on the
    /// viewer.
    #[tokio::test]
    async fn a_failed_recording_cuts_off_the_target_while_the_viewer_is_stalled() {
        let (event_tx, event_rx) = channel(16);
        // One slot, never read: the viewer has stopped reading.
        let (server_in, _viewer) = channel(1);
        let (abort_tx, mut abort_rx) = unbounded_channel();
        let recording_failed = Arc::new(Notify::new());
        let bridge = tokio::spawn({
            let recording_failed = recording_failed.clone();
            async move {
                forward_frames(
                    event_rx,
                    &server_in,
                    &abort_tx,
                    None,
                    true,
                    &recording_failed,
                )
                .await;
            }
        });
        // The first frame fills the viewer's queue; the bridge blocks on the second.
        event_tx.send(resize()).await.unwrap();
        event_tx.send(resize()).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while event_tx.capacity() != event_tx.max_capacity() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(abort_rx.try_recv().is_err(), "nothing failed yet");

        recording_failed.notify_one();
        assert!(aborted(&mut abort_rx).await, "the target was cut off");
        tokio::time::timeout(Duration::from_secs(5), event_tx.closed())
            .await
            .expect("target frames are no longer taken");
        // Its shutdown still waits for the viewer, which never reads.
        assert!(!bridge.is_finished());
        bridge.abort();
    }
}
