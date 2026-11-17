use std::sync::{Arc, OnceLock};

use bytes::Bytes;
use tokio::sync::Mutex;
use tokio::sync::mpsc::Sender;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use warpgate_common::{UserSessionId, WarpgateError};
use warpgate_core::recordings::DesktopRecorder;
use warpgate_core::{DesktopEvent, DesktopInput, DesktopRect, Framebuffer, Rect};
use warpgate_web_clients_common::{ManagedSession, Sheddable, WebSession};

use crate::protocol::{ServerMessage, WsRect};

/// Initial output-buffer allocation. Not a hard cap: incremental frames are bounded by
/// [`MAX_BUFFERED_INCREMENTAL`] and structural messages are rare, so the buffer stays small.
const OUTPUT_BUFFER_CAPACITY: usize = 128;

/// How many incremental (droppable) framebuffer frames to keep buffered for a slow or
/// briefly-disconnected client. Small on purpose: a client that falls behind should get
/// the recent live edge, not a huge stale backlog to grind through (which is what froze
/// the browser on high-frequency updates). Structural messages are never counted or dropped.
const MAX_BUFFERED_INCREMENTAL: usize = 64;

impl Sheddable for ServerMessage {
    fn is_droppable(&self) -> bool {
        self.is_incremental()
    }
}

pub struct DesktopBackend {
    pub input_tx: Sender<DesktopInput>,
    pub recorder: Option<Arc<DesktopRecorder>>,
}

pub struct WebDesktopSession {
    core: WebSession<ServerMessage>,
    backend: OnceLock<DesktopBackend>,
    /// Composited surface, kept so a viewer attaching mid-session gets a base image.
    /// Separate from the recorder's: that one must only see events it actually wrote.
    /// Holds the refinement scratch too, so encoding one region needs a single lock.
    framebuffer: Mutex<(Framebuffer, RefineScratch)>,
}

/// Buffers reused across refinement encodes. A settling screen refines many regions back to
/// back, and `rgba` is a full copy of each region's pixels — a fresh allocation per region
/// would churn megabytes for a once-per-settle job.
#[derive(Default)]
struct RefineScratch {
    rgba: Vec<u8>,
    png: Vec<u8>,
}

impl WebDesktopSession {
    pub fn new(
        id: UserSessionId,
        user_id: Uuid,
        target_name: String,
        target_kind: warpgate_db_entities::Target::TargetKind,
        server_handle: Arc<tokio::sync::Mutex<warpgate_core::WarpgateServerHandle>>,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            core: WebSession::new(
                id,
                user_id,
                target_name,
                target_kind,
                server_handle,
                cancel,
                OUTPUT_BUFFER_CAPACITY,
                MAX_BUFFERED_INCREMENTAL,
            ),
            backend: OnceLock::new(),
            framebuffer: Mutex::new((Framebuffer::default(), RefineScratch::default())),
        }
    }

    pub fn bind_backend(&self, backend: DesktopBackend) {
        let _ = self.backend.set(backend);
    }

    /// Composite an event into the session's surface. Driven from the manager's event loop
    /// on the *pre-JPEG* stream, so this stays a plain blit with no decode round-trip.
    pub async fn composite(&self, event: &DesktopEvent) {
        self.framebuffer.lock().await.0.apply(event);
    }

    /// A full-canvas snapshot for a viewer that just attached. `None` until the backend has
    /// painted something, so a viewer is never handed a black surface to reveal.
    ///
    /// Encodes under the lock: it runs once per attach, and copying the surface out to
    /// offload it would cost more than the encode saves.
    pub async fn keyframe(&self) -> Option<ServerMessage> {
        let (width, height, data) = self.framebuffer.lock().await.0.snapshot_png()?;
        Some(ServerMessage::Keyframe {
            rect: WsRect {
                x: 0,
                y: 0,
                width,
                height,
            },
            data: data.into(),
        })
    }

    /// The current pixels of a region, as a lossless PNG event. Used to refine a region
    /// that was sent lossily and has since gone quiet; `None` once it falls outside the
    /// surface (a resize since it was marked dirty).
    pub async fn refinement(&self, rect: DesktopRect) -> Option<DesktopEvent> {
        let mut guard = self.framebuffer.lock().await;
        let (framebuffer, scratch) = &mut *guard;
        let clipped = framebuffer.region_png(
            Rect {
                x: u32::from(rect.x),
                y: u32::from(rect.y),
                width: u32::from(rect.width),
                height: u32::from(rect.height),
            },
            &mut scratch.rgba,
            &mut scratch.png,
        )?;
        Some(DesktopEvent::PngImage {
            rect: DesktopRect {
                x: u16::try_from(clipped.x).ok()?,
                y: u16::try_from(clipped.y).ok()?,
                width: u16::try_from(clipped.width).ok()?,
                height: u16::try_from(clipped.height).ok()?,
            },
            // Copied out so the scratch keeps its capacity for the next region.
            data: Bytes::copy_from_slice(&scratch.png),
        })
    }

    pub async fn send_input(&self, input: DesktopInput) {
        let Some(backend) = self.backend.get() else {
            return;
        };
        // Once the session is ended (for its recording or otherwise), nothing more is
        // forwarded, though the backend may not have stopped yet: input the recording
        // never writes (the clipboard, unrecorded keys) would otherwise still pass.
        if self.cancellation().is_cancelled() {
            return;
        }
        // Record the viewer's input for audit before forwarding (like native RDP/VNC).
        // A failed write is reported once by the recorder; when unrecorded sessions are
        // refused the session ends before the input is forwarded.
        if let Some(recorder) = &backend.recorder
            && let Err(error) = recorder.write_input(&input).await
            && recorder.write_failed(&error)
        {
            self.push(ServerMessage::Error {
                message: WarpgateError::SessionRecordingFailed.to_string(),
            })
            .await;
            self.abort();
            return;
        }
        // The recording's write awaits: the session may have ended meanwhile.
        if self.cancellation().is_cancelled() {
            return;
        }
        // let inputs drop under backpressure
        let _ = backend.input_tx.try_send(input);
    }
}

impl std::ops::Deref for WebDesktopSession {
    type Target = WebSession<ServerMessage>;
    fn deref(&self) -> &Self::Target {
        &self.core
    }
}

impl ManagedSession for WebDesktopSession {
    fn id(&self) -> UserSessionId {
        self.core.id()
    }

    fn user_id(&self) -> Uuid {
        self.core.user_id()
    }

    fn on_removed(&self) {
        self.core.abort();
    }
}

// Every test here fails a recording through `/proc/self/fd`.
#[cfg(all(test, target_os = "linux"))]
pub(crate) mod tests {
    use std::time::Duration;

    use sea_orm::ActiveValue::Set;
    use sea_orm::{ActiveModelTrait, Database, IntoActiveModel};
    use tokio::sync::mpsc::Receiver;
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

    /// A web desktop session whose recording started on a real disk root, then
    /// fails as a full disk would.
    pub(crate) struct Harness {
        pub(crate) session: WebDesktopSession,
        forwarded: Receiver<DesktopInput>,
        /// The recorder bound to the session's backend.
        pub(crate) recorder: Arc<DesktopRecorder>,
        recordings: Arc<SessionRecordings>,
        id: TargetSessionId,
        required: bool,
        _dir: tempfile::TempDir,
    }

    pub(crate) async fn desktop_failing_mid_session(refuse: bool) -> Harness {
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
            protocol: "web-desktop",
            user: "alice".into(),
            target: "desktop".into(),
        };
        let recorder = recordings
            .start_for::<DesktopRecorder, _>(&owner, &id, None, DesktopRecordingMetadata::Desktop)
            .await
            .unwrap()
            .unwrap();
        let session = WebDesktopSession::new(
            user_session,
            Uuid::new_v4(),
            "desktop".into(),
            warpgate_db_entities::Target::TargetKind::Rdp,
            server_handle,
            CancellationToken::new(),
        );
        let (input_tx, forwarded) = tokio::sync::mpsc::channel(10_000);
        let recorder = Arc::new(recorder);
        session.bind_backend(DesktopBackend {
            input_tx,
            recorder: Some(recorder.clone()),
        });
        assert!(
            test_support::fail_open_recording_files(&dir.path().join("recordings")) >= 2,
            "the data and index files were broken"
        );
        Harness {
            session,
            forwarded,
            recorder,
            recordings,
            id,
            required: refuse,
            _dir: dir,
        }
    }

    impl Harness {
        pub(crate) fn failures(&self) -> u64 {
            self.recordings.failed_recordings()
        }

        fn aborted(&self) -> bool {
            self.session.cancellation().is_cancelled()
        }

        fn forwarded(&mut self) -> usize {
            let mut n = 0;
            while self.forwarded.try_recv().is_ok() {
                n += 1;
            }
            n
        }

        /// Sends viewer input until the failure is seen (writes are queued, so the
        /// first ones after the break can still be accepted). Returns how many inputs
        /// were sent and how many were forwarded to the desktop.
        async fn input_until_failure(&mut self) -> (usize, usize) {
            let (mut inputs, mut forwarded) = (0, 0);
            for _ in 0..1000 {
                self.session
                    .send_input(DesktopInput::Pointer {
                        x: 1,
                        y: 1,
                        buttons: 0,
                    })
                    .await;
                inputs += 1;
                forwarded += self.forwarded();
                // The recorder's own task logs the failure as soon as it happens; the
                // session sees it at its next write. So when required, wait for the
                // end; otherwise for the log line.
                let seen = if self.required {
                    self.aborted()
                } else {
                    self.recordings.failed_recordings() > 0
                };
                if seen {
                    return (inputs, forwarded);
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            panic!("the recording never failed");
        }

        pub(crate) fn assert_one_failure_line(&self, required: bool) {
            assert_eq!(self.recordings.failed_recordings(), 1);
            let lines = test_support::failed_recording_lines(&self.id);
            assert_eq!(lines.len(), 1, "{lines:?}");
            assert_eq!(lines[0]["protocol"], "web-desktop");
            assert_eq!(lines[0]["stage"], "write");
            assert_eq!(lines[0]["required"], required.to_string());
        }
    }

    /// Required: viewer input whose recording fails ends the session, tells the
    /// viewer, and is not forwarded to the desktop.
    #[tokio::test]
    async fn input_whose_recording_fails_ends_the_session_when_required() {
        let mut h = desktop_failing_mid_session(true).await;
        let (inputs, forwarded) = h.input_until_failure().await;
        assert!(h.aborted(), "the session is ended");
        assert_eq!(
            forwarded,
            inputs - 1,
            "the input whose recording failed was not forwarded"
        );
        let reason = WarpgateError::SessionRecordingFailed.to_string();
        assert!(
            h.session
                .drain_buffer()
                .await
                .iter()
                .any(|m| matches!(m, ServerMessage::Error { message } if *message == reason))
        );
        h.assert_one_failure_line(true);
    }

    /// Once the session has ended for its recording, no later input reaches the
    /// desktop, whether or not the recording would write it.
    #[tokio::test]
    async fn no_input_passes_once_the_session_ended_for_its_recording() {
        let mut h = desktop_failing_mid_session(true).await;
        h.input_until_failure().await;
        assert!(h.aborted());
        for input in [
            DesktopInput::Pointer {
                x: 3,
                y: 3,
                buttons: 1,
            },
            DesktopInput::Clipboard("text".into()),
            DesktopInput::Refresh,
        ] {
            h.session.send_input(input).await;
        }
        assert_eq!(h.forwarded(), 0, "forwarded after the end");
    }

    /// Not required (the default): the session goes on unrecorded and every input is
    /// forwarded; the failure is logged and counted once.
    #[tokio::test]
    async fn with_refusal_off_failing_input_recording_ends_nothing() {
        let mut h = desktop_failing_mid_session(false).await;
        let (inputs, forwarded) = h.input_until_failure().await;
        assert_eq!(forwarded, inputs, "every input was forwarded");
        for _ in 0..3 {
            h.session
                .send_input(DesktopInput::Pointer {
                    x: 2,
                    y: 2,
                    buttons: 0,
                })
                .await;
        }
        assert_eq!(h.forwarded(), 3);
        assert!(!h.aborted(), "the session goes on");
        h.assert_one_failure_line(false);
    }
}
