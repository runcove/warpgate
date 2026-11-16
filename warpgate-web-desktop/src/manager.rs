use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;

use anyhow::anyhow;
use bytes::Bytes;
use futures::stream::{FuturesOrdered, StreamExt};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, info_span};
use warpgate_common::{TargetOptions, TargetSessionId, UserSessionId, WarpgateError};
use warpgate_core::recordings::{
    DesktopRecorder, DesktopRecordingMetadata, RecordingOwner, SessionRecordings,
};
use warpgate_core::{
    AdmittedTarget, DesktopClientHandles, DesktopEvent, Services, TargetAuthorization,
};
use warpgate_db_entities::Target::TargetKind;
use warpgate_web_clients_common::{
    ClientManager, register_provisional_web_client_session, run_web_client_lifecycle,
};

use crate::dirty::DirtyTracker;
use crate::protocol::{ServerMessage, phase_for};
use crate::session::{DesktopBackend, WebDesktopSession};

const MAX_SESSIONS_PER_USER: usize = 50;

#[derive(Default)]
pub struct WebDesktopClientManager(ClientManager<WebDesktopSession>);

impl std::ops::Deref for WebDesktopClientManager {
    type Target = ClientManager<WebDesktopSession>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl WebDesktopClientManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn create_session(
        &self,
        services: &Services,
        authorization: TargetAuthorization,
        remote_address: Option<SocketAddr>,
        size: Option<(u16, u16)>,
    ) -> Result<UserSessionId, WarpgateError> {
        let user_id = authorization.user_info().id;
        let username = authorization.user_info().username.clone();
        let target_name = authorization.target().name.clone();
        let target_kind = TargetKind::from(&authorization.target().options);
        let protocol = match &authorization.target().options {
            TargetOptions::Vnc(_) => warpgate_protocol_vnc::PROTOCOL_NAME,
            TargetOptions::Rdp(_) => warpgate_protocol_rdp::PROTOCOL_NAME,
            _ => return Err(WarpgateError::InvalidTarget),
        };

        let cancel = CancellationToken::new();
        let server_handle =
            register_provisional_web_client_session(services, protocol, remote_address, &cancel)
                .await?;
        let session_id = server_handle.lock().await.user_session_id();

        let session = Arc::new(WebDesktopSession::new(
            session_id,
            user_id,
            target_name.clone(),
            target_kind,
            server_handle,
            cancel,
        ));

        self.try_insert(session.clone(), MAX_SESSIONS_PER_USER)
            .await?;
        // Reaped unless a client attaches; attaching cancels the timer.
        session.start_disconnect_timer(self.0.clone()).await;

        tokio::spawn(
            run_session(
                session,
                authorization,
                remote_address,
                size,
                self.0.clone(),
                services.clone(),
            )
            .instrument(info_span!("web-desktop", session=%session_id)),
        );

        debug!(session=%session_id, user=%username, target=%target_name, "Web-desktop session created");

        Ok(session_id)
    }
}

async fn run_session(
    session: Arc<WebDesktopSession>,
    authorization: TargetAuthorization,
    remote_address: Option<SocketAddr>,
    size: Option<(u16, u16)>,
    registry: ClientManager<WebDesktopSession>,
    services: Services,
) {
    run_web_client_lifecycle(
        &session,
        registry,
        &services,
        authorization,
        remote_address,
        |admitted| async {
            match connect(&session, &services, admitted, size).await {
                Ok((handles, recorder, encode_jpeg)) => {
                    relay_events(&session, handles, recorder, encode_jpeg).await
                }
                Err(e) => Err(e),
            }
        },
    )
    .await;
}

/// Whether a backend's raw tiles are re-encoded as JPEG before they reach the browser.
///
/// Both backends hand us decoded BGRA: the RDP helper only ever emits raw, and the VNC
/// client decodes every Tight/ZRLE rect it receives, so a lossless rect (text, UI)
/// arrives as raw pixels at 4 bytes each. Shipping those to the browser as-is cost
/// 6.4 MB per full 1600x1000 frame and a steady ~14 Mbit/s, about 20x what Xvnc sent.
/// The JPEG path stays sharp: a region is re-sent losslessly once it settles
/// ([`DirtyTracker`]).
fn encodes_jpeg(kind: TargetKind) -> bool {
    matches!(kind, TargetKind::Vnc | TargetKind::Rdp)
}

/// Start recording, then connect.
async fn connect(
    session: &WebDesktopSession,
    services: &Services,
    admitted: AdmittedTarget,
    size: Option<(u16, u16)>,
) -> Result<(DesktopClientHandles, Option<Arc<DesktopRecorder>>, bool), WarpgateError> {
    let target_session_id = admitted.id();
    let kind = *session.target_kind();
    if !matches!(kind, TargetKind::Vnc | TargetKind::Rdp) {
        return Err(WarpgateError::InvalidTarget);
    }
    let owner = RecordingOwner {
        protocol: "web-desktop",
        user: admitted.user_info().username.clone(),
        target: admitted.target().name.clone(),
    };
    let (handles, recorder) = record_then_dial(
        &services.recordings,
        &owner,
        &target_session_id,
        || match kind {
            TargetKind::Vnc => {
                warpgate_protocol_vnc::connect(admitted.narrow()?, services.secret_backends.clone())
            }
            // Connect at the viewer's measured size when known, so the desktop fits the
            // browser from the first frame; the DVC resize path handles later changes.
            _ => warpgate_protocol_rdp::connect(
                admitted.narrow()?,
                size.unwrap_or(warpgate_protocol_rdp::DEFAULT_SIZE),
                services.secret_backends.clone(),
            ),
        },
    )
    .await?;

    session.bind_backend(DesktopBackend {
        input_tx: handles.input_tx.clone(),
        recorder: recorder.clone(),
    });
    Ok((handles, recorder, encodes_jpeg(kind)))
}

/// Start a desktop recording (no-op if recording is disabled in config), then `dial` the
/// backend with its stored credentials. A recording that fails to start while unrecorded
/// sessions are refused ends here, before the backend is dialled. The recorder is shared
/// (Arc) between the session — which records viewer input — and the event loop, which
/// records framebuffer updates; the recording finalises when both drop.
async fn record_then_dial(
    recordings: &SessionRecordings,
    owner: &RecordingOwner,
    target_session_id: &TargetSessionId,
    dial: impl FnOnce() -> Result<DesktopClientHandles, WarpgateError>,
) -> Result<(DesktopClientHandles, Option<Arc<DesktopRecorder>>), WarpgateError> {
    let recorder = match recordings
        .start_for::<DesktopRecorder, _>(
            owner,
            target_session_id,
            None,
            DesktopRecordingMetadata::Desktop,
        )
        .await
    {
        Ok(recorder) => recorder,
        // Logged by `start_for`.
        Err(_) => {
            if recordings.refuses_unrecorded_sessions() {
                return Err(WarpgateError::SessionNotRecorded);
            }
            None
        }
    };
    let handles = dial()?;
    if let Some(recorder) = &recorder {
        recorder.track_logon_state(handles.logon_state.clone());
    }
    Ok((handles, recorder.map(Arc::new)))
}

/// Record an event, then send it. Both the live stream and refinements go out this way, so
/// a recording plays back at the same progressive quality the viewer saw. `raw` carries a
/// re-encoded tile's original pixels, letting the recorder composite without a decode.
///
/// A backend state change becomes a session phase; an error is remembered and returned so
/// the session can end with it. A failed recording write is reported once by the
/// recorder; when unrecorded sessions are refused it is
/// [`WarpgateError::SessionRecordingFailed`] and the event is not sent.
async fn emit(
    session: &WebDesktopSession,
    recorder: Option<&DesktopRecorder>,
    event: DesktopEvent,
    raw: Option<&Bytes>,
) -> Result<(), WarpgateError> {
    if let Some(recorder) = recorder {
        let result = match (&event, raw) {
            (DesktopEvent::JpegImage { rect, data }, Some(raw)) => {
                recorder.write_jpeg_with_raw(*rect, data, raw).await
            }
            _ => recorder.write_event(&event).await,
        };
        if let Err(error) = result
            && recorder.write_failed(&error)
        {
            return Err(WarpgateError::SessionRecordingFailed);
        }
    }
    match event {
        DesktopEvent::State(state) => {
            if let Some(phase) = phase_for(state) {
                session.set_phase(phase).await;
            }
            Ok(())
        }
        DesktopEvent::Error(message) => {
            session
                .push(ServerMessage::Error {
                    message: message.clone(),
                })
                .await;
            Err(anyhow!(message).into())
        }
        event => {
            if let Some(msg) = ServerMessage::from_event(event) {
                session.push(msg).await;
            }
            Ok(())
        }
    }
}

/// How many events may sit between receipt and emission. Tiles inside this window JPEG-
/// encode concurrently on the blocking pool while emission stays in arrival order; past
/// it, receiving pauses so a slow encoder or recorder backpressures the backend.
const MAX_PIPELINED_EVENTS: usize = 8;

/// An event ready to emit, with the original pixels of a re-encoded tile (see [`emit`]).
type PreparedEvent = (DesktopEvent, Option<Bytes>);

fn prepare(
    event: DesktopEvent,
    encode_jpeg: bool,
) -> Pin<Box<dyn Future<Output = PreparedEvent> + Send>> {
    if encode_jpeg {
        Box::pin(crate::jpeg::encode_raw_images(event))
    } else {
        Box::pin(std::future::ready((event, None)))
    }
}

async fn relay_events(
    session: &WebDesktopSession,
    handles: DesktopClientHandles,
    recorder: Option<Arc<DesktopRecorder>>,
    encode_jpeg: bool,
) -> Result<(), WarpgateError> {
    let DesktopClientHandles {
        mut event_rx,
        abort_tx,
        ..
    } = handles;
    session.forward_cancellation(abort_tx);
    // Only the JPEG path loses detail, so only it has anything to refine.
    let mut dirty = DirtyTracker::new();
    // Events between receipt and emission. Composited immediately, JPEG-encoded
    // concurrently, emitted strictly in arrival order.
    let mut pipeline: FuturesOrdered<_> = FuturesOrdered::new();
    let mut backend_done = false;
    let mut final_result: Result<(), WarpgateError> = Ok(());
    loop {
        if backend_done && pipeline.is_empty() {
            break;
        }
        // No pending regions means nothing to wake up for; park on the far future
        // rather than spinning, and let an incoming event arm the timer.
        let next_due = dirty.next_due();
        let refine = async {
            match next_due {
                Some(due) => tokio::time::sleep_until(due.into()).await,
                None => std::future::pending().await,
            }
        };

        tokio::select! {
            event = event_rx.recv(), if !backend_done && pipeline.len() < MAX_PIPELINED_EVENTS => {
                let Some(event) = event else {
                    backend_done = true;
                    continue;
                };
                // Composite before any re-encoding, so this is a plain blit rather
                // than a JPEG decode round-trip. Gives a viewer attaching later a
                // base image, and is the source the refinement reads back from.
                session.composite(&event).await;
                // Ahead of the recorder, so recordings shrink along with the wire.
                pipeline.push_back(prepare(event, encode_jpeg));
            }
            Some((event, raw)) = pipeline.next(), if !pipeline.is_empty() => {
                match &event {
                    DesktopEvent::Resize { width, height } => {
                        dirty.resize(*width, *height);
                    }
                    DesktopEvent::JpegImage { rect, .. } if encode_jpeg => {
                        dirty.touch(*rect, Instant::now());
                    }
                    _ => {}
                }
                match emit(session, recorder.as_deref(), event, raw.as_ref()).await {
                    // Ends the session: nothing more reaches the viewer unrecorded.
                    Err(WarpgateError::SessionRecordingFailed) => {
                        return Err(WarpgateError::SessionRecordingFailed);
                    }
                    Err(err) => final_result = Err(err),
                    Ok(()) => (),
                }
            }
            // Gated on an empty pipeline: a refinement snapshots the composited
            // surface, which is ahead of anything still awaiting emission — sent
            // sooner, its newer pixels would be overwritten by the older tiles
            // behind it.
            () = refine, if pipeline.is_empty() => {
                for rect in dirty.take_settled(Instant::now()) {
                    // `None`: the region left the surface (resize) or failed to encode.
                    if let Some(event) = session.refinement(rect).await {
                        debug!(?rect, "Refining settled region");
                        if let Err(WarpgateError::SessionRecordingFailed) =
                            emit(session, recorder.as_deref(), event, None).await
                        {
                            return Err(WarpgateError::SessionRecordingFailed);
                        }
                    } else {
                        debug!(?rect, "Settled region no longer refinable");
                    }
                }
            }
        }
    }
    // Backend ended; dropping `recorder` here finalises the recording.
    drop(recorder);
    final_result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A recording whose start fails for real: recordings on, `--recordings-keep-group-read`
    /// with files secured, and the session's directory under the recordings root a
    /// symlink, which the start refuses to follow.
    mod unrecorded {
        use std::sync::atomic::{AtomicBool, Ordering};

        use sea_orm::ActiveValue::Set;
        use sea_orm::{ActiveModelTrait, Database, IntoActiveModel};
        use uuid::Uuid;
        use warpgate_common::GlobalParams;
        use warpgate_db_entities::Parameters::{
            self, ConfigMigrationValues, RecordingsDiskConfig, RecordingsStorageConfig,
            set_config_migration_values,
        };
        use warpgate_db_migrations::migrate_database;

        use super::*;

        async fn failing_recordings(
            dir: &std::path::Path,
            id: &TargetSessionId,
            refuse: bool,
        ) -> SessionRecordings {
            set_config_migration_values(ConfigMigrationValues::default());
            let db = Database::connect("sqlite::memory:").await.unwrap();
            migrate_database(&db).await.unwrap();
            let root = dir.join("recordings");
            std::fs::create_dir_all(&root).unwrap();
            std::fs::create_dir_all(dir.join("elsewhere")).unwrap();
            std::os::unix::fs::symlink(dir.join("elsewhere"), root.join(id.to_string())).unwrap();
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
            let params = GlobalParams::new(dir.join("warpgate.yaml"), true)
                .unwrap()
                .with_recordings_keep_group_read(true)
                .with_refuse_unrecorded_sessions(refuse);
            SessionRecordings::new(db, &params)
        }

        /// Whether the backend was dialled, and the outcome.
        async fn dial_with_failing_recording(refuse: bool) -> (bool, Result<(), WarpgateError>) {
            let dir = tempfile::tempdir().unwrap();
            let id = TargetSessionId(Uuid::new_v4());
            let recordings = failing_recordings(dir.path(), &id, refuse).await;
            let dialled = AtomicBool::new(false);
            let owner = RecordingOwner {
                protocol: "web-desktop",
                user: "alice".into(),
                target: "desktop".into(),
            };
            let result = record_then_dial(&recordings, &owner, &id, || {
                dialled.store(true, Ordering::SeqCst);
                // The dial's own outcome does not matter here.
                Err(WarpgateError::InvalidTarget)
            })
            .await
            .map(|_| ());
            (dialled.load(Ordering::SeqCst), result)
        }

        #[tokio::test]
        async fn a_refused_desktop_session_never_dials_the_backend() {
            let (dialled, result) = dial_with_failing_recording(true).await;
            assert!(
                !dialled,
                "the backend was dialled with its stored credentials"
            );
            assert!(matches!(result, Err(WarpgateError::SessionNotRecorded)));
        }

        #[tokio::test]
        async fn with_refusal_off_the_desktop_session_dials_unrecorded() {
            let (dialled, result) = dial_with_failing_recording(false).await;
            assert!(dialled);
            assert!(matches!(result, Err(WarpgateError::InvalidTarget)));
        }
    }

    #[test]
    fn vnc_tiles_are_jpeg_encoded_like_rdp() {
        // VNC once shipped its decoded rects raw: ~100 MB on the websocket for 4.9 MiB
        // from Xvnc.
        assert!(encodes_jpeg(TargetKind::Vnc));
        assert!(encodes_jpeg(TargetKind::Rdp));
    }
}
