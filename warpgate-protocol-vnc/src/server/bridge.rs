//! The authorized VNC proxy session: the single decode-and-re-encode loop that pumps
//! backend framebuffer updates to the viewer as RFB, forwards viewer input to the backend,
//! and records both. Recording is transparent — recorded and unrecorded sessions share this
//! path.

use std::collections::VecDeque;

use anyhow::{Result, anyhow, bail};
use tokio::io::AsyncWrite;
use tokio::sync::mpsc;
use tracing::warn;
use warpgate_common::WarpgateError;
use warpgate_core::recordings::DesktopRecorder;
use warpgate_core::{DesktopEvent, DesktopInput, DesktopState};

use super::protocol::{
    ClientEvent, pack_bgra, write_desktop_size, write_raw_rect, write_server_cut_text,
    write_tight_jpeg_rect,
};
use super::{ProxySession, RenderState};

/// Record an event. No-op when recording is disabled (`None`). A failed write is
/// reported once by the recorder; it is an error, which ends the session, only when
/// unrecorded sessions are refused.
async fn record_event(recorder: Option<&DesktopRecorder>, event: &DesktopEvent) -> Result<()> {
    if let Some(recorder) = recorder
        && let Err(error) = recorder.write_event(event).await
    {
        return check_recording(recorder, &error);
    }
    Ok(())
}

/// Record a viewer input, before it is forwarded. As [`record_event`].
async fn record_input(recorder: Option<&DesktopRecorder>, input: &DesktopInput) -> Result<()> {
    if let Some(recorder) = recorder
        && let Err(error) = recorder.write_input(input).await
    {
        return check_recording(recorder, &error);
    }
    Ok(())
}

fn check_recording(
    recorder: &DesktopRecorder,
    error: &warpgate_core::recordings::Error,
) -> Result<()> {
    if recorder.write_failed(error) {
        warn!("Closing the VNC session: its recording failed");
        return Err(WarpgateError::SessionRecordingFailed.into());
    }
    Ok(())
}

/// Drain backend events until the first [`DesktopEvent::Resize`] reveals the framebuffer
/// geometry, recording each consumed event. The backend client always emits `Resize`
/// before any `RawImage`, so nothing visible is consumed here.
pub(super) async fn wait_for_backend_size(
    event_rx: &mut mpsc::Receiver<DesktopEvent>,
    recorder: Option<&DesktopRecorder>,
) -> Result<(u16, u16)> {
    while let Some(event) = event_rx.recv().await {
        record_event(recorder, &event).await?;
        match event {
            DesktopEvent::Resize { width, height } => return Ok((width, height)),
            DesktopEvent::Error(message) => bail!("backend error before first frame: {message}"),
            DesktopEvent::State(DesktopState::Disconnected) => {
                bail!("backend disconnected before first frame")
            }
            _ => {}
        }
    }
    bail!("backend channel closed before first frame")
}

/// Re-encode one queued backend frame toward the viewer in response to an outstanding
/// `FramebufferUpdateRequest`. Clears `pending_request` once a frame is actually sent.
async fn flush_frame<W>(
    viewer_wr: &mut W,
    render: &mut RenderState,
    event: DesktopEvent,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    match event {
        DesktopEvent::RawImage { rect, data } => {
            let pixels = pack_bgra(&render.caps.pixel_format, &data);
            write_raw_rect(viewer_wr, rect.x, rect.y, rect.width, rect.height, &pixels).await?;
            render.pending_request = false;
        }
        // The backend compressed this rect with Tight's JPEG sub-encoding. The viewer
        // negotiated Tight, so it decodes JPEG itself — forward the bytes straight through
        // as a Tight/JPEG rect rather than decoding and re-encoding as (much larger) Raw.
        DesktopEvent::JpegImage { rect, data } if render.caps.viewer_supports_tight => {
            write_tight_jpeg_rect(viewer_wr, rect.x, rect.y, rect.width, rect.height, &data)
                .await?;
            render.pending_request = false;
        }
        // A viewer that requested Tight is universal; if one somehow didn't, we can't
        // proxy the backend's JPEG without a decoder, so skip the rect (it stays stale
        // until the next full frame) rather than carrying a JPEG decoder for this.
        DesktopEvent::JpegImage { .. } => {
            warn!("viewer did not negotiate Tight; dropping backend JPEG rect");
            render.pending_request = false;
        }
        DesktopEvent::Resize { width, height } if render.caps.supports_desktop_size => {
            write_desktop_size(viewer_wr, width, height).await?;
            render.pending_request = false;
        }
        // A resize the viewer can't be told about: drop it but keep the request pending
        // so the next real frame still satisfies it. Other variants never reach the queue.
        _ => {}
    }
    Ok(())
}

/// The decode-and-re-encode loop: pump backend `DesktopEvent`s to the viewer as RFB
/// (recording each), and forward viewer input back to the backend. Lockstep — at most
/// one rect per `FramebufferUpdateRequest` — with a bounded queue providing end-to-end
/// backpressure when the viewer is slow. Dropping the recorder finalises the recording.
pub(super) async fn run_proxy_session(session: ProxySession) -> Result<()> {
    /// Bound on queued-but-unflushed backend frames before we stop draining the backend.
    const QUEUE_CAP: usize = 256;

    let ProxySession {
        mut viewer_wr,
        mut viewer_events,
        reader,
        stop_tx,
        mut render,
        backend,
        recorder,
    } = session;
    let warpgate_core::DesktopClientHandles {
        mut event_rx,
        input_tx,
        abort_tx,
        logon_state: _,
    } = backend;

    let mut queue: VecDeque<DesktopEvent> = VecDeque::new();

    let result = loop {
        // Satisfy an outstanding request with one queued frame before blocking again.
        if render.pending_request
            && let Some(event) = queue.pop_front()
        {
            if let Err(error) = flush_frame(&mut viewer_wr, &mut render, event).await {
                break Err(error);
            }
            continue;
        }

        tokio::select! {
            biased;

            // Viewer → us: input to forward, plus pixel-format/encoding/refresh updates.
            event = viewer_events.recv() => {
                match event {
                    Some(ClientEvent::WantsFrame) => render.pending_request = true,
                    Some(ClientEvent::PixelFormat(pf)) => render.caps.pixel_format = pf,
                    Some(ClientEvent::Encodings {
                        desktop_size,
                        tight,
                    }) => {
                        render.caps.supports_desktop_size = desktop_size;
                        render.caps.viewer_supports_tight = tight;
                    }
                    Some(ClientEvent::Key { down, keysym }) => {
                        let input = DesktopInput::Key {
                            keysym: Some(keysym),
                            scancode: None,
                            down,
                        };
                        if let Err(error) = record_input(recorder.as_ref(), &input).await {
                            break Err(error);
                        }
                        if input_tx.send(input).await.is_err() {
                            break Ok(());
                        }
                    }
                    Some(ClientEvent::Pointer { x, y, buttons }) => {
                        let input = DesktopInput::Pointer { x, y, buttons };
                        if let Err(error) = record_input(recorder.as_ref(), &input).await {
                            break Err(error);
                        }
                        if input_tx.send(input).await.is_err() {
                            break Ok(());
                        }
                    }
                    Some(ClientEvent::Clipboard(text)) => {
                        let input = DesktopInput::Clipboard(text);
                        if let Err(error) = record_input(recorder.as_ref(), &input).await {
                            break Err(error);
                        }
                        let _ = input_tx.send(input).await;
                    }
                    None => break Ok(()), // viewer disconnected
                }
            }

            // Backend → us: record every event, queue frames, mirror clipboard. Gated so
            // a slow viewer back-pressures the backend instead of growing the queue.
            event = event_rx.recv(), if queue.len() < QUEUE_CAP => {
                match event {
                    Some(event) => {
                        if let Err(error) = record_event(recorder.as_ref(), &event).await {
                            break Err(error);
                        }
                        match event {
                            DesktopEvent::RawImage { .. }
                            | DesktopEvent::JpegImage { .. }
                            | DesktopEvent::Resize { .. } => {
                                queue.push_back(event);
                            }
                            DesktopEvent::Clipboard(text) => {
                                if let Err(error) = write_server_cut_text(&mut viewer_wr, &text).await {
                                    break Err(error);
                                }
                            }
                            DesktopEvent::State(DesktopState::Disconnected) => break Ok(()),
                            DesktopEvent::Error(message) => break Err(anyhow!("backend error: {message}")),
                            // PROXY_ENCODINGS rules out CopyRect/Cursor; Bell/Cursor ignored.
                            _ => {}
                        }
                    }
                    None => break Ok(()), // backend ended
                }
            }
        }
    };

    // Teardown: stop the viewer reader and the backend client. Dropping `recorder`
    // (held until here) finalises the recording.
    let _ = stop_tx.send(());
    let _ = abort_tx.send(());
    reader.abort();
    drop(recorder);

    result
}

// Every test here fails a recording through `/proc/self/fd`.
#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use sea_orm::ActiveValue::Set;
    use sea_orm::{ActiveModelTrait, Database, IntoActiveModel};
    use tokio::sync::Mutex;
    use tokio::sync::mpsc::{Receiver, Sender, UnboundedReceiver, UnboundedSender};
    use tokio::task::JoinHandle;
    use uuid::Uuid;
    use warpgate_common::{GlobalParams, TargetSessionId};
    use warpgate_core::cluster::Cluster;
    use warpgate_core::rate_limiting::RateLimiterRegistry;
    use warpgate_core::recordings::{
        DesktopRecordingMetadata, RecordingOwner, SessionRecordings, test_support,
    };
    use warpgate_core::{
        DesktopClientHandles, DesktopRect, LogonState, SessionHandle, State, UserSessionStateInit,
    };
    use warpgate_db_entities::Parameters::{
        self, ConfigMigrationValues, RecordingsDiskConfig, RecordingsStorageConfig,
        set_config_migration_values,
    };
    use warpgate_db_migrations::migrate_database;

    use super::*;
    use crate::server::ViewerStream;

    struct NoopHandle;

    impl SessionHandle for NoopHandle {
        fn close(&mut self) {}
    }

    /// A native VNC session's recording, started on a real disk root, whose files
    /// then fail as a full disk would.
    struct Recording {
        recorder: DesktopRecorder,
        recordings: Arc<SessionRecordings>,
        id: TargetSessionId,
        _dir: tempfile::TempDir,
    }

    impl Recording {
        fn failures(&self) -> u64 {
            self.recordings.failed_recordings()
        }
    }

    async fn failing_recording(refuse: bool) -> Recording {
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
        parameters.recordings_storage = Set(serde_json::to_string(&RecordingsStorageConfig::Disk(
            RecordingsDiskConfig {
                path: "recordings".into(),
            },
        ))
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
            warpgate_common::Protocol::Vnc,
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
            protocol: "vnc",
            user: "alice".into(),
            target: "desktop".into(),
        };
        let recorder = recordings
            .start_for::<DesktopRecorder, _>(&owner, &id, None, DesktopRecordingMetadata::Desktop)
            .await
            .unwrap()
            .unwrap();
        assert!(
            test_support::fail_open_recording_files(&dir.path().join("recordings")) >= 2,
            "the data and index files were broken"
        );
        Recording {
            recorder,
            recordings,
            id,
            _dir: dir,
        }
    }

    fn assert_one_failure_line(
        recordings: &SessionRecordings,
        id: &TargetSessionId,
        required: bool,
    ) {
        assert_eq!(recordings.failed_recordings(), 1);
        let lines = test_support::failed_recording_lines(id);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert_eq!(lines[0]["protocol"], "vnc");
        assert_eq!(lines[0]["stage"], "write");
        assert_eq!(lines[0]["required"], required.to_string());
    }

    /// A backend event the recorder writes at once (a `Resize` would end
    /// [`wait_for_backend_size`] before its write could fail).
    const fn copy_rect() -> DesktopEvent {
        DesktopEvent::CopyRect {
            dst: DesktopRect {
                x: 0,
                y: 0,
                width: 1,
                height: 1,
            },
            src_x: 0,
            src_y: 0,
        }
    }

    fn is_recording_failed(result: &Result<impl Sized>) -> bool {
        result.as_ref().is_err_and(|error| {
            matches!(
                error.downcast_ref::<WarpgateError>(),
                Some(WarpgateError::SessionRecordingFailed)
            )
        })
    }

    /// Required: the wait for the backend's first frame ends with
    /// `SessionRecordingFailed` once an event's recording fails. Not required: it
    /// goes on, and returns the size the backend then reports.
    #[tokio::test]
    async fn the_wait_for_the_first_frame_follows_the_setting_when_recording_fails() {
        for required in [true, false] {
            let r = failing_recording(required).await;
            let (event_tx, mut event_rx) = mpsc::channel(16);
            let feed = async {
                for _ in 0..1000 {
                    if event_tx.send(copy_rect()).await.is_err() {
                        break;
                    }
                    if !required && r.failures() > 0 {
                        event_tx
                            .send(DesktopEvent::Resize {
                                width: 640,
                                height: 480,
                            })
                            .await
                            .unwrap();
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                // Closing the channel ends a wait that ignored the failure.
                drop(event_tx);
                std::future::pending::<()>().await;
            };
            let result = tokio::select! {
                result = wait_for_backend_size(&mut event_rx, Some(&r.recorder)) => result,
                () = feed => unreachable!(),
            };
            if required {
                assert!(is_recording_failed(&result), "{result:?}");
            } else {
                assert_eq!(result.unwrap(), (640, 480));
            }
            assert_one_failure_line(&r.recordings, &r.id, required);
        }
    }

    /// A [`ProxySession`] over an in-memory viewer, and the ends of it a test
    /// drives: the viewer's events in, the backend's events in, the inputs
    /// forwarded to the backend, and its abort signal.
    struct Proxy {
        session: JoinHandle<Result<()>>,
        viewer: UnboundedSender<ClientEvent>,
        backend: Sender<DesktopEvent>,
        forwarded: Receiver<DesktopInput>,
        aborted: UnboundedReceiver<()>,
        _viewer_end: tokio::io::DuplexStream,
    }

    fn proxy(recorder: DesktopRecorder) -> Proxy {
        let (ours, viewer_end) = tokio::io::duplex(1 << 16);
        let stream: Box<dyn ViewerStream> = Box::new(ours);
        let (viewer_rd, viewer_wr) = tokio::io::split(stream);
        let (viewer, viewer_events) = mpsc::unbounded_channel();
        let reader = tokio::spawn(async move {
            std::future::pending::<()>().await;
            Ok(viewer_rd)
        });
        let (stop_tx, _stop_rx) = tokio::sync::oneshot::channel();
        let (backend, event_rx) = mpsc::channel(16);
        let (input_tx, forwarded) = mpsc::channel(10_000);
        let (abort_tx, aborted) = mpsc::unbounded_channel();
        let session = ProxySession {
            viewer_wr,
            viewer_events,
            reader,
            stop_tx,
            render: RenderState::new(),
            backend: DesktopClientHandles {
                event_rx,
                input_tx,
                abort_tx,
                logon_state: LogonState::logged_on(),
            },
            recorder: Some(recorder),
        };
        Proxy {
            session: tokio::spawn(run_proxy_session(session)),
            viewer,
            backend,
            forwarded,
            aborted,
            _viewer_end: viewer_end,
        }
    }

    fn pointer() -> ClientEvent {
        ClientEvent::Pointer {
            x: 1,
            y: 1,
            buttons: 0,
        }
    }

    /// Required: viewer input whose recording fails ends the session with
    /// `SessionRecordingFailed`, is not forwarded to the backend, and the backend is
    /// told to disconnect. Not required: every input is forwarded and the session
    /// goes on.
    #[tokio::test]
    async fn viewer_input_whose_recording_fails_follows_the_setting() {
        for required in [true, false] {
            let r = failing_recording(required).await;
            let Recording {
                recorder,
                recordings,
                id,
                _dir,
            } = r;
            let mut p = proxy(recorder);
            let (mut inputs, mut forwarded) = (0, 0);
            let mut ended = None;
            for _ in 0..1000 {
                p.viewer.send(pointer()).unwrap();
                inputs += 1;
                // Each input is either forwarded or ends the session.
                tokio::select! {
                    Some(_) = p.forwarded.recv() => forwarded += 1,
                    result = &mut p.session => {
                        ended = Some(result.unwrap());
                        break;
                    }
                }
                if !required && recordings.failed_recordings() > 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            assert!(
                recordings.failed_recordings() > 0,
                "the recording never failed"
            );
            if required {
                let result = ended.expect("the session ended");
                assert!(is_recording_failed(&result), "{result:?}");
                assert_eq!(
                    forwarded,
                    inputs - 1,
                    "the input whose recording failed was not forwarded"
                );
                assert!(p.aborted.try_recv().is_ok(), "the backend was told to stop");
            } else {
                assert!(ended.is_none(), "the session went on");
                assert_eq!(forwarded, inputs);
                for _ in 0..3 {
                    p.viewer.send(pointer()).unwrap();
                    tokio::time::timeout(Duration::from_secs(5), p.forwarded.recv())
                        .await
                        .expect("forwarded after the failure")
                        .unwrap();
                }
                drop(p.viewer);
                p.session.await.unwrap().unwrap();
            }
            assert_one_failure_line(&recordings, &id, required);
        }
    }

    /// Required: a backend event whose recording fails ends the session with
    /// `SessionRecordingFailed` while the backend is still sending, and the backend
    /// is told to disconnect. Not required: the session goes on until the backend
    /// ends.
    #[tokio::test]
    async fn a_backend_event_whose_recording_fails_follows_the_setting() {
        for required in [true, false] {
            let Recording {
                recorder,
                recordings,
                id,
                _dir,
            } = failing_recording(required).await;
            let mut p = proxy(recorder);
            let mut closed = false;
            for _ in 0..1000 {
                // The session drops its end of the backend's events when it ends.
                if p.backend.send(copy_rect()).await.is_err() {
                    closed = true;
                    break;
                }
                if !required && recordings.failed_recordings() > 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            assert!(
                recordings.failed_recordings() > 0,
                "the recording never failed"
            );
            if required {
                assert!(closed, "the session ended while the backend was sending");
                let result = tokio::time::timeout(Duration::from_secs(5), &mut p.session)
                    .await
                    .expect("the session ended")
                    .unwrap();
                assert!(is_recording_failed(&result), "{result:?}");
                assert!(p.aborted.try_recv().is_ok(), "the backend was told to stop");
            } else {
                assert!(!closed && !p.session.is_finished(), "the session went on");
                for _ in 0..3 {
                    p.backend.send(copy_rect()).await.unwrap();
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
                assert!(!p.session.is_finished(), "the session went on");
                drop(p.backend);
                p.session.await.unwrap().unwrap();
                assert!(
                    p.aborted.try_recv().is_ok(),
                    "torn down at the backend's end"
                );
            }
            assert_one_failure_line(&recordings, &id, required);
        }
    }
}
