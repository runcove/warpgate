use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use bytes::Bytes;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::{Mutex, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::info;
use uuid::Uuid;
use warpgate_common::{TargetSSHOptions, TargetSessionId, UserSessionId, WarpgateError};
use warpgate_core::WarpgateServerHandle;
use warpgate_core::recordings::{RecordingOwner, SessionRecordings, TerminalRecorder};
use warpgate_db_entities::Target::TargetKind;
use warpgate_protocol_ssh::{
    ChannelAudit, ChannelOperation, PtyRequest, RCCommand, RCCommandReply, SshClientError,
    SshRecordingMetadata,
};
use warpgate_web_clients_common::{ManagedSession, Sheddable, WebSession};

use crate::protocol::ServerMessage;

/// Terminal output ring: the byte stream is droppable, so an idle/slow client's backlog is
/// capped at the most recent [`OUTPUT_BUFFER_CAPACITY`] output messages.
const OUTPUT_BUFFER_CAPACITY: usize = 2048;

impl Sheddable for ServerMessage {
    fn is_droppable(&self) -> bool {
        matches!(self, Self::Output { .. })
    }
}

pub struct PendingHostKey {
    pub reply: oneshot::Sender<bool>,
}

pub struct WebSshSession {
    core: WebSession<ServerMessage>,

    command_tx: UnboundedSender<(RCCommand, Option<RCCommandReply>)>,

    channel_counter: Arc<AtomicUsize>,
    /// Named on a failed recording's log line.
    username: String,
    /// Bound once the target is admitted; recordings need it, so no channel is opened before.
    target_session_id: OnceLock<TargetSessionId>,
    recordings: Arc<SessionRecordings>,
    channel_audits: Arc<Mutex<HashMap<Uuid, ChannelAudit>>>,
    pending_host_key: Arc<Mutex<Option<PendingHostKey>>>,
    /// Set once the session is closed because its recording failed or could not
    /// start: from then on no input, output or resize passes, even before the close
    /// takes effect.
    closed_for_recording_failure: AtomicBool,
}

impl WebSshSession {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: UserSessionId,
        user_id: Uuid,
        username: String,
        target_name: String,
        target_kind: TargetKind,
        server_handle: Arc<Mutex<WarpgateServerHandle>>,
        cancel: CancellationToken,
        command_tx: UnboundedSender<(RCCommand, Option<RCCommandReply>)>,
        recordings: Arc<SessionRecordings>,
    ) -> Self {
        Self {
            username,
            core: WebSession::new(
                id,
                user_id,
                target_name,
                target_kind,
                server_handle,
                cancel,
                OUTPUT_BUFFER_CAPACITY,
                OUTPUT_BUFFER_CAPACITY,
            ),
            command_tx,
            channel_counter: Arc::new(AtomicUsize::new(0)),
            target_session_id: OnceLock::new(),
            recordings,
            channel_audits: Arc::new(Mutex::new(HashMap::new())),
            pending_host_key: Arc::new(Mutex::new(None)),
            closed_for_recording_failure: AtomicBool::new(false),
        }
    }

    pub fn bind_target_session(&self, id: TargetSessionId) {
        let _ = self.target_session_id.set(id);
    }

    pub async fn set_pending_host_key(&self, pending: PendingHostKey) {
        *self.pending_host_key.lock().await = Some(pending);
    }

    pub async fn take_pending_host_key(&self) -> Option<PendingHostKey> {
        self.pending_host_key.lock().await.take()
    }

    pub fn connect(&self, chain: Vec<TargetSSHOptions>) {
        let _ = self.command_tx.send((RCCommand::Connect(chain), None));
    }

    async fn start_recording(
        &self,
        target_session_id: &TargetSessionId,
    ) -> Result<Option<TerminalRecorder>, WarpgateError> {
        let channel_number = self
            .channel_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let owner = RecordingOwner {
            protocol: "web-ssh",
            user: self.username.clone(),
            target: self.core.target_name().to_owned(),
        };
        start_shell_recording(&self.recordings, &owner, target_session_id, channel_number).await
    }

    pub async fn end_channel(&self, channel_id: Uuid) {
        self.channel_audits.lock().await.remove(&channel_id);
    }

    fn command(&self, cmd: RCCommand) -> Option<oneshot::Receiver<Result<(), SshClientError>>> {
        let (tx, rx) = oneshot::channel();

        if self.command_tx.send((cmd, Some(tx))).is_err() {
            return None;
        }

        Some(rx)
    }

    pub async fn open_shell_channel(&self, cols: u32, rows: u32) -> Option<Uuid> {
        if self.closed_for_recording_failure() {
            return None;
        }
        let target_session_id = self.target_session_id.get()?;
        let started = self.start_recording(target_session_id).await;
        self.open_recorded_shell_channel(cols, rows, started).await
    }

    /// [`Self::open_shell_channel`] once its recording has started (or failed to).
    /// When unrecorded sessions are refused, the recording's first writes are waited
    /// for, so a recording that cannot be written ends the session before the shell is
    /// opened on the target.
    async fn open_recorded_shell_channel(
        &self,
        cols: u32,
        rows: u32,
        started: Result<Option<TerminalRecorder>, WarpgateError>,
    ) -> Option<Uuid> {
        let channel_id = Uuid::new_v4();

        info!(session=%self.id(), channel=%channel_id, "Opening session channel");

        let pty_request = make_pty_request(cols, rows);
        let mut audit = ChannelAudit::new(channel_id);
        let (cols, rows) = pty_request.screen_size();
        audit.start_command_detection(cols, rows);
        match started {
            Ok(Some(recorder)) => audit.set_recorder(recorder),
            Ok(None) => (),
            // Refused before the shell is opened on the target: closed as for a failure
            // mid-session, with the refusal's own text.
            Err(error) => {
                self.close_for_recording(error).await;
                return None;
            }
        }
        // seeds the recording with the initial screen size
        if audit.on_resize(&pty_request).await.is_break()
            || (self.recordings.refuses_unrecorded_sessions()
                && audit.write_recording_header().await.is_break())
        {
            self.close_on_recording_failure().await;
            return None;
        }
        let mut audits = self.channel_audits.lock().await;
        // The session may have been closed for another channel's recording while this
        // recording started, its first writes were awaited or the lock was: then no shell
        // is opened. The lock is held until the shell is requested, so a close by
        // input, output or a resize comes after it.
        if self.closed_for_recording_failure() {
            return None;
        }
        audits.insert(channel_id, audit);

        self.command(RCCommand::Channel(channel_id, ChannelOperation::OpenShell));
        self.command(RCCommand::Channel(
            channel_id,
            ChannelOperation::RequestPty(pty_request),
        ));
        self.command(RCCommand::Channel(
            channel_id,
            ChannelOperation::RequestShell,
        ));
        drop(audits);
        Some(channel_id)
    }

    pub async fn send_input(&self, channel_id: Uuid, data: Bytes) {
        if self.closed_for_recording_failure() {
            return;
        }
        let mut audits = self.channel_audits.lock().await;
        // A close that ran while the lock was awaited has removed nothing: check again.
        if self.closed_for_recording_failure() {
            return;
        }
        if let Some(audit) = audits.get_mut(&channel_id)
            && audit.on_input(&data).await.is_break()
        {
            self.close_on_recording_failure().await;
            return;
        }
        self.command(RCCommand::Channel(channel_id, ChannelOperation::Data(data)));
    }

    /// Records the target's output. `false` when the recording failed and the session
    /// was closed: the output must then not reach the viewer.
    #[must_use]
    pub async fn on_output(&self, channel_id: Uuid, data: &[u8]) -> bool {
        if self.closed_for_recording_failure() {
            return false;
        }
        let mut audits = self.channel_audits.lock().await;
        if self.closed_for_recording_failure() {
            return false;
        }
        if let Some(audit) = audits.get_mut(&channel_id)
            && audit.on_output(data).await.is_break()
        {
            self.close_on_recording_failure().await;
            return false;
        }
        true
    }

    pub async fn resize_channel(&self, channel_id: Uuid, cols: u32, rows: u32) {
        if self.closed_for_recording_failure() {
            return;
        }
        let pty_request = make_pty_request(cols, rows);
        let mut audits = self.channel_audits.lock().await;
        if self.closed_for_recording_failure() {
            return;
        }
        if let Some(audit) = audits.get_mut(&channel_id)
            && audit.on_resize(&pty_request).await.is_break()
        {
            self.close_on_recording_failure().await;
            return;
        }
        self.command(RCCommand::Channel(
            channel_id,
            ChannelOperation::ResizePty(pty_request),
        ));
    }

    /// A recording failed mid-session (logged by its recorder) and unrecorded
    /// sessions are refused: tell the viewer, then end the session. Its failed
    /// recorder is gone once this has run, so from here on nothing more is
    /// forwarded either way, and the target connection is told to disconnect
    /// before the abort is relayed.
    async fn close_on_recording_failure(&self) {
        self.close_for_recording(WarpgateError::SessionRecordingFailed)
            .await;
    }

    /// Closes the session for its recording, once: from here no input, output or
    /// resize passes, the viewer is told `reason`, the target connection is told to
    /// disconnect, and the session is aborted.
    async fn close_for_recording(&self, reason: WarpgateError) {
        if self
            .closed_for_recording_failure
            .swap(true, Ordering::SeqCst)
        {
            return;
        }
        self.push(ServerMessage::Error {
            message: reason.to_string(),
        })
        .await;
        let _ = self.command_tx.send((RCCommand::Disconnect, None));
        self.abort();
    }

    fn closed_for_recording_failure(&self) -> bool {
        self.closed_for_recording_failure.load(Ordering::SeqCst)
    }

    pub fn close_channel(&self, channel_id: Uuid) {
        self.command(RCCommand::Channel(channel_id, ChannelOperation::Close));
    }
}

impl std::ops::Deref for WebSshSession {
    type Target = WebSession<ServerMessage>;
    fn deref(&self) -> &Self::Target {
        &self.core
    }
}

impl ManagedSession for WebSshSession {
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

pub fn make_pty_request(cols: u32, rows: u32) -> PtyRequest {
    PtyRequest {
        term: "xterm-256color".to_owned(),
        col_width: cols,
        row_height: rows,
        pix_width: 0,
        pix_height: 0,
        modes: vec![],
    }
}

/// Start a web SSH shell's recording. `Ok(None)` when recording is disabled. A failure to
/// start is logged (by `start_for`); it is then [`WarpgateError::SessionNotRecorded`] when unrecorded
/// sessions are refused, and `Ok(None)` otherwise (the default).
async fn start_shell_recording(
    recordings: &SessionRecordings,
    owner: &RecordingOwner,
    target_session_id: &TargetSessionId,
    channel_number: usize,
) -> Result<Option<TerminalRecorder>, WarpgateError> {
    match recordings
        .start_for::<TerminalRecorder, _>(
            owner,
            target_session_id,
            None,
            SshRecordingMetadata::Shell {
                channel: channel_number,
            },
        )
        .await
    {
        Ok(recorder) => Ok(recorder),
        Err(_) => {
            if recordings.refuses_unrecorded_sessions() {
                Err(WarpgateError::SessionNotRecorded)
            } else {
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::ActiveValue::Set;
    use sea_orm::{ActiveModelTrait, Database, IntoActiveModel};
    use warpgate_common::GlobalParams;
    use warpgate_db_entities::Parameters::{
        self, ConfigMigrationValues, RecordingsDiskConfig, RecordingsStorageConfig,
        set_config_migration_values,
    };
    use warpgate_db_migrations::migrate_database;

    use super::*;

    /// A recording whose start fails for real: recordings on, `--recordings-keep-group-read`
    /// with files secured, and the session's directory under the recordings root a
    /// symlink, which the start refuses to follow.
    async fn start_failing(refuse: bool) -> Result<Option<TerminalRecorder>, WarpgateError> {
        let dir = tempfile::tempdir().unwrap();
        let id = TargetSessionId(Uuid::new_v4());
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        let root = dir.path().join("recordings");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(dir.path().join("elsewhere")).unwrap();
        std::os::unix::fs::symlink(dir.path().join("elsewhere"), root.join(id.to_string()))
            .unwrap();
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
        let params = GlobalParams::new(dir.path().join("warpgate.yaml"), true)
            .unwrap()
            .with_recordings_keep_group_read(true)
            .with_refuse_unrecorded_sessions(refuse);
        let recordings = SessionRecordings::new(db, &params);
        let owner = RecordingOwner {
            protocol: "web-ssh",
            user: "alice".into(),
            target: "host".into(),
        };
        start_shell_recording(&recordings, &owner, &id, 0).await
    }

    #[tokio::test]
    async fn a_web_shell_whose_recording_fails_is_refused_when_required() {
        assert!(matches!(
            start_failing(true).await,
            Err(WarpgateError::SessionNotRecorded)
        ));
    }

    #[tokio::test]
    async fn with_refusal_off_a_web_shell_continues_unrecorded() {
        assert!(matches!(start_failing(false).await, Ok(None)));
    }
    /// A web shell whose recording started on a real disk root, and fails mid-session
    /// as a full disk would.
    #[cfg(target_os = "linux")]
    mod failing_mid_session {
        use std::time::Duration;

        use tokio::sync::mpsc::UnboundedReceiver;
        use warpgate_core::cluster::Cluster;
        use warpgate_core::rate_limiting::RateLimiterRegistry;
        use warpgate_core::recordings::test_support;
        use warpgate_core::{SessionHandle, State, UserSessionStateInit};

        use super::*;
        use crate::protocol::ServerMessage;

        struct NoopHandle;

        impl SessionHandle for NoopHandle {
            fn close(&mut self) {}
        }

        struct Harness {
            session: WebSshSession,
            sent: UnboundedReceiver<(RCCommand, Option<RCCommandReply>)>,
            recordings: Arc<SessionRecordings>,
            id: TargetSessionId,
            channel: Uuid,
            required: bool,
            /// `RCCommand::Disconnect`s seen by [`Harness::data_sent`].
            disconnects: usize,
            _dir: tempfile::TempDir,
        }

        /// A web SSH session bound to its target session, no channel open yet.
        async fn bound_shell(refuse: bool) -> Harness {
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
                warpgate_protocol_ssh::PROTOCOL_NAME,
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

            let (command_tx, sent) = tokio::sync::mpsc::unbounded_channel();
            let session = WebSshSession::new(
                user_session,
                Uuid::new_v4(),
                "alice".into(),
                "host".into(),
                TargetKind::Ssh,
                server_handle,
                CancellationToken::new(),
                command_tx,
                recordings.clone(),
            );
            session.bind_target_session(id);
            Harness {
                session,
                sent,
                recordings,
                id,
                channel: Uuid::nil(),
                required: refuse,
                disconnects: 0,
                _dir: dir,
            }
        }

        /// A web shell whose recording started and works.
        async fn recorded_shell(refuse: bool) -> Harness {
            let mut h = bound_shell(refuse).await;
            h.channel = h.session.open_shell_channel(80, 24).await.unwrap();
            while h.sent.try_recv().is_ok() {}
            h
        }

        async fn shell_failing_mid_session(refuse: bool) -> Harness {
            let h = recorded_shell(refuse).await;
            assert!(h.fail_recordings() >= 2, "the data and index files were broken");
            h
        }

        impl Harness {
            /// Fails the open recording files, as a full disk would.
            fn fail_recordings(&self) -> usize {
                test_support::fail_open_recording_files(&self._dir.path().join("recordings"))
            }

            fn sent_commands(&mut self) -> Vec<RCCommand> {
                let mut commands = Vec::new();
                while let Ok((command, _)) = self.sent.try_recv() {
                    commands.push(command);
                }
                commands
            }

            fn aborted(&self) -> bool {
                self.session.cancellation().is_cancelled()
            }

            fn data_sent(&mut self) -> usize {
                let mut n = 0;
                while let Ok((command, _)) = self.sent.try_recv() {
                    match command {
                        RCCommand::Channel(_, ChannelOperation::Data(_)) => n += 1,
                        RCCommand::Disconnect => self.disconnects += 1,
                        _ => (),
                    }
                }
                n
            }

            /// Sends input until the failure is seen (writes are queued, so the first
            /// ones after the break can still be accepted). Returns how many inputs
            /// were sent and how many reached the target.
            async fn input_until_failure(&mut self) -> (usize, usize) {
                let (mut inputs, mut forwarded) = (0, 0);
                for _ in 0..1000 {
                    self.session
                        .send_input(self.channel, Bytes::from_static(b"input"))
                        .await;
                    inputs += 1;
                    forwarded += self.data_sent();
                    // The recorder's own task logs the failure as soon as it happens;
                    // the session sees it at its next write. So when required, wait
                    // for the abort; otherwise for the log line.
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

            async fn told_the_viewer(&self) -> bool {
                let reason = WarpgateError::SessionRecordingFailed.to_string();
                self.session
                    .drain_buffer()
                    .await
                    .iter()
                    .any(|m| matches!(m, ServerMessage::Error { message } if *message == reason))
            }

            fn assert_one_failure_line(&self, required: bool) {
                assert_eq!(self.recordings.failed_recordings(), 1);
                let lines = test_support::failed_recording_lines(&self.id);
                assert_eq!(lines.len(), 1, "{lines:?}");
                assert_eq!(lines[0]["protocol"], "web-ssh");
                assert_eq!(lines[0]["user"], "alice");
                assert_eq!(lines[0]["target"], "host");
                assert_eq!(lines[0]["stage"], "write");
                assert_eq!(lines[0]["required"], required.to_string());
            }
        }

        /// Required: input whose recording fails ends the session and never reaches
        /// the target.
        #[tokio::test]
        async fn input_whose_recording_fails_aborts_the_session_when_required() {
            let mut h = shell_failing_mid_session(true).await;
            let (inputs, forwarded) = h.input_until_failure().await;
            assert!(h.aborted(), "the session is aborted");
            assert_eq!(
                forwarded,
                inputs - 1,
                "the input whose recording failed was not forwarded"
            );
            assert_eq!(h.disconnects, 1, "the target was told to disconnect");
            // The failed recorder is gone now; later input, resize and output must
            // still not pass while the close takes effect.
            h.session
                .send_input(h.channel, Bytes::from_static(b"after"))
                .await;
            h.session.resize_channel(h.channel, 100, 30).await;
            assert!(!h.session.on_output(h.channel, b"after").await);
            let mut after = Vec::new();
            while let Ok((command, _)) = h.sent.try_recv() {
                after.push(command);
            }
            assert!(
                after.is_empty(),
                "no input or resize was sent after the close: {after:?}"
            );
            assert!(h.told_the_viewer().await);
            h.assert_one_failure_line(true);
        }

        /// Required: output whose recording fails ends the session and is not shown.
        #[tokio::test]
        async fn output_whose_recording_fails_aborts_the_session_when_required() {
            let mut h = shell_failing_mid_session(true).await;
            let mut shown = true;
            for _ in 0..1000 {
                shown = h.session.on_output(h.channel, b"output").await;
                if !shown {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            assert!(!shown, "the output whose recording failed is not shown");
            assert!(h.aborted(), "the session is aborted");
            assert!(
                !h.session.on_output(h.channel, b"after").await,
                "later output is not shown either"
            );
            h.session
                .send_input(h.channel, Bytes::from_static(b"after"))
                .await;
            assert_eq!(h.data_sent(), 0, "no input after the failure was forwarded");
            assert!(h.told_the_viewer().await);
            h.assert_one_failure_line(true);
        }

        /// Not required (the default): the session goes on unrecorded and every input
        /// reaches the target; the failure is logged and counted once.
        #[tokio::test]
        async fn with_refusal_off_a_failing_recording_aborts_nothing() {
            let mut h = shell_failing_mid_session(false).await;
            let (inputs, forwarded) = h.input_until_failure().await;
            assert_eq!(forwarded, inputs, "every input was forwarded");
            assert!(h.session.on_output(h.channel, b"output").await);
            h.session
                .send_input(h.channel, Bytes::from_static(b"more"))
                .await;
            assert_eq!(h.data_sent(), 1);
            assert!(!h.aborted(), "the session goes on");
            h.assert_one_failure_line(false);
        }

        /// A shell whose recording starts on files that cannot be written (a full
        /// disk). Required: the session ends before the shell is opened on the
        /// target. Otherwise the shell opens, its first writes not waited for.
        #[tokio::test]
        async fn a_web_shell_that_cannot_be_recorded_follows_the_setting_at_start() {
            for required in [true, false] {
                let mut h = bound_shell(required).await;
                let started = h.session.start_recording(&h.id).await;
                assert!(h.fail_recordings() >= 2);
                let opened = h.session.open_recorded_shell_channel(80, 24, started).await;
                let commands = h.sent_commands();
                let shell_opened = commands
                    .iter()
                    .any(|c| matches!(c, RCCommand::Channel(_, ChannelOperation::OpenShell)));
                if required {
                    assert!(opened.is_none(), "refused at start");
                    assert!(!shell_opened, "the shell was opened: {commands:?}");
                    assert!(h.aborted(), "the session is aborted");
                    assert!(h.told_the_viewer().await);
                    h.assert_one_failure_line(true);
                } else {
                    assert!(opened.is_some());
                    assert!(shell_opened, "{commands:?}");
                    assert!(!h.aborted());
                }
            }
        }

        /// A shell whose recording could not start, when required: closed as for a
        /// failure mid-session. No shell is opened, the viewer is told the refusal, the
        /// target is told to disconnect, and nothing more passes.
        #[tokio::test]
        async fn a_web_shell_refused_at_start_closes_as_for_a_failure() {
            let mut h = bound_shell(true).await;
            let opened = h
                .session
                .open_recorded_shell_channel(80, 24, Err(WarpgateError::SessionNotRecorded))
                .await;
            assert!(opened.is_none());
            assert!(h.aborted());
            assert!(h.session.closed_for_recording_failure());
            let commands = h.sent_commands();
            assert!(
                matches!(commands.as_slice(), [RCCommand::Disconnect]),
                "{commands:?}"
            );
            let reason = WarpgateError::SessionNotRecorded.to_string();
            assert!(
                h.session
                    .drain_buffer()
                    .await
                    .iter()
                    .any(|m| matches!(m, ServerMessage::Error { message } if *message == reason))
            );

            let channel = Uuid::new_v4();
            h.session
                .send_input(channel, Bytes::from_static(b"input"))
                .await;
            h.session.resize_channel(channel, 100, 30).await;
            assert!(!h.session.on_output(channel, b"output").await);
            assert!(h.session.open_shell_channel(80, 24).await.is_none());
            let commands = h.sent_commands();
            assert!(commands.is_empty(), "sent to the target: {commands:?}");
        }

        /// Once the session was closed for its recording, no new shell is opened.
        #[tokio::test]
        async fn once_closed_for_its_recording_no_new_shell_opens() {
            let mut h = shell_failing_mid_session(true).await;
            h.input_until_failure().await;
            assert!(h.aborted());
            h.sent_commands();
            assert!(h.session.open_shell_channel(80, 24).await.is_none());
            let commands = h.sent_commands();
            assert!(commands.is_empty(), "sent to the target: {commands:?}");
        }

        /// A close for another channel's recording that runs while a new shell's
        /// recording starts, or while the shell waits for the channel lock: no shell is
        /// opened on the target.
        #[tokio::test]
        async fn a_close_while_a_shell_opens_opens_no_shell() {
            for while_waiting_for_the_lock in [false, true] {
                let mut h = bound_shell(true).await;
                let session = &h.session;
                let started = session.start_recording(&h.id).await;
                assert!(matches!(started, Ok(Some(_))), "the recording started");
                let opened = if while_waiting_for_the_lock {
                    let guard = session.channel_audits.lock().await;
                    let open = session.open_recorded_shell_channel(80, 24, started);
                    let close = async move {
                        // Time for the shell's first writes, so it waits on the lock when
                        // the close runs. On a slower machine the close can land during
                        // those writes instead: a weaker case, never a wrong failure.
                        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                        session.close_on_recording_failure().await;
                        drop(guard);
                    };
                    tokio::join!(open, close).0
                } else {
                    session.close_on_recording_failure().await;
                    session.open_recorded_shell_channel(80, 24, started).await
                };
                assert!(opened.is_none(), "a shell was opened");
                let forwarded: Vec<_> = h
                    .sent_commands()
                    .into_iter()
                    .filter(|c| !matches!(c, RCCommand::Disconnect))
                    .collect();
                assert!(forwarded.is_empty(), "sent to the target: {forwarded:?}");
                assert!(h.session.channel_audits.lock().await.is_empty());
            }
        }

        /// A close that runs while input, output or a resize waits for the channel
        /// lock: once that has the lock, it passes nothing.
        #[tokio::test]
        async fn a_close_while_waiting_for_the_channel_lock_passes_nothing() {
            for op in ["input", "output", "resize"] {
                let mut h = recorded_shell(true).await;
                let (session, channel) = (&h.session, h.channel);
                let guard = session.channel_audits.lock().await;
                let passed = async {
                    match op {
                        "input" => {
                            session
                                .send_input(channel, Bytes::from_static(b"input"))
                                .await;
                            true
                        }
                        "output" => session.on_output(channel, b"output").await,
                        _ => {
                            session.resize_channel(channel, 100, 30).await;
                            true
                        }
                    }
                };
                let close = async move {
                    tokio::task::yield_now().await;
                    session.close_on_recording_failure().await;
                    drop(guard);
                };
                let (passed, ()) = tokio::join!(passed, close);
                let forwarded: Vec<_> = h
                    .sent_commands()
                    .into_iter()
                    .filter(|c| !matches!(c, RCCommand::Disconnect))
                    .collect();
                assert!(forwarded.is_empty(), "{op} reached the target: {forwarded:?}");
                assert!(op != "output" || !passed, "the output was shown");
            }
        }
    }
}
