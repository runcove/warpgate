use std::collections::HashMap;
use std::sync::atomic::AtomicUsize;
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
        let username_for_recordings = username;
        Self {
            username: username_for_recordings,
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
        let target_session_id = self.target_session_id.get()?;
        let channel_id = Uuid::new_v4();

        info!(session=%self.id(), channel=%channel_id, "Opening session channel");

        let pty_request = make_pty_request(cols, rows);
        let mut audit = ChannelAudit::new(channel_id);
        let (cols, rows) = pty_request.screen_size();
        audit.start_command_detection(cols, rows);
        match self.start_recording(target_session_id).await {
            Ok(Some(recorder)) => audit.set_recorder(recorder),
            Ok(None) => (),
            // Refused before the shell is opened on the target: tell the viewer, then end
            // the session.
            Err(error) => {
                self.push(ServerMessage::Error {
                    message: error.to_string(),
                })
                .await;
                self.abort();
                return None;
            }
        }
        // seeds the recording with the initial screen size
        if audit.on_resize(&pty_request).await.is_break() {
            self.close_on_recording_failure().await;
            return None;
        }
        self.channel_audits.lock().await.insert(channel_id, audit);

        self.command(RCCommand::Channel(channel_id, ChannelOperation::OpenShell));
        self.command(RCCommand::Channel(
            channel_id,
            ChannelOperation::RequestPty(pty_request),
        ));
        self.command(RCCommand::Channel(
            channel_id,
            ChannelOperation::RequestShell,
        ));
        Some(channel_id)
    }

    pub async fn send_input(&self, channel_id: Uuid, data: Bytes) {
        if let Some(audit) = self.channel_audits.lock().await.get_mut(&channel_id)
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
        if let Some(audit) = self.channel_audits.lock().await.get_mut(&channel_id)
            && audit.on_output(data).await.is_break()
        {
            self.close_on_recording_failure().await;
            return false;
        }
        true
    }

    pub async fn resize_channel(&self, channel_id: Uuid, cols: u32, rows: u32) {
        let pty_request = make_pty_request(cols, rows);
        if let Some(audit) = self.channel_audits.lock().await.get_mut(&channel_id)
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
    /// sessions are refused: tell the viewer, then end the session.
    async fn close_on_recording_failure(&self) {
        self.push(ServerMessage::Error {
            message: WarpgateError::SessionRecordingFailed.to_string(),
        })
        .await;
        self.abort();
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
}
