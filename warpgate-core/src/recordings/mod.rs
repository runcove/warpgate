use std::collections::HashMap;
use std::fmt::Debug;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use serde::Serialize;
use time::OffsetDateTime;
use tokio::sync::{Mutex, broadcast};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{error, info, warn};
use uuid::Uuid;
use warpgate_common::helpers::fs::{
    KEEP_FOR_DIRECTORY, create_recording_directories, secure_directory,
    secure_recordings_root_by_masking,
};
use warpgate_common::{GlobalParams, TargetSessionId};
use warpgate_db_entities::Recording::{self, RecordingKind};
mod desktop;
mod storage;
mod terminal;
mod traffic;
mod writer;
pub use desktop::*;
pub use storage::FileAccess;
use storage::Storage;
pub use terminal::*;
pub use traffic::*;
pub use writer::{LiveChunk, NDJsonRecordingWriter, RawRecordingWriter};
use writer::{RecordingCompletion, WriterShutdown};

/// How long `SessionRecordings::shutdown` waits
/// (just under kubernetes default)
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(25);

const RECORDING_GENERATION: i32 = 3;

/// The log text written when a session's recording fails: when it cannot start, or
/// when a write fails after a good start. An operator alert matches this text
/// exactly to count failed recordings, so a rewording would silently read as zero
/// failures: changing it needs the alert changed too (`log_text_tests` pins it, and
/// `tests::failed_recording_line` pins the fields it carries).
pub mod log_text {
    /// Every protocol (SSH, Kubernetes, web SSH, web desktop, native RDP / VNC) and
    /// both stages (`start`, `write`).
    pub const SESSION_RECORDING_FAILED: &str = "Session recording failed";
}

#[cfg(test)]
mod log_text_tests {
    use super::log_text::*;

    /// An operator alert matches this text; changing it needs the alert changed too.
    #[test]
    fn failed_recording_log_text_is_pinned() {
        assert_eq!(SESSION_RECORDING_FAILED, "Session recording failed");
    }
}

/// Who a recording belongs to, carried on its [`log_text::SESSION_RECORDING_FAILED`] line.
#[derive(Clone, Debug)]
pub struct RecordingOwner {
    /// `ssh`, `kubernetes`, `web-ssh`, `web-desktop`, `rdp` or `vnc`.
    pub protocol: &'static str,
    pub user: String,
    pub target: String,
}

/// Where a recording failed: it could not start, or a write failed after it started.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureStage {
    Start,
    Write,
}

impl std::fmt::Display for FailureStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Start => "start",
            Self::Write => "write",
        })
    }
}

/// Logs the one [`log_text::SESSION_RECORDING_FAILED`] line and counts it.
fn log_recording_failure(
    owner: &RecordingOwner,
    target_session: &TargetSessionId,
    stage: FailureStage,
    cause: &dyn std::fmt::Display,
    required: bool,
    failures: &AtomicU64,
) {
    let total = failures.fetch_add(1, Ordering::SeqCst).saturating_add(1);
    error!(
        protocol = owner.protocol,
        user = %owner.user,
        target = %owner.target,
        target_session = %target_session,
        stage = %stage,
        cause = %cause,
        required,
        total,
        "{}",
        log_text::SESSION_RECORDING_FAILED
    );
}

/// One per recording, shared by all its writers: reports the recording's first
/// write failure, and only that one.
pub(crate) struct FailureReporter {
    owner: RecordingOwner,
    target_session: TargetSessionId,
    required: bool,
    failures: Arc<AtomicU64>,
    shutdown: CancellationToken,
    reported: AtomicBool,
}

impl FailureReporter {
    /// Logs and counts the failure unless this recording's failure was already
    /// reported, or Warpgate is shutting down (its writers are closing, not failing).
    /// Returns whether the session must now be closed
    /// (`--recordings-refuse-unrecorded-sessions`).
    pub(crate) fn write_failed(&self, cause: &dyn std::fmt::Display) -> bool {
        if !self.shutdown.is_cancelled() && !self.reported.swap(true, Ordering::SeqCst) {
            log_recording_failure(
                &self.owner,
                &self.target_session,
                FailureStage::Write,
                cause,
                self.required,
                &self.failures,
            );
        }
        self.required
    }

    /// A reporter for a writer built by hand in this crate's tests, counting into
    /// `recordings`' total as a started recording's would.
    #[cfg(test)]
    pub(crate) fn for_test(recordings: &SessionRecordings, id: &TargetSessionId) -> Arc<Self> {
        Arc::new(Self {
            owner: RecordingOwner {
                protocol: "test",
                user: "test-user".into(),
                target: "test-target".into(),
            },
            target_session: *id,
            required: recordings.refuses_unrecorded_sessions(),
            failures: recordings.failures.clone(),
            shutdown: recordings.shutdown.clone(),
            reported: AtomicBool::new(false),
        })
    }
}

/// The live-broadcast channel for a recording's primary data stream, keyed by
/// recording id. Each item carries its end byte offset so a viewer can splice
/// the live tail onto a history snapshot without gaps (see [`LiveChunk`]).
type LiveMap = Arc<Mutex<HashMap<Uuid, broadcast::Sender<LiveChunk>>>>;

// The possible files that a recording can open
#[derive(Debug, Clone, Copy)]
pub enum RecordingFile {
    NDJsonData,
    TcpDumpData,
    Index,
}

impl RecordingFile {
    const fn filename(self) -> &'static str {
        match self {
            Self::NDJsonData => "data.ndjson",
            Self::TcpDumpData => "data.tcpdump",
            Self::Index => "index.ndjson",
        }
    }

    pub const fn mime_type(self) -> &'static str {
        match self {
            Self::NDJsonData | Self::Index => "application/x-ndjson",
            Self::TcpDumpData => "application/vnd.tcpdump.pcap",
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),

    #[error("Creating recording directory {}: {source}", path.display())]
    CreateDirectory {
        path: std::path::PathBuf,
        source: std::io::Error,
    },

    #[error("Database: {0}")]
    Database(#[from] sea_orm::DbErr),

    #[error("Failed to serialize a recording item: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Image codec: {0}")]
    Codec(String),

    #[error(transparent)]
    PngEncode(#[from] crate::protocols::PngEncodeError),

    #[error("Writer is closed")]
    Closed,

    #[error("Invalid recording path")]
    InvalidPath,

    #[error("Storage backend: {0}")]
    Aws(#[from] warpgate_aws::AwsError),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Runs blocking filesystem calls on tokio's blocking pool, off the async workers.
async fn blocking_io<T: Send + 'static>(
    f: impl FnOnce() -> std::io::Result<T> + Send + 'static,
) -> std::io::Result<T> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(std::io::Error::other)?
}

pub struct RecordingWriterOpener {
    storage: Storage,
    model: Recording::Model,
    db: DatabaseConnection,
    live: LiveMap,
    params: GlobalParams,
    shutdown: CancellationToken,
    shutdown_tracker: TaskTracker,
    completion: Arc<RecordingCompletion>,
    reporter: Arc<FailureReporter>,
}

impl RecordingWriterOpener {
    pub async fn open_ndjson_data(&self) -> Result<NDJsonRecordingWriter> {
        Ok(NDJsonRecordingWriter::new(
            self.open(RecordingFile::NDJsonData).await?,
        ))
    }

    pub async fn open_index(&self) -> Result<NDJsonRecordingWriter> {
        Ok(NDJsonRecordingWriter::new(
            self.open(RecordingFile::Index).await?,
        ))
    }

    pub async fn open_tcpdump_data(&self) -> Result<RawRecordingWriter> {
        self.open(RecordingFile::TcpDumpData).await
    }

    async fn open(&self, file: RecordingFile) -> Result<RawRecordingWriter> {
        // Only the primary data stream is live-broadcast (keyed by recording id). The index
        // and tcpdump sidecars must NOT register: they'd overwrite the data writer's entry
        // under the same id, and a live viewer would then receive the index (seek anchors,
        // no pixels) instead of the framebuffer.
        let live = matches!(file, RecordingFile::NDJsonData).then(|| self.live.clone());
        let sink = self
            .storage
            .open_sink(&self.model, file, &self.params)
            .await?;

        RawRecordingWriter::new(
            sink,
            live,
            WriterShutdown {
                token: self.shutdown.clone(),
                tracker: self.shutdown_tracker.clone(),
            },
            self.completion.register_writer().await,
            self.reporter.clone(),
        )
        .await
    }
}

pub trait Recorder
where
    Self: Sized,
{
    fn kind() -> RecordingKind;
    fn new(opener: &RecordingWriterOpener) -> impl Future<Output = Result<Self>> + Send;
}

pub struct SessionRecordings {
    db: DatabaseConnection,
    live: LiveMap,
    params: GlobalParams,
    shutdown: CancellationToken,
    shutdown_tracker: TaskTracker,
    /// Recordings that failed (to start, or mid-session) since Warpgate started.
    failures: Arc<AtomicU64>,
}

impl SessionRecordings {
    pub fn new(db: DatabaseConnection, params: &GlobalParams) -> Self {
        Self {
            db,
            live: Arc::new(Mutex::new(HashMap::new())),
            params: params.clone(),
            shutdown: CancellationToken::new(),
            shutdown_tracker: TaskTracker::new(),
            failures: Arc::new(AtomicU64::new(0)),
        }
    }

    /// How many recordings have failed (to start, or mid-session) since Warpgate
    /// started: the `total` on each [`log_text::SESSION_RECORDING_FAILED`] line.
    pub fn failed_recordings(&self) -> u64 {
        self.failures.load(Ordering::SeqCst)
    }

    /// Whether a session whose recording fails to start is refused rather than
    /// continued unrecorded (`--recordings-refuse-unrecorded-sessions`, off by default).
    /// A caller whose [`Self::start_for`] returned `Err` (already logged) refuses the
    /// session when this is true. A recorder's `write_failed` returns the same
    /// setting for a recording that fails mid-session.
    pub const fn refuses_unrecorded_sessions(&self) -> bool {
        self.params.refuse_unrecorded_sessions()
    }

    /// Signal every in-flight writer to finalize, then wait (bounded)
    pub async fn shutdown(&self) {
        self.shutdown.cancel();
        if !self.shutdown_tracker.is_empty() {
            info!(
                count = self.shutdown_tracker.len(),
                "Waiting for session recording uploads to finish..."
            );
        }
        self.shutdown_tracker.close();

        if tokio::time::timeout(SHUTDOWN_TIMEOUT, self.shutdown_tracker.wait())
            .await
            .is_err()
        {
            warn!("Timed out waiting for recording uploads to finish");
        }
    }

    async fn storage(&self) -> Result<Storage> {
        Storage::load(&self.db, &self.params).await
    }

    /// Starting a recording with the same name again will append to it. On S3
    /// storage this is not supported: each start completes its own upload of the
    /// same keys, and `ended` is not reset on append. With
    /// `--recordings-keep-group-read` it is refused: each recording file must be new,
    /// so the second start fails.
    /// `None` when recording is disabled. A failure to start is logged with the
    /// [`log_text::SESSION_RECORDING_FAILED`] line (`stage=start`) and counted before
    /// it is returned; a later write failure is reported through the recorder's
    /// `write_failed`, once per recording.
    pub async fn start_for<T, M>(
        &self,
        owner: &RecordingOwner,
        id: &TargetSessionId,
        name: Option<String>,
        metadata: M,
    ) -> Result<Option<T>>
    where
        T: Recorder,
        M: Serialize + Debug,
    {
        let result = self.start_inner(owner, id, name, metadata).await;
        if let Err(error) = &result {
            log_recording_failure(
                owner,
                id,
                FailureStage::Start,
                error,
                self.refuses_unrecorded_sessions(),
                &self.failures,
            );
        }
        result
    }

    /// [`Self::start_for`] with a placeholder owner, for this crate's tests.
    #[cfg(test)]
    pub(crate) async fn start<T, M>(
        &self,
        id: &TargetSessionId,
        name: Option<String>,
        metadata: M,
    ) -> Result<Option<T>>
    where
        T: Recorder,
        M: Serialize + Debug,
    {
        let owner = RecordingOwner {
            protocol: "test",
            user: "test-user".into(),
            target: "test-target".into(),
        };
        self.start_for(&owner, id, name, metadata).await
    }

    async fn start_inner<T, M>(
        &self,
        owner: &RecordingOwner,
        id: &TargetSessionId,
        name: Option<String>,
        metadata: M,
    ) -> Result<Option<T>>
    where
        T: Recorder,
        M: Serialize + Debug,
    {
        let storage = self.storage().await?;
        if !storage.enabled() {
            return Ok(None);
        }

        let name = name.unwrap_or_else(|| Uuid::new_v4().to_string());
        // Gen 2+ recordings are folders holding fixed-name files (`data.ndjson`, and an
        // index `index.json`), so the recording path is a directory we create here.
        // On S3 this folder is a scratch copy, live-readable while the session runs and
        // dropped once each file finishes uploading.
        let folder = storage.recording_folder(id, &name);
        let masking = self.params.should_secure_files() && self.params.recordings_keep_group_read();
        if masking {
            let root = storage.local_root().to_path_buf();
            let relative = Path::new(&id.to_string()).join(&name);
            blocking_io(move || {
                // Below the root, each directory is created and opened relative to the
                // one above it, never through a symlink, and tightened as it is opened:
                // the session and recording directories are Warpgate's own and fail
                // closed.
                create_recording_directories(&root, &relative)?;
                // The root too, so a reader granted read by a default POSIX ACL on it
                // can traverse to the recording: never recursive and never adding a
                // bit. The root may predate Warpgate and belong to someone else, so it
                // is only warned about.
                secure_recordings_root_by_masking(&root, KEEP_FOR_DIRECTORY);
                Ok(())
            })
            .await
        } else {
            tokio::fs::create_dir_all(&folder).await
        }
        .map_err(|source| Error::CreateDirectory {
            path: folder.clone(),
            source,
        })?;
        if self.params.should_secure_files() && !masking {
            secure_directory(&folder)?;
        }

        let model = {
            let db = &self.db;
            let existing = Recording::Entity::find()
                .filter(
                    Recording::Column::SessionId
                        .eq(id.0)
                        .and(Recording::Column::Name.eq(name.clone()))
                        .and(Recording::Column::Kind.eq(T::kind())),
                )
                .one(db)
                .await?;
            if let Some(e) = existing {
                e
            } else {
                use sea_orm::ActiveValue::Set;
                info!(%name, ?metadata, path=?folder, "Recording session {}", id);
                let values = Recording::ActiveModel {
                    id: Set(Uuid::new_v4()),
                    started: Set(OffsetDateTime::now_utc()),
                    session_id: Set(*id),
                    name: Set(name.clone()),
                    kind: Set(T::kind()),
                    metadata: Set(serde_json::to_string(&metadata)?),
                    generation: Set(RECORDING_GENERATION),
                    ..Default::default()
                };
                values.insert(db).await.map_err(Error::Database)?
            }
        };

        let opener = RecordingWriterOpener {
            storage,
            completion: RecordingCompletion::new(self.db.clone(), model.id),
            model,
            db: self.db.clone(),
            live: self.live.clone(),
            params: self.params.clone(),
            shutdown: self.shutdown.clone(),
            shutdown_tracker: self.shutdown_tracker.clone(),
            reporter: Arc::new(FailureReporter {
                owner: owner.clone(),
                target_session: *id,
                required: self.refuses_unrecorded_sessions(),
                failures: self.failures.clone(),
                shutdown: self.shutdown.clone(),
                reported: AtomicBool::new(false),
            }),
        };

        // Held until every file is open, so a recorder that fails or is cancelled
        // half-way cannot let its first file end the recording.
        let construction = opener.completion.register_writer().await;
        let recorder = T::new(&opener).await?;
        construction.finished(None).await?;
        Ok(Some(recorder))
    }

    pub async fn subscribe_live(&self, id: &Uuid) -> Option<broadcast::Receiver<LiveChunk>> {
        let live = self.live.lock().await;
        live.get(id).map(broadcast::Sender::subscribe)
    }

    pub async fn remove(&self, session_id: &TargetSessionId, name: &str) -> Result<()> {
        self.storage().await?.remove(session_id, name).await
    }

    /// Open a recording file as a streaming reader (local file or S3 object),
    /// without buffering the whole thing. Used by endpoints that transform the
    /// file server-side.
    pub async fn access(
        &self,
        recording: &Recording::Model,
        file: RecordingFile,
    ) -> Result<FileAccess> {
        Ok(self.storage().await?.access(recording, file))
    }
}

#[cfg(test)]
#[cfg(feature = "sqlite")]
mod tests;

/// For tests (this crate's, and others' through the `test-util` feature): fail a
/// recording mid-session the way a full disk does.
#[cfg(any(test, feature = "test-util"))]
pub mod test_support {
    use std::collections::HashMap;
    use std::os::fd::AsRawFd;
    use std::path::Path;
    use std::sync::{Mutex, OnceLock};

    use warpgate_common::TargetSessionId;

    use super::log_text;

    /// Every event this test binary logs, as field values. Installed once and
    /// globally: `tracing` caches a callsite first reached with no subscriber as
    /// never-interested for the whole process, so a per-test subscriber would miss
    /// events whenever another test thread got there first. The one global
    /// subscriber a test binary can install, so this crate's audit tests share it.
    pub fn log_events() -> &'static Mutex<Vec<HashMap<&'static str, String>>> {
        use tracing_subscriber::layer::SubscriberExt;

        use crate::logging::layer::ValuesLogLayer;

        static EVENTS: OnceLock<Mutex<Vec<HashMap<&'static str, String>>>> = OnceLock::new();
        let events = EVENTS.get_or_init(|| Mutex::new(Vec::new()));
        static INSTALLED: OnceLock<()> = OnceLock::new();
        INSTALLED.get_or_init(|| {
            let subscriber =
                tracing_subscriber::registry().with(ValuesLogLayer::new(|values, _target| {
                    if let Ok(mut events) = events.lock() {
                        events.push(values.into_values());
                    }
                }));
            let _ = tracing::subscriber::set_global_default(subscriber);
        });
        events
    }

    /// The [`log_text::SESSION_RECORDING_FAILED`] lines logged for one target
    /// session since [`log_events`] was first called.
    pub fn failed_recording_lines(session: &TargetSessionId) -> Vec<HashMap<&'static str, String>> {
        let session = session.to_string();
        log_events()
            .lock()
            .map(|events| {
                events
                    .iter()
                    .filter(|values| {
                        values.get("message").map(String::as_str)
                            == Some(log_text::SESSION_RECORDING_FAILED)
                            && values.get("target_session") == Some(&session)
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Points every recording file this process has open under `root` at
    /// `/dev/full`, so the writers' next writes fail with "No space left on
    /// device" as they would on a full disk. Returns how many were broken.
    #[allow(unsafe_code)]
    pub fn fail_open_recording_files(root: &Path) -> usize {
        #[allow(clippy::unwrap_used)]
        let full = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .unwrap();
        let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
        let mut broken = 0;
        let Ok(fds) = std::fs::read_dir("/proc/self/fd") else {
            return 0;
        };
        for entry in fds.flatten() {
            let Ok(path) = std::fs::read_link(entry.path()) else {
                continue;
            };
            let is_recording_file = path.file_name().is_some_and(|name| {
                ["data.ndjson", "index.ndjson", "data.tcpdump"]
                    .iter()
                    .any(|file| name == *file)
            });
            if !path.starts_with(&root) || !is_recording_file {
                continue;
            }
            let Ok(fd) = entry.file_name().to_string_lossy().parse::<i32>() else {
                continue;
            };
            // SAFETY: `dup2` atomically replaces an open descriptor with another
            // open one; the file's owner keeps a valid descriptor, now to
            // `/dev/full`.
            if unsafe { libc::dup2(full.as_raw_fd(), fd) } >= 0 {
                broken += 1;
            }
        }
        broken
    }
}
