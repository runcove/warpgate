//! Each failure test first asserts that the failure it injects actually fired,
//! so a pass is not vacuous.

use std::path::{Path, PathBuf};

use poem::http::{Method, StatusCode};
use poem::listener::{Acceptor, Listener, TcpListener};
use poem::{Request, Response};
use sea_orm::ActiveValue::Set;
use sea_orm::{ConnectionTrait, Database, IntoActiveModel};
use tokio::io::AsyncReadExt;
use warpgate_aws::{S3Credentials, S3Storage, S3StorageConfig, StaticCredentials};
use warpgate_db_entities::Parameters::{
    self, ConfigMigrationValues, RecordingsDiskConfig, RecordingsStorageConfig,
    set_config_migration_values,
};
use warpgate_db_migrations::migrate_database;

use super::storage::RecordingSink;
use super::*;

/// A recording made of two files, like a terminal recording's data + index.
struct TwoFiles {
    data: RawRecordingWriter,
    index: RawRecordingWriter,
}

impl Recorder for TwoFiles {
    fn kind() -> RecordingKind {
        RecordingKind::Terminal
    }

    async fn new(opener: &RecordingWriterOpener) -> Result<Self> {
        Ok(Self {
            data: opener.open(RecordingFile::NDJsonData).await?,
            index: opener.open(RecordingFile::Index).await?,
        })
    }
}

/// Just enough of the S3 multipart API, with a failure knob per call.
#[derive(Default)]
struct FakeS3 {
    fail_create: Option<&'static str>,
    fail_part: Option<(&'static str, u32)>,
    fail_complete: Option<&'static str>,
    created: Vec<String>,
    failed_creates: Vec<String>,
    failed_parts: Vec<String>,
    /// (key, part number, body length) of every accepted part.
    parts: Vec<(String, u32, usize)>,
    failed_completes: Vec<String>,
    completed: Vec<String>,
    aborted: Vec<String>,
}

impl FakeS3 {
    fn handle(&mut self, method: &Method, path: &str, query: &str, len: usize) -> Response {
        let part = query
            .split('&')
            .find_map(|pair| pair.strip_prefix("partNumber="))
            .and_then(|n| n.parse::<u32>().ok());
        let ok = |body: &str| Response::builder().body(body.to_string());
        let fail = || {
            Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body("<Error><Code>InvalidRequest</Code><Message>injected</Message></Error>")
        };
        match (method, part) {
            (&Method::POST, _) if query.split('&').any(|q| q.starts_with("uploads")) => {
                if self.fail_create.is_some_and(|f| path.ends_with(f)) {
                    self.failed_creates.push(path.into());
                    return fail();
                }
                self.created.push(path.into());
                ok(
                    "<InitiateMultipartUploadResult><UploadId>u</UploadId></InitiateMultipartUploadResult>",
                )
            }
            (&Method::PUT, Some(n)) => {
                if self
                    .fail_part
                    .is_some_and(|(f, fail_n)| path.ends_with(f) && n == fail_n)
                {
                    self.failed_parts.push(path.into());
                    return fail();
                }
                self.parts.push((path.into(), n, len));
                Response::builder()
                    .header("ETag", format!("\"{n}\""))
                    .body("")
            }
            (&Method::POST, _) => {
                if self.fail_complete.is_some_and(|f| path.ends_with(f)) {
                    self.failed_completes.push(path.into());
                    return fail();
                }
                self.completed.push(path.into());
                ok(
                    "<CompleteMultipartUploadResult><ETag>\"e\"</ETag></CompleteMultipartUploadResult>",
                )
            }
            (&Method::DELETE, _) => {
                self.aborted.push(path.into());
                Response::builder().status(StatusCode::NO_CONTENT).body("")
            }
            _ => fail(),
        }
    }

    fn completed(&self, file: &str) -> bool {
        self.completed.iter().any(|key| key.ends_with(file))
    }
}

struct Harness {
    db: DatabaseConnection,
    recordings: SessionRecordings,
    root: PathBuf,
    session_id: TargetSessionId,
    s3: Arc<std::sync::Mutex<FakeS3>>,
    s3_config: Option<S3StorageConfig>,
}

impl Harness {
    async fn new(s3: Option<FakeS3>) -> Self {
        Self::with_securing(s3, false, false).await
    }

    async fn with_securing(s3: Option<FakeS3>, secure: bool, keep_group_read: bool) -> Self {
        Self::with_disk_path(s3, secure, keep_group_read, "data/recordings").await
    }

    /// `disk_path` is the disk backend's recordings root, relative to the harness root
    /// unless absolute.
    async fn with_disk_path(
        s3: Option<FakeS3>,
        secure: bool,
        keep_group_read: bool,
        disk_path: &str,
    ) -> Self {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        let root = std::env::temp_dir().join(format!("wg-recordings-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();

        let use_s3 = s3.is_some();
        let s3 = Arc::new(std::sync::Mutex::new(s3.unwrap_or_default()));
        let s3_config = if use_s3 {
            Some(S3StorageConfig {
                bucket: "recordings".into(),
                region: "us-east-1".into(),
                endpoint: Some(format!("http://{}", serve(s3.clone()).await)),
                path_style: true,
                prefix: String::new(),
                credentials: S3Credentials::Static(StaticCredentials {
                    access_key_id: "test".into(),
                    secret_access_key: Some("test".into()),
                }),
                scratch_path: Some(root.join("scratch").to_string_lossy().into_owned()),
            })
        } else {
            None
        };

        let mut parameters = Parameters::Entity::get(&db)
            .await
            .unwrap()
            .into_active_model();
        parameters.recordings_enable = Set(true);
        let storage = match &s3_config {
            Some(config) => RecordingsStorageConfig::S3(config.clone()),
            None => RecordingsStorageConfig::Disk(RecordingsDiskConfig {
                path: disk_path.into(),
            }),
        };
        parameters.recordings_storage = Set(serde_json::to_string(&storage).unwrap());
        parameters.update(&db).await.unwrap();

        let params = GlobalParams::new(root.join("warpgate.yaml"), secure)
            .unwrap()
            .with_recordings_keep_group_read(keep_group_read);
        let recordings = SessionRecordings::new(db.clone(), &params);

        let session_id = TargetSessionId(Uuid::new_v4());
        warpgate_db_entities::TargetSession::ActiveModel {
            id: Set(session_id),
            user_session_id: Set(warpgate_common::UserSessionId(Uuid::new_v4())),
            target_snapshot: Set("{}".into()),
            target_id: Set(Uuid::new_v4()),
            started: Set(OffsetDateTime::now_utc()),
            ..Default::default()
        }
        .insert(&db)
        .await
        .unwrap();

        Self {
            db,
            recordings,
            root,
            session_id,
            s3,
            s3_config,
        }
    }

    async fn wait_for_writers(&self, remaining: usize) {
        tokio::time::timeout(Duration::from_secs(10), async {
            while self.recordings.shutdown_tracker.len() != remaining {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }

    async fn recording(&self) -> Recording::Model {
        Recording::Entity::find()
            .one(&self.db)
            .await
            .unwrap()
            .unwrap()
    }

    async fn ended(&self) -> Option<OffsetDateTime> {
        self.recording().await.ended
    }

    async fn scratch(&self, file: RecordingFile) -> PathBuf {
        let recording = self.recording().await;
        self.root
            .join("scratch")
            .join(recording.session_id.to_string())
            .join(recording.name)
            .join(file.filename())
    }

    fn s3(&self) -> std::sync::MutexGuard<'_, FakeS3> {
        self.s3.lock().unwrap()
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

async fn serve(s3: Arc<std::sync::Mutex<FakeS3>>) -> std::net::SocketAddr {
    let acceptor = TcpListener::bind("127.0.0.1:0")
        .into_acceptor()
        .await
        .unwrap();
    let address = acceptor
        .local_addr()
        .into_iter()
        .find_map(|address| address.0.as_socket_addr().copied())
        .unwrap();
    let app = poem::endpoint::make(move |mut request: Request| {
        let s3 = s3.clone();
        async move {
            let len = request
                .take_body()
                .into_vec()
                .await
                .map(|b| b.len())
                .unwrap_or_default();
            let uri = request.uri();
            s3.lock().unwrap().handle(
                request.method(),
                uri.path(),
                uri.query().unwrap_or_default(),
                len,
            )
        }
    });
    tokio::spawn(poem::Server::new_with_acceptor(acceptor).run(app));
    address
}

fn exists(path: &Path) -> bool {
    path.try_exists().unwrap()
}

/// Readers switch a recording to S3 as soon as it is ended, so a file that
/// finishes first must not end it while another is still uploading.
#[tokio::test]
async fn a_recording_ends_only_after_its_last_file_is_finalized() {
    let h = Harness::new(None).await;

    let recording: TwoFiles = h
        .recordings
        .start(&h.session_id, None, ())
        .await
        .unwrap()
        .unwrap();
    h.wait_for_writers(2).await;

    drop(recording.index);
    h.wait_for_writers(1).await;
    assert_eq!(h.ended().await, None, "ended while data.ndjson was open");

    drop(recording.data);
    h.wait_for_writers(0).await;
    assert!(h.ended().await.is_some(), "never ended");
}

/// index.ndjson fails to complete on S3. The recording is rightly not ended,
/// so readers are sent to the local scratch; data.ndjson's scratch must
/// therefore still be there.
#[tokio::test]
async fn a_failed_finalize_keeps_the_other_files_scratch() {
    let h = Harness::new(Some(FakeS3 {
        fail_complete: Some("index.ndjson"),
        ..Default::default()
    }))
    .await;

    let recording: TwoFiles = h
        .recordings
        .start(&h.session_id, None, ())
        .await
        .unwrap()
        .unwrap();
    recording.data.write(b"data\n").await.unwrap();
    recording.index.write(b"index\n").await.unwrap();
    drop(recording);
    h.wait_for_writers(0).await;

    assert!(
        h.s3().completed("data.ndjson"),
        "data.ndjson was never finalized"
    );
    assert_eq!(
        h.s3().failed_completes.len(),
        1,
        "the index completion failure never fired"
    );
    let recording = h.recording().await;
    assert_eq!(
        recording.ended, None,
        "ended with index.ndjson missing on S3"
    );

    let access = h
        .recordings
        .access(&recording, RecordingFile::NDJsonData)
        .await
        .unwrap();
    assert!(
        access.open_read().await.is_ok(),
        "the reader for a not-ended recording is pointed at a scratch file that no longer exists",
    );
}

/// data.ndjson is already uploaded when index.ndjson fails to open; ending the
/// recording then would point readers at an index that does not exist.
#[tokio::test]
async fn a_recorder_that_fails_to_open_all_files_does_not_end() {
    let h = Harness::new(Some(FakeS3 {
        fail_create: Some("index.ndjson"),
        ..Default::default()
    }))
    .await;

    let started = h
        .recordings
        .start::<TwoFiles, _>(&h.session_id, None, ())
        .await;
    assert!(
        started.is_err(),
        "index.ndjson opened despite the injected failure"
    );
    let failed_creates = h.s3().failed_creates.clone();
    assert!(
        matches!(failed_creates.as_slice(), [key] if key.ends_with("index.ndjson")),
        "start failed, but not on the injected index.ndjson create"
    );
    h.wait_for_writers(0).await;

    assert!(
        h.s3().completed("data.ndjson"),
        "data.ndjson was never finalized"
    );
    let index_on_s3 = h.s3().completed("index.ndjson");
    let ended = h.ended().await;
    assert!(
        ended.is_none(),
        "ended={ended:?} while index.ndjson on S3={index_on_s3}; data scratch exists={}",
        exists(&h.scratch(RecordingFile::NDJsonData).await),
    );
}

/// The scratch write fails, so the upload is missing what was written.
#[tokio::test]
async fn a_failed_local_write_does_not_end() {
    let h = Harness::new(Some(FakeS3::default())).await;
    let model = Recording::ActiveModel {
        id: Set(Uuid::new_v4()),
        started: Set(OffsetDateTime::now_utc()),
        session_id: Set(h.session_id),
        name: Set("broken".into()),
        kind: Set(RecordingKind::Terminal),
        metadata: Set("{}".into()),
        generation: Set(RECORDING_GENERATION),
        ..Default::default()
    }
    .insert(&h.db)
    .await
    .unwrap();

    let scratch = h.scratch(RecordingFile::NDJsonData).await;
    std::fs::create_dir_all(scratch.parent().unwrap()).unwrap();
    std::fs::write(&scratch, b"").unwrap();
    let s3 = S3Storage::new(h.s3_config.as_ref().unwrap()).await.unwrap();
    let sink = RecordingSink::S3 {
        // Read-only, so writing to it fails.
        scratch: tokio::fs::File::open(&scratch).await.unwrap(),
        scratch_path: scratch.clone(),
        upload: Some(s3.start_multipart("broken/data.ndjson").await.unwrap()),
    };
    let writer = RawRecordingWriter::new(
        sink,
        None,
        WriterShutdown {
            token: h.recordings.shutdown.clone(),
            tracker: h.recordings.shutdown_tracker.clone(),
        },
        RecordingCompletion::new(h.db.clone(), model.id)
            .register_writer()
            .await,
        FailureReporter::for_test(&h.recordings, &h.session_id),
    )
    .await
    .unwrap();
    let written = b"first\n".len() + b"second\n".len();
    writer.write(b"first\n").await.unwrap();
    writer.write(b"second\n").await.unwrap();
    drop(writer);
    h.wait_for_writers(0).await;

    assert!(
        h.s3().completed("data.ndjson"),
        "data.ndjson was never finalized"
    );
    let uploaded: usize = h.s3().parts.iter().map(|(_, _, len)| len).sum();
    assert!(uploaded < written, "the local write never failed");
    let ended = h.ended().await;
    assert!(
        ended.is_none(),
        "ended={ended:?} with {uploaded} of {written} written bytes on S3"
    );
    assert!(
        exists(&scratch),
        "the scratch of a not-ended recording is gone"
    );
}

/// S3 accepts a multipart upload with a gap in its part numbers, so a lost
/// part would otherwise complete into a silently truncated object.
#[tokio::test]
async fn a_failed_s3_part_does_not_end() {
    let h = Harness::new(Some(FakeS3 {
        fail_part: Some(("data.ndjson", 1)),
        ..Default::default()
    }))
    .await;

    let recording: TwoFiles = h
        .recordings
        .start(&h.session_id, None, ())
        .await
        .unwrap()
        .unwrap();
    let data = vec![b'x'; 6 * 1024 * 1024];
    recording.data.write(&data).await.unwrap();
    drop(recording);
    h.wait_for_writers(0).await;

    assert_eq!(h.s3().failed_parts.len(), 1, "no part failed");
    let completed = h.s3().completed("data.ndjson");
    let uploaded: usize = h
        .s3()
        .parts
        .iter()
        .filter(|(key, _, _)| key.ends_with("data.ndjson"))
        .map(|(_, _, len)| len)
        .sum();
    let ended = h.ended().await;
    assert!(
        !completed && ended.is_none(),
        "data.ndjson completed={completed} with {uploaded} of {} bytes, ended={ended:?}",
        data.len(),
    );
    let aborted = h.s3().aborted.clone();
    assert!(
        matches!(aborted.as_slice(), [key] if key.ends_with("data.ndjson")),
        "expected exactly one abort, of data.ndjson"
    );

    let mut scratch = Vec::new();
    h.recordings
        .access(&h.recording().await, RecordingFile::NDJsonData)
        .await
        .unwrap()
        .open_read()
        .await
        .unwrap()
        .read_to_end(&mut scratch)
        .await
        .unwrap();
    assert_eq!(scratch.len(), data.len(), "the scratch is not complete");
}

/// Both files are uploaded but storing `ended` fails, so the recording is
/// still read from its scratch, which must therefore still be there.
#[tokio::test]
async fn a_failed_ended_update_keeps_the_scratch() {
    let h = Harness::new(Some(FakeS3::default())).await;

    let recording: TwoFiles = h
        .recordings
        .start(&h.session_id, None, ())
        .await
        .unwrap()
        .unwrap();
    recording.data.write(b"data\n").await.unwrap();
    recording.index.write(b"index\n").await.unwrap();
    drop(recording.index);
    h.wait_for_writers(1).await;

    h.db.execute_unprepared("ALTER TABLE recordings RENAME TO recordings_hidden")
        .await
        .unwrap();
    assert!(
        Recording::Entity::find().one(&h.db).await.is_err(),
        "the recordings table is still reachable"
    );
    drop(recording.data);
    h.wait_for_writers(0).await;
    h.db.execute_unprepared("ALTER TABLE recordings_hidden RENAME TO recordings")
        .await
        .unwrap();

    assert!(
        h.s3().completed("data.ndjson") && h.s3().completed("index.ndjson"),
        "a file was never finalized"
    );
    assert_eq!(h.ended().await, None);
    for file in [RecordingFile::NDJsonData, RecordingFile::Index] {
        let path = h.scratch(file).await;
        assert!(
            exists(&path),
            "a scratch file of the unended recording is gone"
        );
    }
}

/// Opens its data file, then never finishes opening the rest.
struct Stalls;

impl Recorder for Stalls {
    fn kind() -> RecordingKind {
        RecordingKind::Terminal
    }

    async fn new(opener: &RecordingWriterOpener) -> Result<Self> {
        let _data = opener.open(RecordingFile::NDJsonData).await?;
        std::future::pending().await
    }
}

/// A start abandoned half-way (e.g. its session went away) is as incomplete
/// as one that failed.
#[tokio::test]
async fn a_recorder_cancelled_while_opening_its_files_does_not_end() {
    let h = Harness::new(Some(FakeS3::default())).await;

    let constructed = tokio::select! {
        _ = h.recordings.start::<Stalls, _>(&h.session_id, None, ()) => true,
        () = h.wait_for_writers(1) => false,
    };
    assert!(!constructed, "construction finished");
    h.wait_for_writers(0).await;

    assert!(
        h.s3().completed("data.ndjson"),
        "data.ndjson was never finalized"
    );
    assert_eq!(h.ended().await, None);
    assert!(exists(&h.scratch(RecordingFile::NDJsonData).await));
}

/// Modes (masked to 0o7777) of everything one recording touches.
struct Modes {
    root: u32,
    session: u32,
    leaf: u32,
    file: u32,
}

/// Starts a two-file recording under `base` (the recordings root) and reads back the
/// modes of the root, the session directory, the recording directory and one file.
/// The root is created beforehand at `root_mode`, so a chmod of it is observable.
async fn start_and_read_modes(h: &Harness, base: &Path, root_mode: u32) -> Modes {
    use std::os::unix::fs::PermissionsExt;

    std::fs::create_dir_all(base).unwrap();
    std::fs::set_permissions(base, std::fs::Permissions::from_mode(root_mode)).unwrap();

    let recording: TwoFiles = h
        .recordings
        .start(&h.session_id, None, ())
        .await
        .unwrap()
        .unwrap();
    h.wait_for_writers(2).await;

    let model = h.recording().await;
    let session = base.join(model.session_id.to_string());
    let leaf = session.join(&model.name);
    let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o7777;
    let modes = Modes {
        root: mode(base),
        session: mode(&session),
        leaf: mode(&leaf),
        file: mode(&leaf.join(RecordingFile::NDJsonData.filename())),
    };
    // A file the other writer made gets the same treatment.
    assert_eq!(
        mode(&leaf.join(RecordingFile::Index.filename())),
        modes.file
    );

    drop(recording);
    h.wait_for_writers(0).await;
    modes
}

fn disk_root(h: &Harness) -> PathBuf {
    h.root.join("data/recordings")
}

fn scratch_root(h: &Harness) -> PathBuf {
    h.root.join("scratch")
}

/// What `create_dir_all` leaves a directory at under this process's umask.
fn default_dir_mode(h: &Harness) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    let probe = h.root.join("umask-probe-dir");
    std::fs::create_dir(&probe).unwrap();
    std::fs::metadata(&probe).unwrap().permissions().mode() & 0o7777
}

/// What a newly created file is left at under this process's umask.
fn default_file_mode(h: &Harness) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    let probe = h.root.join("umask-probe-file");
    std::fs::File::create(&probe).unwrap();
    std::fs::metadata(&probe).unwrap().permissions().mode() & 0o7777
}

/// With the flag on, nothing may end up wider than 0o750 (directories) or 0o640 (files):
/// no group write, no other access, no exec bit on files, no setuid/setgid/sticky.
fn assert_within_ceiling(modes: &Modes) {
    for (what, mode) in [
        ("root", modes.root),
        ("session", modes.session),
        ("leaf", modes.leaf),
    ] {
        assert_eq!(mode & !0o750, 0, "{what} is wider than 750: {mode:o}");
    }
    assert_eq!(
        modes.file & !0o640,
        0,
        "file is wider than 640: {:o}",
        modes.file
    );
}

async fn keeps_group_read(h: Harness, base: PathBuf) {
    let dir_default = default_dir_mode(&h);
    let file_default = default_file_mode(&h);
    let modes = start_and_read_modes(&h, &base, 0o777).await;

    assert_eq!(modes.root, 0o750, "a 777 root becomes 750");
    // Directories Warpgate creates are born at most 0750 under the umask, and masking
    // only removes bits.
    assert_eq!(modes.session, dir_default & 0o750);
    assert_eq!(modes.leaf, dir_default & 0o750);
    assert_eq!(modes.file, file_default & 0o640);
    assert_within_ceiling(&modes);
}

async fn never_adds_a_bit(h: Harness, base: PathBuf) {
    let dir_default = default_dir_mode(&h);
    let modes = start_and_read_modes(&h, &base, 0o700).await;

    assert_eq!(modes.root, 0o700, "a 700 root stays 700");
    assert_eq!(modes.session, dir_default & 0o750);
    assert_eq!(modes.leaf, dir_default & 0o750);
    assert_within_ceiling(&modes);
}

async fn special_bits_are_stripped(h: Harness, base: PathBuf) {
    let modes = start_and_read_modes(&h, &base, 0o7777).await;

    assert_eq!(modes.root, 0o750, "a 7777 root becomes 750");
    assert_within_ceiling(&modes);
}

async fn old_modes(h: Harness, base: PathBuf) {
    let dir_default = default_dir_mode(&h);
    let modes = start_and_read_modes(&h, &base, 0o755).await;

    assert_eq!(modes.root, 0o755, "root is left alone");
    assert_eq!(
        modes.session, dir_default,
        "session directory is left alone"
    );
    assert_eq!(modes.leaf, 0o700);
    assert_eq!(modes.file, 0o600);
}

#[tokio::test]
async fn disk_recordings_keep_group_read_when_asked() {
    let h = Harness::with_securing(None, true, true).await;
    let base = disk_root(&h);
    keeps_group_read(h, base).await;
}

#[tokio::test]
async fn s3_scratch_keeps_group_read_when_asked() {
    let h = Harness::with_securing(Some(FakeS3::default()), true, true).await;
    let base = scratch_root(&h);
    keeps_group_read(h, base).await;
}

#[tokio::test]
async fn disk_recordings_never_gain_a_bit_when_asked() {
    let h = Harness::with_securing(None, true, true).await;
    let base = disk_root(&h);
    never_adds_a_bit(h, base).await;
}

#[tokio::test]
async fn s3_scratch_never_gains_a_bit_when_asked() {
    let h = Harness::with_securing(Some(FakeS3::default()), true, true).await;
    let base = scratch_root(&h);
    never_adds_a_bit(h, base).await;
}

#[tokio::test]
async fn disk_recordings_lose_special_bits_when_asked() {
    let h = Harness::with_securing(None, true, true).await;
    let base = disk_root(&h);
    special_bits_are_stripped(h, base).await;
}

#[tokio::test]
async fn s3_scratch_loses_special_bits_when_asked() {
    let h = Harness::with_securing(Some(FakeS3::default()), true, true).await;
    let base = scratch_root(&h);
    special_bits_are_stripped(h, base).await;
}

#[tokio::test]
async fn disk_recordings_keep_the_old_modes_when_not_asked() {
    let h = Harness::with_securing(None, true, false).await;
    let base = disk_root(&h);
    old_modes(h, base).await;
}

#[tokio::test]
async fn s3_scratch_keeps_the_old_modes_when_not_asked() {
    let h = Harness::with_securing(Some(FakeS3::default()), true, false).await;
    let base = scratch_root(&h);
    old_modes(h, base).await;
}

/// `--skip-securing-files` wins over `--recordings-keep-group-read`: no chmod at all.
#[tokio::test]
async fn nothing_is_chmodded_when_securing_is_skipped() {
    for keep_group_read in [false, true] {
        let h = Harness::with_securing(None, false, keep_group_read).await;
        let dir_default = default_dir_mode(&h);
        let file_default = default_file_mode(&h);
        let modes = start_and_read_modes(&h, &disk_root(&h), 0o755).await;

        assert_eq!(modes.root, 0o755);
        assert_eq!(modes.session, dir_default);
        assert_eq!(modes.leaf, dir_default);
        assert_eq!(modes.file, file_default);
    }
}

/// The flag only touches the recordings tree: another session's directory and files
/// are left alone, not recursed into.
#[tokio::test]
async fn keeping_group_read_does_not_touch_other_sessions() {
    use std::os::unix::fs::PermissionsExt;

    let h = Harness::with_securing(None, true, true).await;
    let base = disk_root(&h);
    let other = base.join(Uuid::new_v4().to_string());
    std::fs::create_dir_all(&other).unwrap();
    std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o777)).unwrap();
    let other_file = other.join("data.ndjson");
    std::fs::write(&other_file, b"x").unwrap();
    std::fs::set_permissions(&other_file, std::fs::Permissions::from_mode(0o666)).unwrap();

    let modes = start_and_read_modes(&h, &base, 0o755).await;
    assert_eq!(modes.root, 0o750);

    let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o7777;
    assert_eq!(mode(&other), 0o777);
    assert_eq!(mode(&other_file), 0o666);
}

fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::symlink_metadata(path)
        .unwrap()
        .permissions()
        .mode()
        & 0o7777
}

fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

const NAME: &str = "named";

async fn start_named(h: &Harness) -> Result<Option<TwoFiles>> {
    h.recordings
        .start::<TwoFiles, _>(&h.session_id, Some(NAME.into()), ())
        .await
}

/// Every directory of a named recording exists beforehand, wide open. After the start
/// each is exactly at the ceiling, so a regression to an exact 0700 fails here whatever
/// the umask is. The files are new, so they are created within the ceiling.
async fn wide_existing_recording_is_masked(h: Harness, base: PathBuf) {
    let session = base.join(h.session_id.to_string());
    let leaf = session.join(NAME);
    std::fs::create_dir_all(&leaf).unwrap();
    for dir in [&base, &session, &leaf] {
        set_mode(dir, 0o777);
    }

    let recording = start_named(&h).await.unwrap().unwrap();
    h.wait_for_writers(2).await;

    for dir in [&base, &session, &leaf] {
        assert_eq!(mode_of(dir), 0o750, "{}", dir.display());
    }
    for file in [RecordingFile::NDJsonData, RecordingFile::Index].map(|f| leaf.join(f.filename())) {
        assert_eq!(mode_of(&file) & !0o640, 0, "{}", file.display());
    }
    drop(recording);
    h.wait_for_writers(0).await;
}

#[tokio::test]
async fn disk_wide_existing_recording_is_masked_to_the_ceiling() {
    let h = Harness::with_securing(None, true, true).await;
    let base = disk_root(&h);
    wide_existing_recording_is_masked(h, base).await;
}

#[tokio::test]
async fn s3_wide_existing_scratch_is_masked_to_the_ceiling() {
    let h = Harness::with_securing(Some(FakeS3::default()), true, true).await;
    let base = scratch_root(&h);
    wide_existing_recording_is_masked(h, base).await;
}

/// `EEXIST`, what `O_CREAT | O_EXCL` fails with on an existing entry: 17 on every
/// Linux architecture. warpgate-core has no libc dependency to name it.
const EEXIST: i32 = 17;

/// Under the flag each recording file must be new: an existing file where a recording
/// file goes fails the start, and is neither written nor chmodded.
#[tokio::test]
async fn an_existing_recording_file_fails_the_start() {
    for s3 in [false, true] {
        let h = Harness::with_securing(s3.then(FakeS3::default), true, true).await;
        let base = if s3 { scratch_root(&h) } else { disk_root(&h) };
        let leaf = base.join(h.session_id.to_string()).join(NAME);
        std::fs::create_dir_all(&leaf).unwrap();
        let existing = leaf.join(RecordingFile::NDJsonData.filename());
        std::fs::write(&existing, b"kept").unwrap();
        set_mode(&existing, 0o666);

        let err = start_named(&h).await.err().expect("the start fails");
        assert_eq!(raw_os_error(&err), Some(EEXIST), "s3: {s3}: {err:?}");
        assert_eq!(mode_of(&existing), 0o666, "s3: {s3}");
        assert_eq!(std::fs::read(&existing).unwrap(), b"kept", "s3: {s3}");
    }
}

/// A recordings root that is a symlink is not chmodded through, and the recording
/// still starts: the root is only warned about.
#[tokio::test]
async fn a_symlinked_root_is_left_alone_and_the_recording_starts() {
    let h = Harness::with_securing(None, true, true).await;
    let real = h.root.join("real-recordings");
    std::fs::create_dir_all(&real).unwrap();
    set_mode(&real, 0o777);
    std::fs::create_dir_all(h.root.join("data")).unwrap();
    std::os::unix::fs::symlink(&real, disk_root(&h)).unwrap();

    let recording = start_named(&h).await.unwrap().unwrap();
    h.wait_for_writers(2).await;

    assert_eq!(
        mode_of(&real),
        0o777,
        "the root behind the symlink is untouched"
    );
    let session = real.join(h.session_id.to_string());
    assert_eq!(mode_of(&session) & !0o750, 0);
    assert_eq!(mode_of(&session.join(NAME)) & !0o750, 0);
    drop(recording);
    h.wait_for_writers(0).await;
}

/// A recordings root owned by another user is left alone and the recording still
/// starts, even when running as root. As a user, the root is a sticky world-writable
/// directory this process does not own (the test fails if there is none); as root,
/// it is a fresh root (mode 0777) chowned to uid and gid 65534 (`nobody`).
#[tokio::test]
async fn a_root_owned_by_someone_else_is_left_alone_and_the_recording_starts() {
    use std::os::unix::fs::MetadataExt;

    // This process's uid, as the owner of a file it just made (no nix dependency here).
    let probe = tempfile_in_temp_dir();
    let euid = std::fs::metadata(&probe).unwrap().uid();
    std::fs::remove_file(&probe).unwrap();
    let h;
    let other = if euid == 0 {
        h = Harness::with_securing(None, true, true).await;
        let root = disk_root(&h);
        std::fs::create_dir_all(&root).unwrap();
        std::os::unix::fs::chown(&root, Some(65534), Some(65534)).unwrap();
        set_mode(&root, 0o777);
        root
    } else {
        let other = ["/tmp", "/var/tmp", "/dev/shm"]
            .into_iter()
            .find(|p| {
                std::fs::metadata(p)
                    .is_ok_and(|m| m.is_dir() && m.uid() != euid && m.mode() & 0o1777 == 0o1777)
            })
            .expect("a world-writable directory owned by another user");
        h = Harness::with_disk_path(None, true, true, other).await;
        PathBuf::from(other)
    };
    let other = other.as_path();
    let before = (mode_of(other), std::fs::metadata(other).unwrap().uid());
    let session = other.join(h.session_id.to_string());

    let started = start_named(&h).await;
    let session_mode = std::fs::metadata(&session).map(|m| {
        use std::os::unix::fs::PermissionsExt;
        m.permissions().mode() & 0o7777
    });
    let recording = started.unwrap().unwrap();
    h.wait_for_writers(2).await;
    drop(recording);
    h.wait_for_writers(0).await;
    let _ = std::fs::remove_dir_all(&session);

    let after = (mode_of(other), std::fs::metadata(other).unwrap().uid());
    assert_eq!(after, before, "{} is untouched", other.display());
    assert_eq!(session_mode.unwrap() & !0o750, 0);
}

/// The directories Warpgate makes fail closed: a symlink where the session or the
/// recording directory goes makes the start fail, and nothing behind it is created
/// or chmodded.
#[tokio::test]
async fn a_symlinked_session_or_recording_directory_fails_the_start() {
    for symlinked_leaf in [false, true] {
        let h = Harness::with_securing(None, true, true).await;
        let base = disk_root(&h);
        let session = base.join(h.session_id.to_string());
        let elsewhere = h.root.join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        set_mode(&elsewhere, 0o777);
        if symlinked_leaf {
            std::fs::create_dir_all(&session).unwrap();
            std::os::unix::fs::symlink(&elsewhere, session.join(NAME)).unwrap();
        } else {
            std::fs::create_dir_all(&base).unwrap();
            std::os::unix::fs::symlink(&elsewhere, &session).unwrap();
        }

        let started = start_named(&h).await;
        assert!(started.is_err(), "symlinked leaf: {symlinked_leaf}");
        assert_eq!(
            mode_of(&elsewhere),
            0o777,
            "symlinked leaf: {symlinked_leaf}"
        );
        let created: Vec<_> = std::fs::read_dir(&elsewhere)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert!(
            created.is_empty(),
            "symlinked leaf: {symlinked_leaf}: created through the link: {created:?}"
        );
    }
}

/// Run as root, Warpgate refuses a session directory below the recordings root that
/// another user owns, rather than tightening and using it: the start fails and the
/// directory is neither chmodded nor written into. Only root can chown the directory
/// to uid 65534, so as any other user this test checks nothing and says so; the same
/// refusal as a user is checked in warpgate-common
/// (`a_child_owned_by_someone_else_is_an_error`).
#[tokio::test]
async fn as_root_a_session_directory_owned_by_someone_else_fails_the_start() {
    use std::os::unix::fs::MetadataExt;

    let probe = tempfile_in_temp_dir();
    let euid = std::fs::metadata(&probe).unwrap().uid();
    std::fs::remove_file(&probe).unwrap();
    if euid != 0 {
        eprintln!(
            "as_root_a_session_directory_owned_by_someone_else_fails_the_start: running as \
             uid {euid}, who cannot chown a directory to another user, so nothing is checked \
             here; the run as root checks it"
        );
        return;
    }

    let h = Harness::with_securing(None, true, true).await;
    let session = disk_root(&h).join(h.session_id.to_string());
    std::fs::create_dir_all(&session).unwrap();
    std::os::unix::fs::chown(&session, Some(65534), Some(65534)).unwrap();
    set_mode(&session, 0o777);

    let err = start_named(&h).await.err().expect("the start fails");
    let message = format!("{err}");
    assert!(message.contains("owned by uid 65534"), "{message}");
    assert_eq!(mode_of(&session), 0o777);
    assert_eq!(std::fs::read_dir(&session).unwrap().count(), 0);
}

/// The raw OS error of the first `std::io::Error` in `err`'s source chain.
fn raw_os_error(err: &(dyn std::error::Error + 'static)) -> Option<i32> {
    let mut current = Some(err);
    while let Some(e) = current {
        if let Some(io) = e.downcast_ref::<std::io::Error>() {
            return io.raw_os_error();
        }
        current = e.source();
    }
    None
}

/// A symlink in place of a recording file fails the start under the flag: the file
/// must be new (`O_CREAT | O_EXCL`, which never follows a symlink), so nothing behind
/// the link is written or chmodded.
#[tokio::test]
async fn a_symlinked_recording_file_fails_the_start() {
    for s3 in [false, true] {
        let h = Harness::with_securing(s3.then(FakeS3::default), true, true).await;
        let base = if s3 { scratch_root(&h) } else { disk_root(&h) };
        let leaf = base.join(h.session_id.to_string()).join(NAME);
        std::fs::create_dir_all(&leaf).unwrap();
        let elsewhere = h.root.join("elsewhere");
        std::fs::write(&elsewhere, b"kept").unwrap();
        set_mode(&elsewhere, 0o666);
        std::os::unix::fs::symlink(&elsewhere, leaf.join(RecordingFile::NDJsonData.filename()))
            .unwrap();

        let err = start_named(&h).await.err().expect("the start fails");
        assert_eq!(raw_os_error(&err), Some(EEXIST), "s3: {s3}: {err:?}");
        assert_eq!(mode_of(&elsewhere), 0o666, "s3: {s3}");
        assert_eq!(std::fs::read(&elsewhere).unwrap(), b"kept", "s3: {s3}");
    }
}

/// The ACL entries of `path`, numeric, without comments or effective rights.
fn acl_entries(path: &Path) -> Vec<String> {
    let output = std::process::Command::new("getfacl")
        .args(["-n", "-c", "-E", "-p"])
        .arg(path)
        .output()
        .unwrap_or_else(|e| panic!("running getfacl (is the acl package installed?): {e}"));
    assert!(
        output.status.success(),
        "getfacl {}: {}",
        path.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Puts the ACL that grants the reader on `root`: execute on the root, and a default
/// ACL giving `reader` read on files and read + execute on directories, nothing to the
/// owning group or others. An error saying why when ACLs are not available here.
fn grant_reader_by_default_acl(root: &Path, reader: u32) -> std::result::Result<(), String> {
    set_acl(root, &["-m", &format!("u:{reader}:x")])?;
    set_acl(
        root,
        &["-d", "-m", &format!("u::rwx,g::---,o::---,u:{reader}:rX")],
    )
}

/// Runs `setfacl ARGS path`. An error saying why when ACLs are not available here.
fn set_acl(path: &Path, args: &[&str]) -> std::result::Result<(), String> {
    let output = std::process::Command::new("setfacl")
        .args(args)
        .arg(path)
        .output()
        .map_err(|e| format!("running setfacl (is the acl package installed?): {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "setfacl {args:?} {} failed (no ACL support on this filesystem?): {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

/// Set to `1` to let the real-ACL tests skip where ACLs are not available. Without
/// it, missing `setfacl` / `getfacl` or ACL support fails the test.
const SKIP_ACL_TEST: &str = "WARPGATE_TEST_SKIP_ACL";

/// Fails the test `test` because ACLs are not available here (`why`), unless
/// [`SKIP_ACL_TEST`] is `1`, which turns that into a skip that says so.
fn acl_unavailable(test: &str, why: &str) {
    assert!(
        std::env::var_os(SKIP_ACL_TEST).is_some_and(|v| v == "1"),
        "{why}. This test needs POSIX ACLs; set {SKIP_ACL_TEST}=1 to skip it where \
         they are not available"
    );
    eprintln!("SKIPPED {test} ({SKIP_ACL_TEST}=1): {why}; nothing was asserted");
}

/// The bits of an ACL entry's rights (`rwx`, `r-x`, `---`, ...).
fn acl_bits(rights: &str) -> u32 {
    rights
        .chars()
        .zip([4, 2, 1])
        .map(|(c, bit)| if c == '-' { 0 } else { bit })
        .sum()
}

/// Asserts that `path`'s mode is within `ceiling` and that its access ACL's effective
/// rights are too: every named entry and the owning-group entry, limited by the mask,
/// within the ceiling's group bits, and the other entry within its other bits. With a
/// ceiling of 0750 or 0640 nobody but the owner can write. Default entries grant no
/// access to `path` itself and are not checked.
fn assert_effective_rights_within(path: &Path, ceiling: u32) {
    let mode = mode_of(path);
    assert_eq!(
        mode & !ceiling,
        0,
        "{}: mode {mode:o} is wider than {ceiling:o}",
        path.display()
    );
    let acl = acl_entries(path);
    let entries: Vec<(&str, &str, u32)> = acl
        .iter()
        .filter(|e| !e.starts_with("default:"))
        .map(|e| {
            let mut parts = e.splitn(3, ':');
            let (Some(tag), Some(qualifier), Some(rights)) =
                (parts.next(), parts.next(), parts.next())
            else {
                panic!("{}: unexpected ACL entry {e:?}", path.display());
            };
            (tag, qualifier, acl_bits(rights))
        })
        .collect();
    let mask = entries
        .iter()
        .find(|(tag, _, _)| *tag == "mask")
        .map_or(0o7, |(_, _, bits)| *bits);
    for (tag, qualifier, bits) in &entries {
        let (effective, allowed) = match *tag {
            "user" if qualifier.is_empty() => continue,
            "mask" => continue,
            "other" => (*bits, ceiling & 0o7),
            "user" | "group" => (bits & mask, (ceiling >> 3) & 0o7),
            _ => panic!("{}: unexpected ACL entry tag {tag:?}", path.display()),
        };
        assert_eq!(
            effective & !allowed,
            0,
            "{}: {tag}:{qualifier} has effective rights {effective:o}, beyond {allowed:o}: {acl:?}",
            path.display()
        );
    }
}

/// Made-up ids for named ACL entries: no such user or group needs to exist, so the
/// ACL tests that use them check the same as root and as any user.
const NAMED_USER: u32 = 4242;
const NAMED_GROUP: u32 = 4343;

/// A default ACL on the recordings root that grants write to a named user, a named
/// group, the owning group and others does not widen what Warpgate creates under the
/// flag: the session directory, the recording directory and both recording files end
/// within 0750 / 0640 by their effective rights, mask included, so nobody but the
/// owner can write and others get nothing. Under a default ACL the kernel ignores the
/// umask, so only Warpgate's creation modes and masking bound them. The named ids are
/// made up and the root is this process's own, so this checks the same as root and as
/// any user. Fails where ACLs are not available, unless [`SKIP_ACL_TEST`] is `1`.
#[tokio::test]
async fn a_default_acl_granting_write_does_not_widen_new_recordings() {
    for s3 in [false, true] {
        let h = Harness::with_securing(s3.then(FakeS3::default), true, true).await;
        let base = if s3 { scratch_root(&h) } else { disk_root(&h) };
        std::fs::create_dir_all(&base).unwrap();
        set_mode(&base, 0o700);
        let default_acl =
            format!("u::rwx,g::rwx,o::rwx,u:{NAMED_USER}:rwx,g:{NAMED_GROUP}:rwx,m::rwx");
        if let Err(why) = set_acl(&base, &["-d", "-m", &default_acl]) {
            acl_unavailable(
                "a_default_acl_granting_write_does_not_widen_new_recordings",
                &why,
            );
            return;
        }

        let recording = start_named(&h).await.unwrap().unwrap();
        h.wait_for_writers(2).await;
        let session = base.join(h.session_id.to_string());
        let leaf = session.join(NAME);

        // The default ACL did apply: the write-granting entries were inherited, so
        // only the mask and the mode stand between them and a write.
        for dir in [&session, &leaf] {
            let acl = acl_entries(dir);
            for entry in [
                format!("user:{NAMED_USER}:rwx"),
                format!("group:{NAMED_GROUP}:rwx"),
            ] {
                assert!(
                    acl.contains(&entry),
                    "s3: {s3}: {} did not inherit {entry}: {acl:?}",
                    dir.display()
                );
            }
            assert_effective_rights_within(dir, 0o750);
        }
        for file in [RecordingFile::NDJsonData, RecordingFile::Index] {
            let file = leaf.join(file.filename());
            let acl = acl_entries(&file);
            assert!(
                acl.contains(&format!("user:{NAMED_USER}:rwx")),
                "s3: {s3}: {} did not inherit the named entry: {acl:?}",
                file.display()
            );
            assert_effective_rights_within(&file, 0o640);
        }

        drop(recording);
        h.wait_for_writers(0).await;
    }
}

/// A recordings root that already has an access ACL granting write (to a named user, a
/// named group and the owning group) is tightened through its mask: under the flag the
/// root's mode becomes `current & 0750`, and on a root with an ACL the group bits are
/// the ACL mask. The named entries are left in place (neither removed nor refused), but
/// the mask caps their effective rights at r-x, others get nothing, and the recording
/// starts. The named ids are made up and the root is this process's own, so this
/// checks the same as root and as any user. Fails where ACLs are not available,
/// unless [`SKIP_ACL_TEST`] is `1`.
#[tokio::test]
async fn a_root_access_acl_granting_write_is_capped_by_its_mask() {
    for s3 in [false, true] {
        let h = Harness::with_securing(s3.then(FakeS3::default), true, true).await;
        let base = if s3 { scratch_root(&h) } else { disk_root(&h) };
        std::fs::create_dir_all(&base).unwrap();
        set_mode(&base, 0o777);
        let access_acl = format!("g::rwx,u:{NAMED_USER}:rwx,g:{NAMED_GROUP}:rwx,m::rwx");
        if let Err(why) = set_acl(&base, &["-m", &access_acl]) {
            acl_unavailable(
                "a_root_access_acl_granting_write_is_capped_by_its_mask",
                &why,
            );
            return;
        }
        assert_eq!(mode_of(&base), 0o777, "s3: {s3}: the root starts wide");

        let recording = start_named(&h).await.unwrap().unwrap();
        h.wait_for_writers(2).await;

        assert_eq!(mode_of(&base), 0o750, "s3: {s3}");
        let acl = acl_entries(&base);
        for entry in [
            format!("user:{NAMED_USER}:rwx"),
            format!("group:{NAMED_GROUP}:rwx"),
            "group::rwx".to_owned(),
            "mask::r-x".to_owned(),
            "other::---".to_owned(),
        ] {
            assert!(
                acl.contains(&entry),
                "s3: {s3}: root lacks {entry}: {acl:?}"
            );
        }
        assert_effective_rights_within(&base, 0o750);

        drop(recording);
        h.wait_for_writers(0).await;
    }
}

/// End to end on a real default ACL (this process's own uid stands in for the
/// reader): with the flag, a new directory's ACL mask is r-x and a new file's r--,
/// so the named reader can read, while the owning group and others get nothing.
/// Without the flag, the exact chmod empties the mask. Fails where ACLs are not
/// available, unless [`SKIP_ACL_TEST`] is `1`, which turns that into a skip.
/// Under a default ACL the kernel ignores the umask, so this holds under umask 0077
/// as under any other.
#[tokio::test]
async fn a_default_acl_reader_keeps_read_and_nobody_else_gains_it() {
    use std::os::unix::fs::MetadataExt;

    let probe = tempfile_in_temp_dir();
    let reader = std::fs::metadata(&probe).unwrap().uid();
    std::fs::remove_file(&probe).unwrap();

    for keep_group_read in [true, false] {
        let h = Harness::with_securing(None, true, keep_group_read).await;
        let base = disk_root(&h);
        std::fs::create_dir_all(&base).unwrap();
        set_mode(&base, 0o700);
        if let Err(why) = grant_reader_by_default_acl(&base, reader) {
            acl_unavailable(
                "a_default_acl_reader_keeps_read_and_nobody_else_gains_it",
                &why,
            );
            return;
        }

        let recording = start_named(&h).await.unwrap().unwrap();
        h.wait_for_writers(2).await;
        let session = base.join(h.session_id.to_string());
        let leaf = session.join(NAME);
        let file = leaf.join(RecordingFile::NDJsonData.filename());
        let named = format!("user:{reader}:r-x");

        // Without the flag only the recording directory is chmodded.
        let dirs = if keep_group_read {
            vec![&session, &leaf]
        } else {
            vec![&leaf]
        };
        for dir in dirs {
            let acl = acl_entries(dir);
            let expected_mask = if keep_group_read {
                "mask::r-x"
            } else {
                "mask::---"
            };
            for entry in [named.as_str(), "group::---", "other::---", expected_mask] {
                assert!(
                    acl.iter().any(|e| e == entry),
                    "flag {keep_group_read}: {} lacks {entry}: {acl:?}",
                    dir.display()
                );
            }
        }
        let acl = acl_entries(&file);
        let expected_mask = if keep_group_read {
            "mask::r--"
        } else {
            "mask::---"
        };
        for entry in [named.as_str(), "group::---", "other::---", expected_mask] {
            assert!(
                acl.iter().any(|e| e == entry),
                "flag {keep_group_read}: file lacks {entry}: {acl:?}"
            );
        }
        let expected_mode = if keep_group_read { 0o640 } else { 0o600 };
        assert_eq!(mode_of(&file), expected_mode, "flag {keep_group_read}");

        drop(recording);
        h.wait_for_writers(0).await;
    }
}

fn tempfile_in_temp_dir() -> PathBuf {
    let probe = std::env::temp_dir().join(format!("wg-uid-probe-{}", Uuid::new_v4()));
    std::fs::write(&probe, b"").unwrap();
    probe
}

fn failed_recording_lines(session: &TargetSessionId) -> Vec<HashMap<&'static str, String>> {
    test_support::failed_recording_lines(session)
}

fn test_owner() -> RecordingOwner {
    RecordingOwner {
        protocol: "ssh",
        user: "alice".into(),
        target: "db-host".into(),
    }
}

/// A harness whose recordings refuse unrecorded sessions when `required`.
async fn harness_requiring(required: bool) -> Harness {
    let mut h = Harness::new(None).await;
    let params = GlobalParams::new(h.root.join("warpgate.yaml"), false)
        .unwrap()
        .with_refuse_unrecorded_sessions(required);
    h.recordings = SessionRecordings::new(h.db.clone(), &params);
    h
}

/// Writes to `recorder` until a write fails, as a session would keep doing.
async fn write_until_failure(recorder: &TerminalRecorder) -> Error {
    for _ in 0..1000 {
        if let Err(error) = recorder
            .write(TerminalRecordingStreamId::Output, b"output")
            .await
        {
            return error;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("the recording never failed");
}

/// A write failure after a good start (here, a full disk) is logged once per
/// recording with the pinned line, `stage=write`, and counted; every later write
/// fails at once, and `write_failed` returns the setting each time.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_recording_failing_mid_session_is_reported_once_and_counted() {
    for required in [false, true] {
        crate::approvals::tests::audit_events();
        let h = harness_requiring(required).await;
        let recorder: TerminalRecorder = h
            .recordings
            .start_for(&test_owner(), &h.session_id, None, ())
            .await
            .unwrap()
            .unwrap();
        recorder
            .write(TerminalRecordingStreamId::Output, b"before")
            .await
            .unwrap();
        assert!(
            test_support::fail_open_recording_files(&h.root) >= 2,
            "the data and index files were broken"
        );

        let error = write_until_failure(&recorder).await;
        assert!(matches!(error, Error::Closed), "{error}");
        for _ in 0..3 {
            assert_eq!(recorder.write_failed(&error), required);
            assert!(
                recorder
                    .write(TerminalRecordingStreamId::Input, b"more")
                    .await
                    .is_err()
            );
        }
        drop(recorder);
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert_eq!(h.recordings.failed_recordings(), 1);
        let lines = failed_recording_lines(&h.session_id);
        assert_eq!(lines.len(), 1, "{lines:?}");
        let line = &lines[0];
        assert_eq!(line["protocol"], "ssh");
        assert_eq!(line["user"], "alice");
        assert_eq!(line["target"], "db-host");
        assert_eq!(line["stage"], "write");
        assert_eq!(line["required"], required.to_string());
        assert_eq!(line["total"], "1");
        assert!(
            line["cause"].contains("No space left on device"),
            "the real cause, not the closed queue: {line:?}"
        );
    }
}

/// A recording that cannot start is logged with the same pinned line,
/// `stage=start`, and counted in the same total.
#[tokio::test]
async fn a_recording_failing_to_start_is_reported_with_the_same_line() {
    crate::approvals::tests::audit_events();
    let h = harness_requiring(true).await;
    // The session's directory is a regular file, so the recording's cannot be made.
    let session_dir = h
        .root
        .join("data/recordings")
        .join(h.session_id.to_string());
    std::fs::create_dir_all(session_dir.parent().unwrap()).unwrap();
    std::fs::write(&session_dir, "not a directory").unwrap();

    let result = h
        .recordings
        .start_for::<TerminalRecorder, _>(&test_owner(), &h.session_id, None, ())
        .await;
    assert!(result.is_err());
    assert_eq!(h.recordings.failed_recordings(), 1);
    let lines = failed_recording_lines(&h.session_id);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0]["stage"], "start");
    assert_eq!(lines[0]["required"], "true");
    assert_eq!(lines[0]["total"], "1");
    assert_eq!(lines[0]["user"], "alice");
}

/// Writers closing because Warpgate shuts down is not a failed recording.
#[tokio::test]
async fn writers_closed_by_shutdown_are_not_reported() {
    crate::approvals::tests::audit_events();
    let h = harness_requiring(false).await;
    let recorder: TerminalRecorder = h
        .recordings
        .start_for(&test_owner(), &h.session_id, None, ())
        .await
        .unwrap()
        .unwrap();
    h.recordings.shutdown().await;
    let error = write_until_failure(&recorder).await;
    recorder.write_failed(&error);
    assert_eq!(h.recordings.failed_recordings(), 0);
    assert!(failed_recording_lines(&h.session_id).is_empty());
}

/// A real write failure in the shutdown drain is a failed recording: it is
/// reported with the pinned line and counted, like any other.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_write_failing_in_the_shutdown_drain_is_reported() {
    crate::approvals::tests::audit_events();
    let h = harness_requiring(false).await;
    let recorder: TerminalRecorder = h
        .recordings
        .start_for(&test_owner(), &h.session_id, None, ())
        .await
        .unwrap()
        .unwrap();
    assert!(test_support::fail_open_recording_files(&h.root) >= 2);
    // Queued without yielding (a current-thread runtime), so the writer task
    // first sees them once the shutdown has begun.
    for _ in 0..3 {
        recorder
            .write(TerminalRecordingStreamId::Output, b"queued")
            .await
            .unwrap();
    }
    h.recordings.shutdown().await;
    assert_eq!(h.recordings.failed_recordings(), 1);
    let lines = failed_recording_lines(&h.session_id);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0]["stage"], "write");
    assert!(
        lines[0]["cause"].contains("No space left on device"),
        "{lines:?}"
    );
}

/// A failed S3 push is a failed recording, reported at once (not only when the
/// upload fails to complete at the end) with the pinned line, and counted.
/// Required: the writer stops, so the session's next write fails and it closes.
/// Not required: the local scratch goes on being written, and is kept.
#[tokio::test]
async fn a_failed_s3_push_is_reported_and_follows_the_setting() {
    for required in [false, true] {
        crate::approvals::tests::audit_events();
        let mut h = Harness::new(Some(FakeS3 {
            fail_part: Some(("data.ndjson", 1)),
            ..Default::default()
        }))
        .await;
        let params = GlobalParams::new(h.root.join("warpgate.yaml"), false)
            .unwrap()
            .with_refuse_unrecorded_sessions(required);
        h.recordings = SessionRecordings::new(h.db.clone(), &params);
        let recorder: TerminalRecorder = h
            .recordings
            .start_for(&test_owner(), &h.session_id, None, ())
            .await
            .unwrap()
            .unwrap();
        // More than one S3 part, so the first part is pushed, and fails.
        let chunk = vec![b'x'; 64 * 1024];
        for _ in 0..96 {
            recorder
                .write(TerminalRecordingStreamId::Output, &chunk)
                .await
                .unwrap();
        }
        for _ in 0..1000 {
            if h.recordings.failed_recordings() > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(h.recordings.failed_recordings(), 1, "required={required}");
        let lines = failed_recording_lines(&h.session_id);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert_eq!(lines[0]["stage"], "write");
        assert_eq!(lines[0]["required"], required.to_string());
        assert!(lines[0]["cause"].contains("S3"), "{lines:?}");

        if required {
            let error = write_until_failure(&recorder).await;
            assert!(matches!(error, Error::Closed), "{error}");
            assert!(recorder.write_failed(&error), "the session must close");
        } else {
            for _ in 0..20 {
                recorder
                    .write(TerminalRecordingStreamId::Output, b"later")
                    .await
                    .unwrap();
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            drop(recorder);
            h.wait_for_writers(0).await;
            assert!(exists(&h.scratch(RecordingFile::NDJsonData).await));
            assert_eq!(h.ended().await, None);
        }
        assert_eq!(
            failed_recording_lines(&h.session_id).len(),
            1,
            "reported once"
        );
    }
}
