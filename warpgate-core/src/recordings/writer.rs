use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use sea_orm::{ActiveModelTrait, DatabaseConnection, DbErr, EntityTrait};
use serde::Serialize;
use time::OffsetDateTime;
use tokio::sync::{Mutex, RwLock, broadcast, mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::error;
use uuid::Uuid;
use warpgate_common::try_block;
use warpgate_db_entities::Recording;

use super::storage::RecordingSink;
use super::{Error, FailureReporter, LiveMap, Result};

/// Capacity of both the disk-write queue and the live broadcast ring. They must
/// stay equal: the live-stream lag heal relies on any item dropped from the
/// broadcast ring already having left the disk queue (so it is on disk, or at
/// most one item is mid-write). That holds only because a producer blocks on the
/// full disk queue before it can broadcast, so the ring cannot outrun the queue
/// by more than its own capacity. Raising the ring above the queue breaks it.
const RECORDING_QUEUE_CAPACITY: usize = 1024;

/// One item of a recording's primary data stream, broadcast to live viewers.
/// `offset` is the total bytes written through this item (its end position in
/// `data.ndjson`), so a viewer that loaded a snapshot covering the first `N`
/// bytes keeps only chunks with `offset > N` — splicing the live tail onto the
/// snapshot with neither a gap nor a duplicate. Both players use this: the
/// snapshot boundary is the `Content-Length` of the raw file they fetched.
#[derive(Clone, Debug)]
pub struct LiveChunk {
    pub offset: u64,
    pub data: Bytes,
}

/// What a writer's queue carries to its task.
enum Queued {
    Data(Bytes),
    /// Answered once everything queued before it is written and flushed; dropped
    /// unanswered when the recording has failed.
    Flush(oneshot::Sender<()>),
}

#[derive(Clone)]
pub struct RawRecordingWriter {
    sender: mpsc::Sender<Queued>,
    live_sender: broadcast::Sender<LiveChunk>,
    /// Running byte offset to hand out. Live viewers rely on this matching the
    /// on-disk byte order, which holds because every write to a recording is
    /// serialized by `NDJsonRecordingWriter`'s `buf` lock: that writer is not
    /// `Clone`, so tasks share the one instance (through an `Arc`) and its single
    /// lock, and the counter can't diverge from disk order.
    offset: Arc<AtomicU64>,
    drop_signal: mpsc::Sender<()>,
    /// Shared by every writer of this recording.
    reporter: Arc<FailureReporter>,
}

impl RawRecordingWriter {
    pub(crate) async fn new(
        mut sink: RecordingSink,
        live: Option<LiveMap>,
        shutdown: WriterShutdown,
        ticket: WriterTicket,
        reporter: Arc<FailureReporter>,
    ) -> Result<Self> {
        let recording_id = ticket.recording_id();
        let (sender, mut receiver) = mpsc::channel::<Queued>(RECORDING_QUEUE_CAPACITY);
        let (drop_signal, mut drop_receiver) = mpsc::channel(1);
        let WriterShutdown { token, tracker } = shutdown;

        // Register in the live-subscription map only when this file is the live stream
        // (see `RecordingWriterOpener::open`). Sidecars pass `None` so they don't clobber
        // the data writer's entry, which shares the same recording id.
        let live_sender = broadcast::channel(RECORDING_QUEUE_CAPACITY).0;
        if let Some(live) = live {
            {
                let mut live = live.lock().await;
                live.insert(recording_id, live_sender.clone());
            }
            tokio::spawn({
                let id = recording_id;
                async move {
                    let _ = drop_receiver.recv().await;
                    let mut live = live.lock().await;
                    live.remove(&id);
                }
            });
        }

        let task_reporter = reporter.clone();
        tracker.spawn(async move {
            let mut written = true;
            try_block!(async {
                let mut last_flush = Instant::now();
                loop {
                    if last_flush.elapsed() > Duration::from_secs(5) {
                        last_flush = Instant::now();
                        sink.flush().await?;
                    }
                    tokio::select! {
                        item = receiver.recv() => match item {
                            Some(item) => {
                                if write_queued(&mut sink, item, &task_reporter).await? {
                                    last_flush = Instant::now();
                                }
                            }
                            None => break,
                        },
                        () = token.cancelled() => break,
                        () = tokio::time::sleep(Duration::from_millis(5000)) => ()
                    }
                }

                // Drain receiver in case writer was shut down
                while let Ok(item) = receiver.try_recv() {
                    write_queued(&mut sink, item, &task_reporter).await?;
                }
                Ok::<(), anyhow::Error>(())
            } catch (error: anyhow::Error) {
                written = false;
                // Reported before the queue closes, so the line carries the real
                // cause rather than a writer's later "Writer is closed". Reported
                // even during shutdown: the drain's writes are real ones.
                task_reporter.sink_failed(&format_args!("{error:#}"));
                // Every later write then fails at once instead of filling the
                // queue and blocking its session while the sink finalizes, and a
                // waiting flush is answered (as failed) now.
                receiver.close();
                while receiver.try_recv().is_ok() {}
            });

            // Crashed writer leaves the recording scratch as-is
            try_block!(async {
                let scratch = sink.finalize().await?;
                if written {
                    ticket.finished(scratch).await?;
                }
                Ok::<(), Error>(())
            } catch (error: Error) {
                error!(%error, "Failed to finalize recording");
                task_reporter.sink_failed(&error);
            });
        });

        Ok(Self {
            sender,
            live_sender,
            offset: Arc::new(AtomicU64::new(0)),
            drop_signal,
            reporter,
        })
    }

    /// Reports this recording's failure (`cause`, typically the error a write
    /// returned) with the [`super::log_text::SESSION_RECORDING_FAILED`] line, unless
    /// it was already reported. Returns whether the session must now be closed.
    pub fn write_failed(&self, cause: &dyn std::fmt::Display) -> bool {
        self.reporter.write_failed(cause)
    }

    pub async fn write(&self, data: &[u8]) -> Result<()> {
        let data = Bytes::from(data.to_vec());
        self.sender
            .send(Queued::Data(data.clone()))
            .await
            .map_err(|_| Error::Closed)?;
        // Tag with the end byte offset (bytes written through this item) after it
        // is durably queued, so a live viewer's offset matches the on-disk order.
        let offset = self.offset.fetch_add(data.len() as u64, Ordering::SeqCst) + data.len() as u64;
        let _ = self.live_sender.send(LiveChunk { offset, data });
        Ok(())
    }
}

impl RawRecordingWriter {
    /// Waits until everything written so far has reached the sink and been
    /// flushed. [`Error::Closed`] when the recording has failed (its real cause is
    /// already reported) or is closing.
    pub async fn flush(&self) -> Result<()> {
        let (ack, acked) = oneshot::channel();
        self.sender
            .send(Queued::Flush(ack))
            .await
            .map_err(|_| Error::Closed)?;
        acked.await.map_err(|_| Error::Closed)
    }
}

/// Writes one queued item. `true` when it was a flush.
///
/// A failed S3 push is a failed recording, reported at once. When unrecorded
/// sessions are refused it ends the writer like any other failure (its session then
/// closes at its next write); otherwise the local scratch goes on being written,
/// and is kept, since the upload cannot be completed.
async fn write_queued(
    sink: &mut RecordingSink,
    item: Queued,
    reporter: &FailureReporter,
) -> Result<bool> {
    match item {
        Queued::Data(bytes) => {
            match sink.write_all(&bytes).await {
                Err(error @ Error::S3Push(_)) if !reporter.required() => {
                    reporter.sink_failed(&error);
                }
                result => result?,
            }
            Ok(false)
        }
        Queued::Flush(ack) => {
            sink.flush().await?;
            let _ = ack.send(());
            Ok(true)
        }
    }
}

impl Drop for RawRecordingWriter {
    fn drop(&mut self) {
        let signal = std::mem::replace(&mut self.drop_signal, mpsc::channel(1).0);
        tokio::spawn(async move { signal.send(()).await });
    }
}

pub struct NDJsonRecordingWriter {
    pub(crate) inner: RawRecordingWriter,
    buf: RwLock<Vec<u8>>,
}

impl NDJsonRecordingWriter {
    pub(crate) fn new(inner: RawRecordingWriter) -> Self {
        Self {
            inner,
            buf: RwLock::new(Vec::new()),
        }
    }

    /// As [`RawRecordingWriter::write_failed`].
    pub fn write_failed(&self, cause: &dyn std::fmt::Display) -> bool {
        self.inner.write_failed(cause)
    }

    /// As [`RawRecordingWriter::flush`].
    pub async fn flush(&self) -> Result<()> {
        self.inner.flush().await
    }

    /// Writes an empty line, which NDJSON readers skip: a recording's first write
    /// when it must show at once that its file accepts writes.
    pub async fn write_empty_line(&self) -> Result<()> {
        let _order = self.buf.write().await;
        self.inner.write(b"\n").await
    }

    pub async fn write_json_line<I: Serialize>(&self, value: I) -> Result<usize> {
        let buf = &mut self.buf.write().await;
        buf.clear();
        serde_json::to_writer(&mut **buf, &value).map_err(Error::Serialization)?;
        buf.push(b'\n');
        self.inner.write(buf).await?;
        Ok(buf.len())
    }
}

mod completion {
    use super::*;

    pub struct WriterShutdown {
        pub token: CancellationToken,
        pub tracker: TaskTracker,
    }

    /// One completion struct shared by multiple writers (index, data) of one recording
    /// Writers get completion tickets via register_writer and the last ticket to close finalizes the DB entry
    pub struct RecordingCompletion {
        db: DatabaseConnection,
        recording_id: Uuid,
        state: Mutex<CompletionState>,
    }

    #[derive(Default)]
    struct CompletionState {
        open_writers: usize,
        /// Scratch files of the finished writers to be removed on completion
        scratch_paths: Vec<PathBuf>,
    }

    impl RecordingCompletion {
        pub fn new(db: DatabaseConnection, recording_id: Uuid) -> Arc<Self> {
            Arc::new(Self {
                db,
                recording_id,
                state: Mutex::default(),
            })
        }

        pub async fn register_writer(self: &Arc<Self>) -> WriterTicket {
            self.state.lock().await.open_writers += 1;
            WriterTicket {
                completion: self.clone(),
            }
        }
    }

    /// A ticket dropped without [`Self::finished`] keeps its recording from ever ending.
    #[must_use]
    pub struct WriterTicket {
        completion: Arc<RecordingCompletion>,
    }

    impl WriterTicket {
        pub fn recording_id(&self) -> Uuid {
            self.completion.recording_id
        }

        /// Hands over the writer's scratch path. The last ticket to finish marks the
        /// recording ended and only then removes every scratch, so a failure before
        /// that point leaves them all in place.
        pub async fn finished(self, scratch: Option<PathBuf>) -> Result<()> {
            use sea_orm::ActiveValue::Set;

            let completion = &self.completion;
            {
                let mut state = completion.state.lock().await;
                state.scratch_paths.extend(scratch);
                state.open_writers = state.open_writers.saturating_sub(1);
                if state.open_writers > 0 {
                    return Ok(());
                }
            }

            let recording = Recording::Entity::find_by_id(completion.recording_id)
                .one(&completion.db)
                .await?
                .ok_or_else(|| {
                    DbErr::RecordNotFound(format!("recording {}", completion.recording_id))
                })?;
            let mut model: Recording::ActiveModel = recording.into();
            model.ended = Set(Some(OffsetDateTime::now_utc()));
            model.update(&completion.db).await?;

            let scratch_paths = std::mem::take(&mut completion.state.lock().await.scratch_paths);
            for path in scratch_paths {
                if let Err(error) = tokio::fs::remove_file(&path).await {
                    error!(%error, ?path, "Failed to remove local recording scratch");
                }
            }
            Ok(())
        }
    }
}

pub use completion::{RecordingCompletion, WriterShutdown, WriterTicket};
