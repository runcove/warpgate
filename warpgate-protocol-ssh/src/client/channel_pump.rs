use std::future::Future;
use std::ops::ControlFlow;

use tokio::sync::mpsc::UnboundedReceiver;

use super::error::SshClientError;
use crate::ChannelOperation;

/// The target-bound half of a channel.
pub(super) trait TargetWriter: Send + Sync {
    /// Applies one operation. A write waits for the target's window, so this
    /// can take as long as the target takes to read. `Break` ends the channel.
    fn apply(
        &self,
        operation: ChannelOperation,
    ) -> impl Future<Output = Result<ControlFlow<()>, SshClientError>> + Send;
}

/// Applies the client's operations to the target in the order they arrived,
/// until the channel is closed.
async fn forward_operations<W: TargetWriter>(
    writer: &W,
    ops_rx: &mut UnboundedReceiver<ChannelOperation>,
) -> Result<(), SshClientError> {
    while let Some(operation) = ops_rx.recv().await {
        if writer.apply(operation).await?.is_break() {
            break;
        }
    }
    Ok(())
}

/// Runs a channel's two directions side by side: the client's operations
/// towards the target, and `target_events`, which reads what the target sends.
///
/// They must not share one loop. A write to the target waits for the target's
/// window, and a target such as `cat` stops reading its input while its output
/// is not being read; a loop that is parked in that write never reads the
/// output, so neither side moves. Ends when either direction ends.
pub(super) async fn pump<W, R>(
    writer: &W,
    ops_rx: &mut UnboundedReceiver<ChannelOperation>,
    target_events: R,
) -> Result<(), SshClientError>
where
    W: TargetWriter,
    R: Future<Output = Result<(), SshClientError>>,
{
    tokio::select! {
        result = forward_operations(writer, ops_rx) => result,
        result = target_events => result,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use bytes::Bytes;
    use tokio::sync::{Notify, mpsc};

    use super::*;

    const TIMEOUT: Duration = Duration::from_secs(5);
    const CHUNKS: usize = 50;

    /// A target that takes no input until its output has been read, like `cat`
    /// whose stdout pipe is full: every write waits on `reads_done`.
    struct StalledTarget {
        reads_done: Arc<Notify>,
        written: Mutex<Vec<String>>,
    }

    impl TargetWriter for StalledTarget {
        async fn apply(
            &self,
            operation: ChannelOperation,
        ) -> Result<ControlFlow<()>, SshClientError> {
            let entry = match operation {
                ChannelOperation::Data(data) => {
                    self.reads_done.notified().await;
                    self.reads_done.notify_one();
                    format!("data:{}", String::from_utf8_lossy(&data))
                }
                ChannelOperation::Eof => "eof".to_string(),
                ChannelOperation::Close => return Ok(ControlFlow::Break(())),
                other => format!("{other:?}"),
            };
            self.written.lock().unwrap().push(entry);
            Ok(ControlFlow::Continue(()))
        }
    }

    fn stalled_target() -> (Arc<StalledTarget>, Arc<Notify>) {
        let reads_done = Arc::new(Notify::new());
        let target = Arc::new(StalledTarget {
            reads_done: reads_done.clone(),
            written: Mutex::new(Vec::new()),
        });
        (target, reads_done)
    }

    /// The target's output, already queued, read through a queue that holds
    /// one chunk at a time. Returns how many chunks it read.
    async fn read_output(mut output: mpsc::Receiver<Bytes>) -> usize {
        let mut read = 0;
        while output.recv().await.is_some() {
            read += 1;
        }
        read
    }

    fn data(bytes: &'static [u8]) -> ChannelOperation {
        ChannelOperation::Data(Bytes::from_static(bytes))
    }

    fn queued_output() -> mpsc::Receiver<Bytes> {
        let (tx, rx) = mpsc::channel(CHUNKS);
        for _ in 0..CHUNKS {
            tx.try_send(Bytes::from_static(b"output")).unwrap();
        }
        rx
    }

    /// The target's output is drained while the client's input waits to be
    /// written, and the input then goes through, in order, with its EOF.
    #[tokio::test]
    async fn target_output_drains_while_client_input_waits_to_be_written() {
        let (target, reads_done) = stalled_target();
        let (ops_tx, mut ops_rx) = mpsc::unbounded_channel();
        ops_tx.send(data(b"a")).unwrap();
        ops_tx.send(data(b"b")).unwrap();
        ops_tx.send(ChannelOperation::Eof).unwrap();
        ops_tx.send(ChannelOperation::Close).unwrap();

        let events = async {
            let read = read_output(queued_output()).await;
            assert_eq!(read, CHUNKS);
            reads_done.notify_one();
            // The target keeps the channel open until the client closes it.
            std::future::pending::<Result<(), SshClientError>>().await
        };

        tokio::time::timeout(TIMEOUT, pump(&*target, &mut ops_rx, events))
            .await
            .expect("the channel stalled: output was not read while input waited")
            .unwrap();

        let written = target.written.lock().unwrap();
        assert_eq!(*written, ["data:a", "data:b", "eof"]);
    }

    /// The target closing its channel ends the pump even though a write to it
    /// never completes.
    #[tokio::test]
    async fn target_closing_ends_the_channel_while_input_waits_to_be_written() {
        let (target, _reads_done) = stalled_target();
        let (ops_tx, mut ops_rx) = mpsc::unbounded_channel();
        ops_tx.send(data(b"a")).unwrap();

        let events = async {
            read_output(queued_output()).await;
            Ok(())
        };

        tokio::time::timeout(TIMEOUT, pump(&*target, &mut ops_rx, events))
            .await
            .expect("the channel stayed open after the target closed it")
            .unwrap();
        drop(ops_tx);
    }
}
