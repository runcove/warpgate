//! Long-lived proxied HTTP traffic (websockets, streamed bodies) by the user and
//! target it runs for, so a revocation can end it without ending the browser
//! session that carries it.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

struct LiveStream {
    user_id: Uuid,
    target_id: Uuid,
    cancel: CancellationToken,
}

/// This node's live proxied HTTP requests, each under the user and target it
/// was authorized for.
#[derive(Clone, Default)]
pub struct LiveStreams {
    streams: Arc<Mutex<HashMap<u64, LiveStream>>>,
    next_id: Arc<AtomicU64>,
}

/// Keeps a request registered until it is dropped.
struct Registration {
    streams: LiveStreams,
    id: u64,
    cancel: CancellationToken,
}

impl Drop for Registration {
    fn drop(&mut self) {
        if let Ok(mut streams) = self.streams.streams.lock() {
            streams.remove(&self.id);
        }
    }
}

impl LiveStreams {
    fn register(&self, user_id: Uuid, target_id: Uuid) -> Registration {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let cancel = CancellationToken::new();
        if let Ok(mut streams) = self.streams.lock() {
            streams.insert(
                id,
                LiveStream {
                    user_id,
                    target_id,
                    cancel: cancel.clone(),
                },
            );
        }
        Registration {
            streams: self.clone(),
            id,
            cancel,
        }
    }

    /// `session_close` (the browser session's own close signal) extended:
    /// the returned receiver also fires when [`Self::cancel`] ends this
    /// user's streams to this target. The request stays registered until the
    /// receiver and every resubscription of it are dropped.
    pub fn watch(
        &self,
        mut session_close: broadcast::Receiver<()>,
        user_id: Uuid,
        target_id: Uuid,
    ) -> broadcast::Receiver<()> {
        let (tx, rx) = broadcast::channel(1);
        let registration = self.register(user_id, target_id);
        tokio::spawn(async move {
            tokio::select! {
                _ = session_close.recv() => {}
                () = registration.cancel.cancelled() => {}
                () = tx.closed() => return,
            }
            let _ = tx.send(());
        });
        rx
    }

    /// The distinct (user, target) pairs with live requests on this node.
    pub fn in_use(&self) -> HashSet<(Uuid, Uuid)> {
        self.streams
            .lock()
            .map(|streams| {
                streams
                    .values()
                    .map(|stream| (stream.user_id, stream.target_id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Ends this node's live requests by `user_id` to `target_id`; returns
    /// how many.
    pub fn cancel(&self, user_id: Uuid, target_id: Uuid) -> usize {
        self.streams
            .lock()
            .map(|streams| {
                let mut cancelled = 0;
                for stream in streams.values() {
                    if stream.user_id == user_id && stream.target_id == target_id {
                        stream.cancel.cancel();
                        cancelled += 1;
                    }
                }
                cancelled
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    const ALICE: Uuid = Uuid::from_u128(1);
    const LOST: Uuid = Uuid::from_u128(10);
    const KEPT: Uuid = Uuid::from_u128(11);

    async fn fired(rx: &mut broadcast::Receiver<()>) -> bool {
        tokio::time::timeout(Duration::from_millis(200), rx.recv())
            .await
            .is_ok()
    }

    /// Cancelling one target's streams fires their close signal and leaves
    /// the user's stream to another target running.
    #[tokio::test]
    async fn cancelling_a_target_ends_only_its_streams() {
        let streams = LiveStreams::default();
        let (_session_tx, session_rx) = broadcast::channel(1);
        let mut lost = streams.watch(session_rx.resubscribe(), ALICE, LOST);
        let mut kept = streams.watch(session_rx, ALICE, KEPT);
        tokio::task::yield_now().await;
        assert_eq!(
            streams.in_use(),
            HashSet::from([(ALICE, LOST), (ALICE, KEPT)])
        );

        assert_eq!(streams.cancel(ALICE, LOST), 1);

        assert!(fired(&mut lost).await);
        assert!(!fired(&mut kept).await);
    }

    /// The browser session closing still ends the stream.
    #[tokio::test]
    async fn the_session_close_still_ends_the_stream() {
        let streams = LiveStreams::default();
        let (session_tx, session_rx) = broadcast::channel(1);
        let mut rx = streams.watch(session_rx, ALICE, KEPT);
        tokio::task::yield_now().await;
        session_tx.send(()).unwrap();
        assert!(fired(&mut rx).await);
    }

    /// A finished request leaves the registry.
    #[tokio::test]
    async fn a_finished_request_is_deregistered() {
        let streams = LiveStreams::default();
        let (_session_tx, session_rx) = broadcast::channel(1);
        let rx = streams.watch(session_rx, ALICE, KEPT);
        assert!(!streams.in_use().is_empty());
        drop(rx);
        for _ in 0..50 {
            if streams.in_use().is_empty() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the finished request stayed registered");
    }
}
