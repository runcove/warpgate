//! Long-lived proxied HTTP traffic (websockets, streamed bodies) by the user and
//! target it runs for, so a revocation can end it without ending the browser
//! session that carries it.
//!
//! A request is registered as role-based (its user was admitted by a role
//! grant), as public-bypass (admitted because the target is public, with no
//! role check) or as binding-only (admitted by a ticket, a token or a peer,
//! which have no role or public rule to re-check). A revocation re-checks each
//! kind by the rule that admitted it, and cancels only that kind. Every kind
//! is also ended when the target's host binding changes.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use warpgate_common::{TargetOptions, WarpgateError};

/// The host a target is bound to (its HTTP `external_host`), if any. An empty
/// value counts as no binding.
pub fn host_binding(options: &TargetOptions) -> Option<String> {
    options
        .external_host()
        .filter(|host| !host.is_empty())
        .map(str::to_owned)
}

/// What admitted a live request, and so what must still hold for it to run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LiveStreamKind {
    /// The user holds a role that grants the target.
    RoleBased,
    /// The target is public, and the request went through the public bypass.
    Public,
    /// Admitted by a ticket, a token or a cluster peer: only the target's
    /// host binding is re-checked, as deleting the ticket or token is what
    /// ends it otherwise.
    BindingOnly,
}

struct LiveStream {
    user_id: Uuid,
    target_id: Uuid,
    kind: LiveStreamKind,
    host_binding: Option<String>,
    cancel: CancellationToken,
}

/// This node's live proxied HTTP requests, each under the user and target it
/// was authorized for and the target's host binding at that time.
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
    fn register(
        &self,
        user_id: Uuid,
        target_id: Uuid,
        kind: LiveStreamKind,
        host_binding: Option<String>,
    ) -> Registration {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let cancel = CancellationToken::new();
        if let Ok(mut streams) = self.streams.lock() {
            streams.insert(
                id,
                LiveStream {
                    user_id,
                    target_id,
                    kind,
                    host_binding,
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
    /// user's streams of this kind to this target. `host_binding` is the
    /// target's [`host_binding`] the request was opened against. The request
    /// stays registered until the receiver and every resubscription of it are
    /// dropped.
    pub fn watch(
        &self,
        mut session_close: broadcast::Receiver<()>,
        user_id: Uuid,
        target_id: Uuid,
        kind: LiveStreamKind,
        host_binding: Option<String>,
    ) -> broadcast::Receiver<()> {
        let (tx, rx) = broadcast::channel(1);
        let registration = self.register(user_id, target_id, kind, host_binding);
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

    /// The distinct (user, target, kind, host binding) tuples with live
    /// requests on this node. Fails if the registry's lock is poisoned, so a
    /// caller that re-checks the streams can report that it could not.
    pub fn in_use(
        &self,
    ) -> Result<HashSet<(Uuid, Uuid, LiveStreamKind, Option<String>)>, WarpgateError> {
        let streams = self.streams.lock().map_err(|_| {
            WarpgateError::InconsistentState("the live request registry lock is poisoned".into())
        })?;
        Ok(streams
            .values()
            .map(|stream| {
                (
                    stream.user_id,
                    stream.target_id,
                    stream.kind,
                    stream.host_binding.clone(),
                )
            })
            .collect())
    }

    /// Ends this node's live requests of `kind` by `user_id` to `target_id`;
    /// returns how many. Requests of the other kind for the same pair stay.
    pub fn cancel(&self, user_id: Uuid, target_id: Uuid, kind: LiveStreamKind) -> usize {
        self.streams
            .lock()
            .map(|streams| {
                let mut cancelled = 0;
                for stream in streams.values() {
                    if stream.user_id == user_id
                        && stream.target_id == target_id
                        && stream.kind == kind
                    {
                        stream.cancel.cancel();
                        cancelled += 1;
                    }
                }
                cancelled
            })
            .unwrap_or_default()
    }

    /// Ends this node's live requests of `kind` by `user_id` to `target_id`
    /// that were opened against `host_binding`; returns how many. Requests
    /// opened against another binding stay.
    pub fn cancel_bound(
        &self,
        user_id: Uuid,
        target_id: Uuid,
        kind: LiveStreamKind,
        host_binding: &Option<String>,
    ) -> usize {
        self.streams
            .lock()
            .map(|streams| {
                let mut cancelled = 0;
                for stream in streams.values() {
                    if stream.user_id == user_id
                        && stream.target_id == target_id
                        && stream.kind == kind
                        && &stream.host_binding == host_binding
                    {
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
        let mut lost = streams.watch(
            session_rx.resubscribe(),
            ALICE,
            LOST,
            LiveStreamKind::RoleBased,
            None,
        );
        let mut kept = streams.watch(session_rx, ALICE, KEPT, LiveStreamKind::RoleBased, None);
        tokio::task::yield_now().await;
        assert_eq!(
            streams.in_use().unwrap(),
            HashSet::from([
                (ALICE, LOST, LiveStreamKind::RoleBased, None),
                (ALICE, KEPT, LiveStreamKind::RoleBased, None)
            ])
        );

        assert_eq!(streams.cancel(ALICE, LOST, LiveStreamKind::RoleBased), 1);

        assert!(fired(&mut lost).await);
        assert!(!fired(&mut kept).await);
    }

    /// Cancelling one kind leaves the other kind's stream for the same user
    /// and target running, whichever kind is cancelled.
    #[tokio::test]
    async fn cancelling_one_kind_leaves_the_other_kind_running() {
        let streams = LiveStreams::default();
        let (_session_tx, session_rx) = broadcast::channel(1);
        let mut public = streams.watch(
            session_rx.resubscribe(),
            ALICE,
            LOST,
            LiveStreamKind::Public,
            None,
        );
        let mut role = streams.watch(session_rx, ALICE, LOST, LiveStreamKind::RoleBased, None);
        tokio::task::yield_now().await;

        assert_eq!(streams.cancel(ALICE, LOST, LiveStreamKind::Public), 1);
        assert!(fired(&mut public).await);
        assert!(!fired(&mut role).await);

        // And the other way round, with fresh streams.
        let (_session_tx, session_rx) = broadcast::channel(1);
        let mut public = streams.watch(
            session_rx.resubscribe(),
            ALICE,
            KEPT,
            LiveStreamKind::Public,
            None,
        );
        let mut role = streams.watch(session_rx, ALICE, KEPT, LiveStreamKind::RoleBased, None);
        tokio::task::yield_now().await;

        assert_eq!(streams.cancel(ALICE, KEPT, LiveStreamKind::RoleBased), 1);
        assert!(fired(&mut role).await);
        assert!(!fired(&mut public).await);
    }

    /// A binding-only stream is kept apart from the other kinds of the same
    /// user and target.
    #[tokio::test]
    async fn cancelling_a_kind_leaves_a_binding_only_stream_running() {
        let streams = LiveStreams::default();
        let (_session_tx, session_rx) = broadcast::channel(1);
        let mut bound = streams.watch(
            session_rx.resubscribe(),
            ALICE,
            LOST,
            LiveStreamKind::BindingOnly,
            None,
        );
        let mut role = streams.watch(session_rx, ALICE, LOST, LiveStreamKind::RoleBased, None);
        tokio::task::yield_now().await;

        assert_eq!(streams.cancel(ALICE, LOST, LiveStreamKind::RoleBased), 1);
        assert!(fired(&mut role).await);
        assert!(!fired(&mut bound).await);
    }

    /// The browser session closing still ends the stream.
    #[tokio::test]
    async fn the_session_close_still_ends_the_stream() {
        let streams = LiveStreams::default();
        let (session_tx, session_rx) = broadcast::channel(1);
        let mut rx = streams.watch(session_rx, ALICE, KEPT, LiveStreamKind::RoleBased, None);
        tokio::task::yield_now().await;
        session_tx.send(()).unwrap();
        assert!(fired(&mut rx).await);
    }

    /// A finished request leaves the registry.
    #[tokio::test]
    async fn a_finished_request_is_deregistered() {
        let streams = LiveStreams::default();
        let (_session_tx, session_rx) = broadcast::channel(1);
        let rx = streams.watch(session_rx, ALICE, KEPT, LiveStreamKind::RoleBased, None);
        assert!(!streams.in_use().unwrap().is_empty());
        drop(rx);
        for _ in 0..50 {
            if streams.in_use().unwrap().is_empty() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the finished request stayed registered");
    }
}
