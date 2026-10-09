use std::future::Future;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use futures::future::join_all;
use futures::{SinkExt, StreamExt};
use poem::IntoResponse;
use poem::web::websocket::{Message, WebSocket};
use sea_orm::ActiveValue::Set;
use sea_orm::sea_query::{Expr, IntoCondition, OnConflict};
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QuerySelect};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio::sync::broadcast;
use tokio::time::timeout;
use tracing::{info, warn};
use uuid::Uuid;
use warpgate_ca::{CLUSTER_TLS_SNI_NAME, ClusterTlsIdentity};
use warpgate_common::http_headers::X_WARPGATE_CLUSTER_TOKEN;
use warpgate_common::{NodeId, Protocol, Secret, UserSessionId, WarpgateError};
use warpgate_db_entities::{HttpSession, Node, Parameters, TargetSession, UserSession};
use warpgate_tls::configure_cluster_tls_connector;

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
const REAP_INTERVAL: Duration = Duration::from_secs(15);
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(30);

/// A node whose last successful heartbeat is older than this can no longer
/// write its own database. The liveness endpoint reports it as stale, so the
/// orchestrator restarts the node instead of leaving it serving errors. A
/// node with no successful heartbeat yet counts its age from startup, which
/// makes this the startup grace too.
pub const HEARTBEAT_STALE_AFTER: Duration = Duration::from_secs(90);

/// The age of this node's last successful heartbeat, read from memory only:
/// a database that is locked must not make the liveness check hang.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeartbeatHealth {
    pub age_seconds: u64,
    pub stale: bool,
}

pub(crate) fn heartbeat_health_at(
    last_success: Option<Instant>,
    started: Instant,
    now: Instant,
) -> HeartbeatHealth {
    let age = now.saturating_duration_since(last_success.unwrap_or(started));
    HeartbeatHealth {
        age_seconds: age.as_secs(),
        stale: age > HEARTBEAT_STALE_AFTER,
    }
}

/// An interval for a periodic database task. A run that overruns its period
/// delays the next one instead of triggering a burst of catch-up runs: with
/// tokio's default, a task slower than its period runs back to back and can
/// hold SQLite's write lock almost continuously.
pub(crate) fn db_task_interval(period: Duration) -> tokio::time::Interval {
    let mut interval = tokio::time::interval(period);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    interval
}

/// When this node last wrote its heartbeat, kept in an atomic so the
/// liveness check never waits on a lock or the database.
pub(crate) struct HeartbeatClock {
    started: Instant,
    /// Milliseconds after `started` of the last success, or `NEVER`.
    last_success_ms: AtomicU64,
}

impl HeartbeatClock {
    const NEVER: u64 = u64::MAX;

    pub(crate) fn new() -> Self {
        Self {
            started: Instant::now(),
            last_success_ms: AtomicU64::new(Self::NEVER),
        }
    }

    pub(crate) fn record_success(&self) {
        let ms = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(Self::NEVER - 1);
        self.last_success_ms.store(ms, Ordering::Relaxed);
    }

    pub(crate) fn health(&self) -> HeartbeatHealth {
        let last = match self.last_success_ms.load(Ordering::Relaxed) {
            Self::NEVER => None,
            ms => Some(self.started + Duration::from_millis(ms)),
        };
        heartbeat_health_at(last, self.started, Instant::now())
    }
}

pub const NOTIFICATION_TIMEOUT: Duration = Duration::from_secs(10);
pub const NOTIFICATIONS_ROUTE: &str = "/cluster/notifications";

/// A refresh notification sent between nodes, used to feed UI update websockets
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClusterNotification {
    SessionsChanged,
    SessionApprovalsChanged,
    WebAuthRequested {
        session_id: UserSessionId,
        user_id: Uuid,
    },
}

pub struct RemoteNode {
    pub address: String,
    /// SPKI pin from the node's registry row; peer TLS verification fails
    /// closed when a node has not published one.
    pub tls_spki_sha256: Option<String>,
}

impl From<Node::Model> for RemoteNode {
    fn from(node: Node::Model) -> Self {
        Self {
            address: node.address,
            tls_spki_sha256: node.tls_spki_sha256,
        }
    }
}

/// Which node owns a node-local resource (an in-progress recording, a live
/// session, an auth state)
pub enum Owner {
    Local,
    Remote(RemoteNode),
}

pub struct PeerConnection {
    pub tls: rustls::ClientConfig,
    pub addrs: Vec<SocketAddr>,
    pub port: u16,
}

/// Cluster identity, registers our ephemeral identity in the node list
pub struct Cluster {
    pub node_id: NodeId,
    /// Peer auth certificate issued for this process
    pub tls_identity: ClusterTlsIdentity,
    pub cluster_token: Arc<Secret<String>>,
    db: DatabaseConnection,
    /// Peer address (host:port)
    address: String,
    hostname: String,
    /// cached warpgate root CA
    ca_certificate_pem: String,
    notifications: broadcast::Sender<ClusterNotification>,
    heartbeat_clock: HeartbeatClock,
}

impl Cluster {
    pub async fn new(db: DatabaseConnection, http_port: u16) -> Result<Self, WarpgateError> {
        let params = Parameters::Entity::get(&db).await?;
        Ok(Self {
            node_id: NodeId(Uuid::new_v4()),
            tls_identity: ClusterTlsIdentity::issue(
                &params.ca_certificate_pem,
                &params.ca_private_key_pem,
            )?,
            cluster_token: Arc::new(resolve_cluster_token(&db, &params).await?),
            address: advertised_peer_address(http_port)?,
            hostname: std::net::hostname()?.to_string_lossy().to_string(),
            ca_certificate_pem: params.ca_certificate_pem,
            notifications: broadcast::channel(256).0,
            heartbeat_clock: HeartbeatClock::new(),
            db,
        })
    }

    pub fn notify_global(self: &Arc<Self>, msg: ClusterNotification) {
        self.deliver_local(msg.clone());
        let this = Arc::clone(self);
        tokio::spawn(async move {
            this.for_each_peer(|peer| this.post_notification(peer.into(), &msg))
                .await;
        });
    }

    pub fn deliver_local(&self, msg: ClusterNotification) {
        let _ = self.notifications.send(msg);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ClusterNotification> {
        self.notifications.subscribe()
    }

    // TODO: client pool
    async fn post_notification(
        &self,
        peer: RemoteNode,
        msg: &ClusterNotification,
    ) -> Result<(), WarpgateError> {
        self.peer_request(
            &peer,
            reqwest::Method::POST,
            &format!("/@warpgate/admin/api{NOTIFICATIONS_ROUTE}"),
        )
        .await?
        .json(msg)
        .send()
        .await?
        .error_for_status()?;
        Ok(())
    }

    /// Run fn against every node with a timeout (best effort)
    pub async fn for_each_peer<T, E, Fut>(&self, f: impl Fn(Node::Model) -> Fut) -> Vec<(String, T)>
    where
        E: std::fmt::Display,
        Fut: Future<Output = Result<T, E>>,
    {
        let peers = match alive_nodes(&self.db).await {
            Ok(peers) => peers,
            Err(error) => {
                warn!(%error, "Failed to list cluster nodes");
                return vec![];
            }
        };
        join_all(
            peers
                .into_iter()
                .filter(|peer| peer.id != self.node_id)
                .map(|peer| {
                    let hostname = peer.hostname.clone();
                    let call = f(peer);
                    async move {
                        match timeout(NOTIFICATION_TIMEOUT, call).await {
                            Ok(Ok(result)) => Some((hostname, result)),
                            Ok(Err(error)) => {
                                warn!(node = %hostname, %error, "Cluster node request failed");
                                None
                            }
                            Err(_) => {
                                warn!(node = %hostname, "Cluster node request timed out");
                                None
                            }
                        }
                    }
                }),
        )
        .await
        .into_iter()
        .flatten()
        .collect()
    }

    pub async fn peer_request(
        &self,
        peer: &RemoteNode,
        method: reqwest::Method,
        path: &str,
    ) -> Result<reqwest::RequestBuilder, WarpgateError> {
        let PeerConnection { tls, addrs, port } = self.peer_connection(peer).await?;
        let client = reqwest::Client::builder()
            .use_preconfigured_tls(tls)
            .resolve_to_addrs(CLUSTER_TLS_SNI_NAME, &addrs)
            .build()?;
        Ok(client
            .request(
                method,
                format!("https://{CLUSTER_TLS_SNI_NAME}:{port}{path}"),
            )
            .header(
                X_WARPGATE_CLUSTER_TOKEN.clone(),
                self.cluster_token.expose_secret(),
            ))
    }

    /// resolve a node UUID into an [Owner::Local]/[Owner::Remote],
    /// handling invalid IDs (warn and fall back to local)
    pub async fn owner(&self, node_id: Option<NodeId>) -> Result<Owner, WarpgateError> {
        let Some(node_id) = node_id else {
            return Ok(Owner::Local);
        };
        if node_id.0.is_nil() || node_id == self.node_id {
            return Ok(Owner::Local);
        }
        let Some(node) = Node::Entity::find_by_id(node_id).one(&self.db).await? else {
            warn!(%node_id, "Owner node is gone from the cluster; serving locally");
            return Ok(Owner::Local);
        };
        Ok(Owner::Remote(node.into()))
    }

    pub async fn peer_connection(
        &self,
        peer: &RemoteNode,
    ) -> Result<PeerConnection, WarpgateError> {
        let Some(pin) = peer.tls_spki_sha256.clone() else {
            return Err(WarpgateError::ClusterPeerUnreachable(format!(
                "{} has no TLS pin",
                peer.address
            )));
        };
        let tls = configure_cluster_tls_connector(self.ca_certificate_pem.as_bytes(), pin)?;
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host(&peer.address)
            .await
            .map_err(|error| {
                WarpgateError::ClusterPeerUnreachable(format!(
                    "cannot resolve {}: {error}",
                    peer.address
                ))
            })?
            .collect();
        let Some(port) = addrs.first().map(SocketAddr::port) else {
            return Err(WarpgateError::ClusterPeerUnreachable(format!(
                "cannot resolve IP for {}",
                peer.address
            )));
        };
        Ok(PeerConnection { tls, addrs, port })
    }

    /// Register this node and spawn heartbeat + reaper tasks
    pub async fn start(self: &Arc<Self>) -> Result<(), WarpgateError> {
        self.heartbeat().await?;
        info!(node_id = %self.node_id, address = %self.address, "Joined cluster");

        tokio::spawn({
            let this = Arc::clone(self);
            async move {
                let mut interval = db_task_interval(HEARTBEAT_INTERVAL);
                loop {
                    interval.tick().await;
                    if let Err(error) = this.heartbeat().await {
                        warn!(%error, "Node heartbeat failed");
                    }
                }
            }
        });

        tokio::spawn({
            let db = self.db.clone();
            async move {
                let mut interval = db_task_interval(REAP_INTERVAL);
                loop {
                    interval.tick().await;
                    if let Err(error) = reap(&db).await {
                        warn!(%error, "Node reaper failed");
                    }
                }
            }
        });

        Ok(())
    }

    async fn heartbeat(&self) -> Result<(), WarpgateError> {
        let model = Node::ActiveModel {
            id: Set(self.node_id),
            address: Set(self.address.clone()),
            hostname: Set(self.hostname.clone()),
            last_seen: Set(OffsetDateTime::now_utc()),
            tls_spki_sha256: Set(Some(self.tls_identity.spki_sha256_hex.clone())),
            encryption_key_fingerprint: Set(warpgate_common::encryption::env_keyring()
                .primary()
                .map(|key| key.fingerprint().to_owned())),
        };
        // Upsert: SeaORM emits `ON CONFLICT DO UPDATE` (Postgres/SQLite) or
        // `ON DUPLICATE KEY UPDATE` (MySQL). `exec_without_returning` avoids the
        // last-insert-id path, which is where MySQL upserts of a non-auto-increment
        // UUID PK misbehave — and we don't need the id anyway.
        Node::Entity::insert(model)
            .on_conflict(
                OnConflict::column(Node::Column::Id)
                    .update_columns([
                        Node::Column::Address,
                        Node::Column::Hostname,
                        Node::Column::LastSeen,
                        Node::Column::TlsSpkiSha256,
                        Node::Column::EncryptionKeyFingerprint,
                    ])
                    .to_owned(),
            )
            .exec_without_returning(&self.db)
            .await?;
        self.heartbeat_clock.record_success();
        Ok(())
    }

    /// How long ago this node last wrote its heartbeat. Lock-free and
    /// database-free, for the liveness endpoint.
    pub fn heartbeat_health(&self) -> HeartbeatHealth {
        self.heartbeat_clock.health()
    }

    /// Graceful shutdown: end this node's still-open sessions and drop its row, so
    /// a scale-down deregisters immediately instead of waiting for the reaper.
    /// Shared sessions carry no node and pass through untouched.
    pub async fn shutdown(&self) -> Result<(), WarpgateError> {
        end_connection_bound_sessions(&self.db, UserSession::Column::NodeId.eq(self.node_id))
            .await?;
        end_children_of_ended_parents(&self.db).await?;
        Node::Entity::delete_by_id(self.node_id)
            .exec(&self.db)
            .await?;
        Ok(())
    }
}

async fn resolve_cluster_token(
    db: &DatabaseConnection,
    params: &Parameters::Model,
) -> Result<Secret<String>, WarpgateError> {
    if let Some(token) = &params.cluster_token {
        return Ok(Secret::new(token.clone()));
    }

    Parameters::Entity::update_many()
        .col_expr(
            Parameters::Column::ClusterToken,
            Expr::value(Secret::<String>::random().expose_secret().clone()),
        )
        .filter(Parameters::Column::ClusterToken.is_null())
        .exec(db)
        .await?;

    Parameters::Entity::get(db)
        .await?
        .cluster_token
        .map(Secret::new)
        .ok_or_else(|| {
            WarpgateError::InconsistentState("cluster token missing after generation".into())
        })
}

/// Websocket that serves refresh notifications for a page from a cluster notification stream
pub fn refresh_notification_stream(
    ws: WebSocket,
    mut rx: broadcast::Receiver<ClusterNotification>,
    mut filter_map: impl FnMut(ClusterNotification) -> Option<String> + Send + Sync + 'static,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| async move {
        let (mut sink, mut source) = socket.split();
        loop {
            tokio::select! {
                received = rx.recv() => match received {
                    Ok(msg) => {
                        if let Some(text) = filter_map(msg) {
                            sink.send(Message::Text(text)).await?;
                        }
                    }
                    // Every client treats any frame as "refetch", so whatever a
                    // lag dropped is delivered as one blank wake-up
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        sink.send(Message::Text(String::new())).await?;
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                },
                // Clients send nothing; the read half only reports that the
                // socket went away, which is when to stop holding a receiver
                incoming = source.next() => match incoming {
                    Some(Ok(Message::Close(_)) | Err(_)) | None => break,
                    Some(Ok(_)) => {}
                },
            }
        }
        Ok::<(), anyhow::Error>(())
    })
}

/// A shared session's row is inserted before the first cookie-session write
/// lands at the end of that request; the grace keeps the orphan sweep from
/// ending a session mid-birth.
const SHARED_SESSION_ORPHAN_GRACE: time::Duration = time::Duration::minutes(5);

/// bound sessions reap 1/2: mark user sessions matching filter as ended
async fn end_connection_bound_sessions(
    db: &DatabaseConnection,
    node_filter: impl IntoCondition,
) -> Result<(), WarpgateError> {
    UserSession::Entity::update_many()
        .col_expr(
            UserSession::Column::Ended,
            Expr::value(OffsetDateTime::now_utc()),
        )
        .filter(node_filter)
        .filter(UserSession::Column::NodeId.is_not_null())
        .filter(UserSession::Column::Ended.is_null())
        .exec(db)
        .await?;
    Ok(())
}

/// End unowned (HTTP browser) sessions whose backing is gone: they are kept
/// alive by their stored cookie sessions, not by any node.
async fn end_sessions_without_cookie(db: &DatabaseConnection) -> Result<(), WarpgateError> {
    let grace_cutoff = OffsetDateTime::now_utc() - SHARED_SESSION_ORPHAN_GRACE;
    UserSession::Entity::update_many()
        .col_expr(
            UserSession::Column::Ended,
            Expr::value(OffsetDateTime::now_utc()),
        )
        .filter(UserSession::Column::Protocol.eq(Protocol::Http.name()))
        .filter(UserSession::Column::NodeId.is_null())
        .filter(UserSession::Column::Ended.is_null())
        .filter(UserSession::Column::Started.lt(grace_cutoff))
        .filter(
            UserSession::Column::Id.not_in_subquery(
                sea_orm::sea_query::Query::select()
                    .column(HttpSession::Column::UserSessionId)
                    .from(HttpSession::Entity)
                    .and_where(Expr::col(HttpSession::Column::UserSessionId).is_not_null())
                    .to_owned(),
            ),
        )
        .exec(db)
        .await?;
    Ok(())
}

/// Safety net: no target access may read as open past its parent. The normal
/// end paths close children with their parent in one statement; this catches
/// whatever a crash left behind.
async fn end_children_of_ended_parents(db: &DatabaseConnection) -> Result<(), WarpgateError> {
    TargetSession::Entity::update_many()
        .col_expr(
            TargetSession::Column::Ended,
            Expr::value(OffsetDateTime::now_utc()),
        )
        .filter(TargetSession::Column::Ended.is_null())
        .filter(
            TargetSession::Column::UserSessionId.in_subquery(
                sea_orm::sea_query::Query::select()
                    .column(UserSession::Column::Id)
                    .from(UserSession::Entity)
                    .and_where(Expr::col(UserSession::Column::Ended).is_not_null())
                    .to_owned(),
            ),
        )
        .exec(db)
        .await?;
    Ok(())
}

pub async fn alive_nodes(db: &DatabaseConnection) -> Result<Vec<Node::Model>, WarpgateError> {
    let cutoff = OffsetDateTime::now_utc() - HEARTBEAT_TIMEOUT;
    Ok(Node::Entity::find()
        .filter(Node::Column::LastSeen.gte(cutoff))
        .all(db)
        .await?)
}

async fn reap(db: &DatabaseConnection) -> Result<(), WarpgateError> {
    let cutoff = OffsetDateTime::now_utc() - HEARTBEAT_TIMEOUT;
    // reap dead nodes
    let dead = Node::Entity::delete_many()
        .filter(Node::Column::LastSeen.lt(cutoff))
        .exec(db)
        .await?
        .rows_affected;
    if dead > 0 {
        warn!(count = dead, "Reaping dead cluster nodes");
    }

    let live: Vec<NodeId> = Node::Entity::find()
        .select_only()
        .column(Node::Column::Id)
        .into_tuple()
        .all(db)
        .await?;

    // At least the current node should have been present - bail
    // intead of ending all sessions
    if !live.is_empty() {
        end_connection_bound_sessions(db, UserSession::Column::NodeId.is_not_in(live)).await?;
    }

    end_sessions_without_cookie(db).await?;
    end_children_of_ended_parents(db).await?;
    Ok(())
}

/// Fallback order
/// * WARPGATE_PEER_ADDRESS
/// * POD_IP (kubernetes)
/// * local outbound IP
fn advertised_peer_address(http_port: u16) -> std::io::Result<String> {
    if let Some(addr) = non_empty_env("WARPGATE_PEER_ADDRESS") {
        return Ok(addr);
    }
    if let Some(ip) = non_empty_env("POD_IP") {
        return Ok(format!("{ip}:{http_port}"));
    }

    let ip = local_ip()?;
    Ok(format!("{ip}:{http_port}"))
}

fn local_ip() -> std::io::Result<IpAddr> {
    let socket = UdpSocket::bind(("0.0.0.0", 0))?;
    socket.connect(("1.1.1.1", 80))?; // no traffic here yet, just a route resolve
    socket.local_addr().map(|a| a.ip())
}

/// An environment variable's value, trimmed, or `None` if unset or blank.
fn non_empty_env(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use sea_orm::ActiveValue::NotSet;
    use sea_orm::Database;
    use warpgate_common::Protocol;
    use warpgate_db_entities::Parameters::{ConfigMigrationValues, set_config_migration_values};
    use warpgate_db_migrations::migrate_database;

    use super::*;

    async fn migrated_db() -> DatabaseConnection {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        db
    }

    async fn target_session(db: &DatabaseConnection, parent: Uuid, node_id: Option<Uuid>) -> Uuid {
        let id = Uuid::new_v4();
        TargetSession::Entity::insert(TargetSession::ActiveModel {
            id: Set(warpgate_common::TargetSessionId(id)),
            user_session_id: Set(warpgate_common::UserSessionId(parent)),
            target_snapshot: Set(r#"{"name":"web"}"#.into()),
            target_id: Set(Uuid::new_v4()),
            started: Set(OffsetDateTime::now_utc()),
            ended: Set(None),
            ticket_id: Set(None),
            node_id: Set(node_id.map(NodeId)),
        })
        .exec_without_returning(db)
        .await
        .unwrap();
        id
    }

    async fn is_open(db: &DatabaseConnection, id: Uuid) -> bool {
        TargetSession::Entity::find_by_id(warpgate_common::TargetSessionId(id))
            .one(db)
            .await
            .unwrap()
            .unwrap()
            .ended
            .is_none()
    }

    async fn user_session_started(
        db: &DatabaseConnection,
        node_id: Option<Uuid>,
        protocol: Protocol,
        started: OffsetDateTime,
    ) -> Uuid {
        let id = Uuid::new_v4();
        UserSession::Entity::insert(UserSession::ActiveModel {
            id: Set(warpgate_common::UserSessionId(id)),
            username: Set(Some("alice".into())),
            user_id: Set(Some(Uuid::new_v4())),
            remote_address: Set("127.0.0.1:1".into()),
            started: Set(started),
            ended: Set(None),
            protocol: Set(protocol.to_string()),
            node_id: Set(node_id.map(NodeId)),
            auth_state_node_id: Set(None),
        })
        .exec_without_returning(db)
        .await
        .unwrap();
        id
    }

    async fn user_session(
        db: &DatabaseConnection,
        node_id: Option<Uuid>,
        protocol: Protocol,
    ) -> Uuid {
        user_session_started(db, node_id, protocol, OffsetDateTime::now_utc()).await
    }

    async fn cookie_backing(db: &DatabaseConnection, user_session_id: Uuid) {
        HttpSession::Entity::insert(HttpSession::ActiveModel {
            id: Set(user_session_id.to_string()),
            expires: Set(None),
            data: Set("{}".into()),
            updated: Set(OffsetDateTime::now_utc()),
            user_session_id: Set(Some(warpgate_common::UserSessionId(user_session_id))),
        })
        .exec_without_returning(db)
        .await
        .unwrap();
    }

    async fn is_user_session_open(db: &DatabaseConnection, id: Uuid) -> bool {
        UserSession::Entity::find_by_id(warpgate_common::UserSessionId(id))
            .one(db)
            .await
            .unwrap()
            .unwrap()
            .ended
            .is_none()
    }

    #[test]
    fn notification_wire_format_is_tagged_by_type() {
        let user_id = Uuid::new_v4();
        let msg = ClusterNotification::WebAuthRequested {
            session_id: UserSessionId(Uuid::nil()),
            user_id,
        };
        let json = serde_json::to_value(&msg).unwrap();
        assert_eq!(json["type"], "web_auth_requested");
        assert_eq!(json["user_id"], user_id.to_string());
        let plain = serde_json::to_string(&ClusterNotification::SessionsChanged).unwrap();
        assert_eq!(plain, r#"{"type":"sessions_changed"}"#);
        let back: ClusterNotification = serde_json::from_str(&plain).unwrap();
        assert!(matches!(back, ClusterNotification::SessionsChanged));
    }

    #[test]
    fn heartbeat_health_is_fresh_right_after_a_success() {
        let started = Instant::now();
        let now = started + Duration::from_secs(300);
        let health = heartbeat_health_at(Some(now - Duration::from_secs(4)), started, now);
        assert_eq!(
            health,
            HeartbeatHealth {
                age_seconds: 4,
                stale: false
            }
        );
    }

    #[test]
    fn heartbeat_health_goes_stale_past_the_threshold() {
        let started = Instant::now();
        let now = started + Duration::from_secs(600);
        let at_limit = heartbeat_health_at(Some(now - HEARTBEAT_STALE_AFTER), started, now);
        assert!(!at_limit.stale, "exactly at the threshold is still fresh");
        let past = heartbeat_health_at(Some(now - Duration::from_secs(91)), started, now);
        assert_eq!(
            past,
            HeartbeatHealth {
                age_seconds: 91,
                stale: true
            }
        );
    }

    #[test]
    fn heartbeat_health_without_a_success_counts_from_startup() {
        let started = Instant::now();
        let in_grace = heartbeat_health_at(None, started, started + Duration::from_secs(30));
        assert_eq!(
            in_grace,
            HeartbeatHealth {
                age_seconds: 30,
                stale: false
            }
        );
        let after_grace = heartbeat_health_at(None, started, started + Duration::from_secs(120));
        assert_eq!(
            after_grace,
            HeartbeatHealth {
                age_seconds: 120,
                stale: true
            }
        );
    }

    #[test]
    fn the_clock_reports_a_recorded_success_as_fresh() {
        let clock = HeartbeatClock::new();
        assert_eq!(
            clock.health().age_seconds,
            0,
            "no success yet: age counts from startup"
        );
        clock.record_success();
        let health = clock.health();
        assert!(!health.stale);
        assert_eq!(health.age_seconds, 0);
    }

    #[tokio::test]
    async fn db_task_intervals_never_run_back_to_back() {
        let interval = db_task_interval(Duration::from_secs(15));
        assert_eq!(
            interval.missed_tick_behavior(),
            tokio::time::MissedTickBehavior::Delay
        );
    }

    #[tokio::test]
    async fn notify_reaches_local_subscribers() {
        let db = migrated_db().await;
        let cluster = Arc::new(Cluster::new(db, 0).await.unwrap());
        let mut rx = cluster.subscribe();
        cluster.notify_global(ClusterNotification::SessionApprovalsChanged);
        assert!(matches!(
            rx.recv().await.unwrap(),
            ClusterNotification::SessionApprovalsChanged
        ));
    }

    #[tokio::test]
    async fn cluster_token_is_shared_across_nodes() {
        let db = migrated_db().await;
        let a = Cluster::new(db.clone(), 0).await.unwrap();
        let b = Cluster::new(db, 0).await.unwrap();
        assert_eq!(
            a.cluster_token.expose_secret(),
            b.cluster_token.expose_secret()
        );
    }

    async fn register_node(db: &DatabaseConnection) -> Uuid {
        let id = Uuid::new_v4();
        Node::Entity::insert(Node::ActiveModel {
            id: Set(NodeId(id)),
            address: Set("127.0.0.1:8888".into()),
            hostname: Set("live".into()),
            last_seen: Set(OffsetDateTime::now_utc()),
            tls_spki_sha256: NotSet,
            encryption_key_fingerprint: NotSet,
        })
        .exec_without_returning(db)
        .await
        .unwrap();
        id
    }

    #[tokio::test]
    async fn reap_ends_connection_bound_sessions_without_a_live_owner() {
        let db = migrated_db().await;
        let live_node = register_node(&db).await;

        let live = user_session(&db, Some(live_node), Protocol::Ssh).await;
        let dead = user_session(&db, Some(Uuid::new_v4()), Protocol::Ssh).await;
        let dead_child = target_session(&db, dead, Some(Uuid::new_v4())).await;
        // What m00072 backfills onto pre-clustering sessions
        let legacy = user_session(&db, Some(Uuid::nil()), Protocol::Ssh).await;
        let shared = user_session(&db, None, Protocol::Http).await;
        cookie_backing(&db, shared).await;
        let shared_child = target_session(&db, shared, None).await;

        reap(&db).await.unwrap();

        assert!(is_user_session_open(&db, live).await);
        assert!(!is_user_session_open(&db, dead).await);
        assert!(!is_open(&db, dead_child).await);
        assert!(!is_user_session_open(&db, legacy).await);
        assert!(is_user_session_open(&db, shared).await);
        assert!(is_open(&db, shared_child).await);
    }

    #[tokio::test]
    async fn reap_keeps_sessions_when_the_node_list_reads_empty() {
        let db = migrated_db().await;

        let id = user_session(&db, Some(Uuid::new_v4()), Protocol::Ssh).await;
        reap(&db).await.unwrap();
        assert!(is_user_session_open(&db, id).await);
    }

    #[tokio::test]
    async fn orphaned_shared_sessions_end_after_the_grace() {
        let db = migrated_db().await;
        register_node(&db).await;
        let stale = OffsetDateTime::now_utc() - SHARED_SESSION_ORPHAN_GRACE * 2;

        let orphan = user_session_started(&db, None, Protocol::Http, stale).await;
        let orphan_child = target_session(&db, orphan, None).await;
        let backed = user_session_started(&db, None, Protocol::Http, stale).await;
        cookie_backing(&db, backed).await;
        // Fresh row whose first cookie write has not landed yet
        let newborn = user_session(&db, None, Protocol::Http).await;

        reap(&db).await.unwrap();

        assert!(!is_user_session_open(&db, orphan).await);
        assert!(!is_open(&db, orphan_child).await);
        assert!(is_user_session_open(&db, backed).await);
        assert!(is_user_session_open(&db, newborn).await);
    }

    /// An HTTP session can be held open by a node-local handle instead of a
    /// stored cookie — a header-borne ticket's. It registers node-owned and so
    /// records an owner, which is what keeps the orphan sweep (whose only
    /// liveness test is a cookie row) from ending it mid-use.
    #[tokio::test]
    async fn node_owned_http_sessions_survive_the_orphan_sweep() {
        let db = migrated_db().await;
        let node = register_node(&db).await;
        let stale = OffsetDateTime::now_utc() - SHARED_SESSION_ORPHAN_GRACE * 2;

        let ticket_session = user_session_started(&db, Some(node), Protocol::Http, stale).await;
        let ticket_child = target_session(&db, ticket_session, Some(node)).await;

        reap(&db).await.unwrap();

        assert!(is_user_session_open(&db, ticket_session).await);
        assert!(is_open(&db, ticket_child).await);
    }
}
