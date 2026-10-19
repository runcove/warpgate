//! HTTP targets reached through a Unix socket (`unix_socket`), served only on
//! a plain-HTTP loopback listener (`http.plain_http_on_loopback`).
//!
//! What holds on each path:
//! - Before every request (HTTP and WebSocket), [`check_socket_ownership`]
//!   checks the socket, its directory and every ancestor up to `/` with
//!   `lstat`. The directory is ours and 0700, and no ancestor can be renamed
//!   or replaced by anyone but us or root, so no other account can swap what
//!   the path names between that check and the connect.
//! - WebSocket: Warpgate connects the socket itself and then also requires
//!   the listening process to run as our account ([`check_peer_uid`]).
//! - HTTP: reqwest connects the socket internally and offers no hook onto
//!   the connected stream, so the path checks above are the boundary there.

use std::path::{Path, PathBuf};

use http::StatusCode;
use poem::Request;
use tracing::warn;
use warpgate_common::TargetHTTPOptions;
use warpgate_common_http::PlainHttpListener;

/// The socket to reach the target through, checked for this request: `None`
/// for a target reached over TCP. Refused (502) unless the request came over
/// a plain-HTTP loopback listener and the socket passes
/// [`check_socket_ownership`].
pub(crate) fn checked_unix_socket(
    req: &Request,
    options: &TargetHTTPOptions,
) -> poem::Result<Option<PathBuf>> {
    let Some(path) = &options.unix_socket else {
        return Ok(None);
    };
    let loopback = req
        .data::<PlainHttpListener>()
        .is_some_and(|listener| listener.0);
    let checked = options.check_unix_socket(loopback).and_then(|()| {
        let our_uid =
            crate::loopback_owner::effective_uid().map_err(|error| format!("{error:#}"))?;
        check_socket_ownership(Path::new(path), our_uid)
    });
    match checked {
        Ok(()) => Ok(Some(PathBuf::from(path))),
        Err(reason) => {
            warn!(socket = path, %reason, "Refused to connect to a target's Unix socket");
            Err(poem::Error::from_string(
                format!("The target's Unix socket cannot be used: {reason}"),
                StatusCode::BAD_GATEWAY,
            ))
        }
    }
}

/// Whether the socket at `path` may be connected to: the socket and its
/// directory are owned by `our_uid`, neither is a symlink, the directory has
/// no group or other permission bits, and the socket is a socket; and every
/// ancestor of the directory up to `/` is a real directory owned by root or
/// `our_uid`, writable by group or others only when it is root-owned and
/// sticky (as `/tmp` is). Looked at with `lstat`, so a symlink is seen as one
/// rather than followed: the path must not go through any symlink (on macOS,
/// name `/private/var/...`, not `/var/...`).
#[cfg(unix)]
pub(crate) fn check_socket_ownership(path: &Path, our_uid: u32) -> Result<(), String> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    warpgate_common::check_unix_socket_path(&path.to_string_lossy())?;
    let directory = path
        .parent()
        .ok_or_else(|| "the path has no directory".to_string())?;

    let directory_meta = std::fs::symlink_metadata(directory)
        .map_err(|error| format!("cannot read its directory: {error}"))?;
    if directory_meta.file_type().is_symlink() {
        return Err("its directory is a symlink".into());
    }
    if !directory_meta.is_dir() {
        return Err("its parent is not a directory".into());
    }
    if directory_meta.uid() != our_uid {
        return Err("its directory is owned by another account".into());
    }
    if directory_meta.mode() & 0o077 != 0 {
        return Err(format!(
            "its directory has mode {:o}; it must not be accessible to group or others (0700)",
            directory_meta.mode() & 0o7777
        ));
    }

    let socket_meta = std::fs::symlink_metadata(path)
        .map_err(|error| format!("cannot read the socket: {error}"))?;
    if socket_meta.file_type().is_symlink() {
        return Err("the socket path is a symlink".into());
    }
    if !socket_meta.file_type().is_socket() {
        return Err("the path is not a socket".into());
    }
    if socket_meta.uid() != our_uid {
        return Err("the socket is owned by another account".into());
    }

    for ancestor in directory.ancestors().skip(1) {
        check_ancestor(ancestor, our_uid)?;
    }
    Ok(())
}

/// One ancestor of the socket's directory: a real directory that only root
/// or `our_uid` can rename entries in, so the path below it stays ours.
#[cfg(unix)]
fn check_ancestor(ancestor: &Path, our_uid: u32) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    const STICKY: u32 = 0o1000;
    let shown = ancestor.display();
    let meta = std::fs::symlink_metadata(ancestor)
        .map_err(|error| format!("cannot read ancestor directory {shown}: {error}"))?;
    if meta.file_type().is_symlink() {
        return Err(format!("ancestor directory {shown} is a symlink"));
    }
    if !meta.is_dir() {
        return Err(format!("ancestor {shown} is not a directory"));
    }
    let owner = meta.uid();
    if owner != 0 && owner != our_uid {
        return Err(format!(
            "ancestor directory {shown} is owned by another account"
        ));
    }
    let writable_by_others = meta.mode() & 0o022 != 0;
    if writable_by_others && !(owner == 0 && meta.mode() & STICKY != 0) {
        return Err(format!(
            "ancestor directory {shown} is writable by group or others (mode {:o}) without being a root-owned sticky directory",
            meta.mode() & 0o7777
        ));
    }
    Ok(())
}

/// Refuses a connected socket whose listening process does not run as
/// `our_uid`, by the kernel's peer credentials.
#[cfg(unix)]
pub(crate) fn check_peer_uid(stream: &tokio::net::UnixStream, our_uid: u32) -> std::io::Result<()> {
    let peer_uid = stream.peer_cred()?.uid();
    if peer_uid != our_uid {
        warn!(
            peer_uid,
            "Refused a target's Unix socket served by another account"
        );
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "the target's Unix socket is served by another account",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn check_socket_ownership(_path: &Path, _our_uid: u32) -> Result<(), String> {
    Err("Unix sockets are not supported on this platform".into())
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;
    use std::time::Duration;

    use futures::{SinkExt, StreamExt};
    use poem::listener::{Listener, UnixListener};
    use poem::web::websocket::WebSocket;
    use poem::{IntoResponse, Route, Server, get, handler};
    use tokio_tungstenite::tungstenite;

    use super::*;
    use crate::client_cache::HttpClientCache;

    /// A fresh directory under the system temp dir with `mode`, removed on
    /// drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(mode: u32) -> Self {
            // Canonical, so the chain has no symlink in it (macOS `/var`).
            // A short name: macOS's canonical temp dir is already ~58 bytes
            // and a socket path may have at most 103.
            let base = std::fs::canonicalize(std::env::temp_dir()).unwrap();
            let mut id = uuid::Uuid::new_v4().simple().to_string();
            id.truncate(8);
            let path = base.join(format!("wg-{id}"));
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            Self(path)
        }

        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn our_uid() -> u32 {
        crate::loopback_owner::effective_uid().unwrap()
    }

    fn bind_socket(path: &Path) -> std::os::unix::net::UnixListener {
        std::os::unix::net::UnixListener::bind(path).unwrap()
    }

    fn options(path: &Path) -> TargetHTTPOptions {
        serde_json::from_value(serde_json::json!({
            "url": "http://app.local",
            "unix_socket": path.to_str().unwrap(),
        }))
        .unwrap()
    }

    #[test]
    fn accepts_our_socket_in_a_private_directory() {
        let dir = TempDir::new(0o700);
        let socket = dir.join("app.sock");
        let _listener = bind_socket(&socket);
        assert_eq!(check_socket_ownership(&socket, our_uid()), Ok(()));
    }

    #[test]
    fn refuses_a_directory_open_to_group_or_others() {
        for mode in [0o755, 0o750, 0o701, 0o710] {
            let dir = TempDir::new(mode);
            let socket = dir.join("app.sock");
            let _listener = bind_socket(&socket);
            let error = check_socket_ownership(&socket, our_uid()).unwrap_err();
            assert!(error.contains("0700"), "{mode:o}: {error}");
        }
    }

    #[test]
    fn refuses_another_accounts_socket() {
        let dir = TempDir::new(0o700);
        let socket = dir.join("app.sock");
        let _listener = bind_socket(&socket);
        let error = check_socket_ownership(&socket, our_uid().wrapping_add(1)).unwrap_err();
        assert!(error.contains("another account"), "{error}");
    }

    #[test]
    fn refuses_symlinks() {
        let dir = TempDir::new(0o700);
        let socket = dir.join("app.sock");
        let _listener = bind_socket(&socket);

        // A symlink to the socket.
        let link = dir.join("link.sock");
        std::os::unix::fs::symlink(&socket, &link).unwrap();
        let error = check_socket_ownership(&link, our_uid()).unwrap_err();
        assert!(error.contains("symlink"), "{error}");

        // A symlinked directory holding the socket.
        let other = TempDir::new(0o700);
        let linked_dir = other.join("dir");
        std::os::unix::fs::symlink(&dir.0, &linked_dir).unwrap();
        let error = check_socket_ownership(&linked_dir.join("app.sock"), our_uid()).unwrap_err();
        assert!(error.contains("symlink"), "{error}");
    }

    #[test]
    fn refuses_relative_paths_missing_sockets_and_plain_files() {
        let error = check_socket_ownership(Path::new("app.sock"), our_uid()).unwrap_err();
        assert!(error.contains("absolute"), "{error}");

        let dir = TempDir::new(0o700);
        assert!(check_socket_ownership(&dir.join("missing.sock"), our_uid()).is_err());

        let file = dir.join("file");
        std::fs::write(&file, b"").unwrap();
        let error = check_socket_ownership(&file, our_uid()).unwrap_err();
        assert!(error.contains("not a socket"), "{error}");
    }

    /// A private directory for the socket, inside `outer/<name>`.
    fn socket_below(outer: &TempDir, name: &str, mode: u32) -> PathBuf {
        let middle = outer.join(name);
        std::fs::create_dir(&middle).unwrap();
        std::fs::set_permissions(&middle, std::fs::Permissions::from_mode(mode)).unwrap();
        let private = middle.join("private");
        std::fs::create_dir(&private).unwrap();
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
        private.join("app.sock")
    }

    #[test]
    fn accepts_a_chain_through_the_system_temp_dir() {
        // The temp dir itself is typically root-owned and sticky (`/tmp`).
        let outer = TempDir::new(0o755);
        let socket = socket_below(&outer, "apps", 0o755);
        let _listener = bind_socket(&socket);
        assert_eq!(check_socket_ownership(&socket, our_uid()), Ok(()));
    }

    #[test]
    fn refuses_an_ancestor_writable_by_others() {
        let outer = TempDir::new(0o700);
        for mode in [0o777, 0o775, 0o757] {
            let socket = socket_below(&outer, &format!("open-{mode:o}"), mode);
            let _listener = bind_socket(&socket);
            let error = check_socket_ownership(&socket, our_uid()).unwrap_err();
            assert!(
                error.contains("writable by group or others"),
                "{mode:o}: {error}"
            );
        }
        // Sticky is not enough unless root owns it; these tests do not run
        // as root.
        if our_uid() != 0 {
            let socket = socket_below(&outer, "sticky", 0o1777);
            let _listener = bind_socket(&socket);
            let error = check_socket_ownership(&socket, our_uid()).unwrap_err();
            assert!(error.contains("root-owned sticky"), "{error}");
        }
    }

    #[test]
    fn refuses_a_symlinked_ancestor() {
        let outer = TempDir::new(0o700);
        let socket = socket_below(&outer, "real", 0o700);
        let _listener = bind_socket(&socket);
        std::os::unix::fs::symlink(outer.join("real"), outer.join("link")).unwrap();
        let through_link = outer.join("link").join("private").join("app.sock");
        let error = check_socket_ownership(&through_link, our_uid()).unwrap_err();
        assert!(error.contains("is a symlink"), "{error}");
        assert!(error.contains("ancestor"), "{error}");
    }

    #[tokio::test]
    async fn peer_credentials_must_be_our_account() {
        let dir = TempDir::new(0o700);
        let socket = dir.join("app.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let stream = tokio::net::UnixStream::connect(&socket).await.unwrap();
        let _accepted = listener.accept().await.unwrap();
        assert!(check_peer_uid(&stream, our_uid()).is_ok());
        let error = check_peer_uid(&stream, our_uid().wrapping_add(1)).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn refuses_outside_loopback_mode() {
        let dir = TempDir::new(0o700);
        let socket = dir.join("app.sock");
        let _listener = bind_socket(&socket);
        let options = options(&socket);

        let req = Request::builder().finish();
        let error = checked_unix_socket(&req, &options).unwrap_err();
        assert_eq!(error.status(), StatusCode::BAD_GATEWAY);

        let mut req = Request::builder().finish();
        req.extensions_mut().insert(PlainHttpListener(false));
        assert!(checked_unix_socket(&req, &options).is_err());

        let mut req = Request::builder().finish();
        req.extensions_mut().insert(PlainHttpListener(true));
        assert_eq!(
            checked_unix_socket(&req, &options).unwrap(),
            Some(socket.clone())
        );
    }

    #[test]
    fn tcp_targets_are_not_affected() {
        let options: TargetHTTPOptions =
            serde_json::from_value(serde_json::json!({"url": "http://app.local"})).unwrap();
        let req = Request::builder().finish();
        assert_eq!(checked_unix_socket(&req, &options).unwrap(), None);
    }

    #[handler]
    fn hello(req: &Request) -> String {
        format!(
            "hello from {}",
            req.header(http::header::HOST).unwrap_or_default()
        )
    }

    #[handler]
    fn echo(ws: WebSocket) -> impl IntoResponse {
        ws.on_upgrade(|mut socket| async move {
            while let Some(Ok(message)) = socket.next().await {
                if let poem::web::websocket::Message::Text(text) = message {
                    let _ = socket
                        .send(poem::web::websocket::Message::Text(format!("echo {text}")))
                        .await;
                }
            }
        })
    }

    /// Serves a tiny app on a Unix socket in a 0700 directory.
    async fn serve_app() -> (TempDir, PathBuf) {
        serve_app_in(0o700).await
    }

    /// Serves a tiny app on a Unix socket in a directory with `mode`.
    async fn serve_app_in(mode: u32) -> (TempDir, PathBuf) {
        let dir = TempDir::new(mode);
        let socket = dir.join("app.sock");
        let acceptor = UnixListener::bind(socket.to_str().unwrap())
            .into_acceptor()
            .await
            .unwrap();
        let app = Route::new().at("/hello", get(hello)).at("/ws", get(echo));
        tokio::spawn(async move {
            let _ = Server::new_with_acceptor(acceptor).run(app).await;
        });
        (dir, socket)
    }

    #[tokio::test]
    async fn http_requests_reach_the_target_through_its_socket() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let (_dir, socket) = serve_app().await;
        let options = options(&socket);
        let mut req = Request::builder().finish();
        req.extensions_mut().insert(PlainHttpListener(true));
        assert!(checked_unix_socket(&req, &options).unwrap().is_some());

        let client = HttpClientCache::default()
            .client_for("app", &options)
            .await
            .unwrap();
        let response = tokio::time::timeout(
            Duration::from_secs(10),
            client.get("http://app.local/hello").send(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.text().await.unwrap(), "hello from app.local");
    }

    /// A WebSocket upgrade request for the app's `/ws`.
    fn ws_request() -> http::Request<()> {
        http::Request::builder()
            .uri("ws://app.local/ws")
            .header(http::header::HOST, "app.local")
            .header(http::header::CONNECTION, "Upgrade")
            .header(http::header::UPGRADE, "websocket")
            .header(http::header::SEC_WEBSOCKET_VERSION, "13")
            .header(
                http::header::SEC_WEBSOCKET_KEY,
                tungstenite::handshake::client::generate_key(),
            )
            .body(())
            .unwrap()
    }

    async fn connector() -> tokio_tungstenite::Connector {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let tls = warpgate_tls::configure_tls_connector(false, false, None)
            .await
            .unwrap();
        tokio_tungstenite::Connector::Rustls(Arc::new(tls))
    }

    #[tokio::test]
    async fn websockets_reach_the_target_through_its_socket() {
        let (_dir, socket) = serve_app().await;
        let (upstream, response) = tokio::time::timeout(
            Duration::from_secs(10),
            crate::proxy::connect_upstream_websocket(ws_request(), Some(socket), connector().await),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
        let crate::proxy::UpstreamWebSocket::Unix(mut upstream) = upstream else {
            panic!("expected a Unix socket connection");
        };
        upstream
            .send(tungstenite::Message::Text("hi".into()))
            .await
            .unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(10), upstream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(reply, tungstenite::Message::Text("echo hi".into()));
    }

    #[tokio::test]
    async fn websockets_refuse_a_socket_served_by_another_account() {
        let (_dir, socket) = serve_app().await;
        let connect = |our_uid: u32| {
            let socket = socket.clone();
            async move {
                tokio::time::timeout(
                    Duration::from_secs(10),
                    crate::proxy::connect_unix_websocket(
                        ws_request(),
                        &socket,
                        our_uid,
                        connector().await,
                    ),
                )
                .await
                .unwrap()
            }
        };
        assert!(connect(our_uid()).await.is_ok());
        // The app runs as us; to a Warpgate running as any other uid it is
        // another account's.
        let Err(tungstenite::Error::Io(error)) = connect(our_uid().wrapping_add(1)).await else {
            panic!("connected to a socket served by another account");
        };
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn websockets_check_the_socket_before_connecting() {
        let mut req = Request::builder().finish();
        req.extensions_mut().insert(PlainHttpListener(true));
        let connect = |socket: PathBuf| {
            let req = &req;
            async move {
                let target = options(&socket);
                tokio::time::timeout(
                    Duration::from_secs(10),
                    crate::proxy::connect_target_websocket(
                        req,
                        &target,
                        ws_request(),
                        connector().await,
                    ),
                )
                .await
                .unwrap()
            }
        };

        let (_dir, socket) = serve_app().await;
        assert!(connect(socket).await.is_ok());

        // The same app, its directory open to others: the app would answer,
        // but the socket is refused before it is connected.
        let (_open_dir, socket) = serve_app_in(0o755).await;
        let Err(error) = connect(socket).await else {
            panic!("connected through a socket in a directory open to others");
        };
        assert_eq!(error.status(), StatusCode::BAD_GATEWAY);
        assert!(error.to_string().contains("0700"), "{error}");
    }
}
