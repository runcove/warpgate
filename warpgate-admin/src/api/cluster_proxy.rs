//! Cross-node proxy for node-owned resources.
//!
//! An in-progress recording's data, and a live session's handle, exist only on
//! the node that owns the connection. For these to be reachable from other
//! nodes, the requests are proxied between nodes.
//!
//! A URL handler on another node calls [`proxy_or_serve`] (or [`proxy_or_serve_websocket`])
//! after auth. If the resource is on another node, it forwards the request there,
//! otherwise it runs the local serve logic.
//!
//! Cross-node proxy requests are authenticated by the sending node's pinned TLS
//! client certificate (see `warpgate_common_http::cluster_tls`); the receiving
//! side then trusts the identity headers stamped here.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use futures::{StreamExt, TryStreamExt};
use poem::http::header::{CONNECTION, CONTENT_LENGTH, COOKIE, HOST, TRANSFER_ENCODING, UPGRADE};
use poem::http::{HeaderName, StatusCode};
use poem::web::websocket::WebSocket;
use poem::{Body, IntoResponse, Request, Response};
use poem_openapi::types::ParseFromJSON;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream, client_async_tls_with_config, tungstenite,
};
use uuid::Uuid;
use warpgate_ca::CLUSTER_TLS_SNI_NAME;
use warpgate_common::helpers::websocket::{pump_websocket, websocket_connect_failed};
use warpgate_common::http_headers::ForwardFilter;
use warpgate_common_http::auth::UnauthenticatedRequestContext;
use warpgate_common_http::logging::get_client_ip;
use warpgate_common_http::{
    AuthenticatedRequestContext, RequestAuthorization, X_WARPGATE_CLUSTER_CLIENT_HOST,
    X_WARPGATE_CLUSTER_CLIENT_IP, X_WARPGATE_CLUSTER_CLIENT_PROTO, X_WARPGATE_CLUSTER_IDENTITY,
    X_WARPGATE_CLUSTER_NODE, is_cluster_peer_request, trusted_host_header, trusted_proto,
};
use warpgate_core::Services;
use warpgate_core::cluster::PeerConnection;
pub use warpgate_core::cluster::{Owner, RemoteNode};

/// Who a forwarded request acts as on the peer.
enum ForwardIdentity<'a> {
    /// An authenticated request: the peer runs it as this user and re-checks
    /// ownership of whatever the path names. The browser session cookie is
    /// dropped — peer hops authenticate via the node's TLS identity, not the
    /// cookie.
    User(&'a RequestAuthorization),
    /// An in-progress, not-yet-authenticated login: there is no identity to
    /// stamp, and the session cookie is forwarded instead so the peer resolves
    /// the same session and reaches the auth state only it holds.
    PendingLogin,
}

impl ForwardIdentity<'_> {
    fn user_id(&self) -> Option<Uuid> {
        match self {
            Self::User(auth) => auth.as_full_user().map(|u| u.user_id()),
            Self::PendingLogin => None,
        }
    }

    const fn forwards_cookie(&self) -> bool {
        matches!(self, Self::PendingLogin)
    }
}

/// Serve a request with `serve_local`, or if the resource is owned by another
/// node, forward the request there instead.
pub async fn proxy_or_serve<F, Fut, B: Serialize, R: ReparseForwardedResponse>(
    ctx: &AuthenticatedRequestContext,
    req: &Request,
    owner: Owner,
    body: Option<&B>,
    serve_local: F,
) -> poem::Result<R>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = poem::Result<R>>,
{
    proxy_or_serve_as(
        ctx,
        ForwardIdentity::User(&ctx.auth),
        req,
        owner,
        body,
        serve_local,
    )
    .await
}

/// [`proxy_or_serve`] for a login step that has not authenticated yet: the peer
/// is reached as the browser session rather than as a user.
pub async fn proxy_or_serve_pending_login<F, Fut, B: Serialize, R: ReparseForwardedResponse>(
    ctx: &UnauthenticatedRequestContext,
    req: &Request,
    owner: Owner,
    body: Option<&B>,
    serve_local: F,
) -> poem::Result<R>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = poem::Result<R>>,
{
    proxy_or_serve_as(
        ctx,
        ForwardIdentity::PendingLogin,
        req,
        owner,
        body,
        serve_local,
    )
    .await
}

async fn proxy_or_serve_as<F, Fut, B: Serialize, R: ReparseForwardedResponse>(
    ctx: &UnauthenticatedRequestContext,
    identity: ForwardIdentity<'_>,
    req: &Request,
    owner: Owner,
    body: Option<&B>,
    serve_local: F,
) -> poem::Result<R>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = poem::Result<R>>,
{
    match owner {
        Owner::Remote(remote) => {
            let response = forward_http_inner(
                ctx.services(),
                req,
                &path_and_query(req),
                remote,
                identity,
                body.map(|b| serde_json::to_vec(&b))
                    .transpose()
                    .context("serializing body for forwarding")?,
            )
            .await?;

            Ok(R::reparse_forwarded_response(response).await?)
        }
        Owner::Local => serve_local().await,
    }
}

pub async fn proxy_or_serve_websocket<F, Fut>(
    ctx: &AuthenticatedRequestContext,
    req: &Request,
    ws: WebSocket,
    owner: Owner,
    serve_local: F,
) -> poem::Result<Response>
where
    F: FnOnce(WebSocket) -> Fut,
    Fut: Future<Output = poem::Result<Response>>,
{
    match owner {
        Owner::Remote(remote) => forward_websocket(ctx, req, ws, remote).await,
        Owner::Local => serve_local(ws).await,
    }
}

fn reject_second_hop(req: &Request) -> poem::Result<()> {
    if is_cluster_peer_request(req) {
        return Err(poem::Error::from_string(
            "Refusing to forward an already-forwarded cluster request",
            StatusCode::BAD_GATEWAY,
        ));
    }
    Ok(())
}

/// Connect to the first reachable resolved address.
async fn connect_any(
    addrs: &[SocketAddr],
) -> Result<tokio::net::TcpStream, Option<std::io::Error>> {
    let mut last_error = None;
    for addr in addrs {
        match tokio::net::TcpStream::connect(addr).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error)
}

/// Forwards `req` to `owner` as `identity`.
async fn forward_http_inner(
    services: &Services,
    req: &Request,
    path: &str,
    owner: RemoteNode,
    identity: ForwardIdentity<'_>,
    body: Option<Vec<u8>>,
) -> poem::Result<Response> {
    reject_second_hop(req)?;

    let headers = forwarded_headers(req.headers(), identity.forwards_cookie());

    let mut request = services
        .cluster
        .peer_request(&owner, req.method().clone(), path)
        .await?
        .headers(headers);
    if let Some(user_id) = identity.user_id() {
        request = request.header(X_WARPGATE_CLUSTER_IDENTITY.clone(), user_id.to_string());
    }
    // The peer's TCP peer is this node, so pass on who the client really is.
    if let Some(client_ip) = get_client_ip(req, services).await {
        request = request.header(X_WARPGATE_CLUSTER_CLIENT_IP.clone(), client_ip);
    }
    // Likewise the host and scheme the client used, resolved here with this
    // node's own trust settings; the client's raw forwarding headers stop here.
    let should_trust_x_forwarded = services
        .config
        .lock()
        .await
        .store
        .http
        .trust_x_forwarded_headers;
    if let Some(host) = trusted_host_header(should_trust_x_forwarded, req) {
        request = request.header(X_WARPGATE_CLUSTER_CLIENT_HOST.clone(), host);
    }
    request = request.header(
        X_WARPGATE_CLUSTER_CLIENT_PROTO.clone(),
        trusted_proto(should_trust_x_forwarded, req).as_str(),
    );
    if let Some(body) = body {
        request = request.body(body);
    }
    let response = request
        .send()
        .await
        .map_err(|error| poem::error::BadGateway(error.without_url()))?;

    let mut builder = Response::builder().status(response.status());
    let filter = ForwardFilter::new(response.headers());
    for (name, value) in response.headers() {
        if should_forward(&filter, name) {
            builder = builder.header(name, value);
        }
    }
    Ok(builder.body(Body::from_bytes_stream(
        response
            .bytes_stream()
            .map_err(|error| std::io::Error::other(error.without_url())),
    )))
}

pub async fn forward_websocket(
    ctx: &AuthenticatedRequestContext,
    req: &Request,
    ws: WebSocket,
    owner: RemoteNode,
) -> poem::Result<Response> {
    reject_second_hop(req)?;
    let cluster = &ctx.services().cluster;
    let PeerConnection { tls, addrs, port } = cluster.peer_connection(&owner).await?;
    let host = format!("{CLUSTER_TLS_SNI_NAME}:{port}");
    let url = format!("wss://{host}{}", path_and_query(req));

    let mut builder = poem::http::Request::builder()
        .uri(&url)
        .header(CONNECTION, "Upgrade")
        .header(UPGRADE, "websocket")
        .header(poem::http::header::SEC_WEBSOCKET_VERSION, "13")
        .header(
            poem::http::header::SEC_WEBSOCKET_KEY,
            tungstenite::handshake::client::generate_key(),
        )
        .header(HOST, host)
        .header(X_WARPGATE_CLUSTER_NODE.clone(), cluster.node_id.to_string());
    if let Some(user_id) = ctx.auth.as_full_user().map(|x| x.user_id()) {
        builder = builder.header(X_WARPGATE_CLUSTER_IDENTITY.clone(), user_id.to_string());
    }
    let request = builder.body(()).map_err(poem::error::InternalServerError)?;

    let stream = connect_any(&addrs).await.map_err(|e| {
        poem::error::BadGateway(e.unwrap_or_else(|| std::io::Error::other("no peer address")))
    })?;

    let peer = upgrade_to_peer(request, stream, Connector::Rustls(Arc::new(tls))).await?;

    Ok(ws
        .on_upgrade(move |socket| async move {
            let (peer_sink, peer_source) = peer.split();
            let (client_sink, client_source) = socket.split();
            let identity = |msg| Box::pin(async move { anyhow::Ok(msg) });
            let mut to_client = tokio::spawn(pump_websocket(
                peer_source,
                client_sink,
                identity,
                "cluster_peer_to_client",
            ));
            let mut to_peer = tokio::spawn(pump_websocket(
                client_source,
                peer_sink,
                identity,
                "cluster_client_to_peer",
            ));
            tokio::select! {
                _ = &mut to_client => to_peer.abort(),
                _ = &mut to_peer => to_client.abort(),
            }
        })
        .into_response())
}

/// Opens the WebSocket to the peer over `stream`. A refused upgrade is a 502
/// that keeps only the peer's status ([`websocket_connect_failed`]).
async fn upgrade_to_peer<S>(
    request: poem::http::Request<()>,
    stream: S,
    connector: Connector,
) -> poem::Result<WebSocketStream<MaybeTlsStream<S>>>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (peer, _) = client_async_tls_with_config(request, stream, None, Some(connector))
        .await
        .map_err(websocket_connect_failed)?;
    Ok(peer)
}

fn path_and_query(req: &Request) -> String {
    req.original_uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_default()
}

/// Cluster-hop header filter: everything the general proxy deny-list blocks
/// (connection management plus any `x-warpgate-*` credential), plus message
/// framing — the body is re-streamed, so the original framing headers don't
/// apply — and the client's cookies: the peer hop is authorized by the node's
/// TLS identity alone. The client's own forwarding headers and any
/// `x-warpgate-cluster-*` header are dropped; the peer gets the host, scheme
/// and address this node resolved, in cluster-only headers.
fn should_forward(filter: &ForwardFilter, name: &HeaderName) -> bool {
    filter.allows(name) && name != CONTENT_LENGTH && name != TRANSFER_ENCODING && name != COOKIE
}

/// The session cookie's name inside a node, behind its cookie gate.
const INNER_SESSION_COOKIE_NAME: &[u8] = b"warpgate-http-session";
/// The session cookie's name in a browser on a TLS listener, the only name
/// a node's cookie gate accepts it under there.
const HOST_SESSION_COOKIE_NAME: &[u8] = b"__Host-warpgate-http-session";

/// The headers a forwarded request carries to the peer. With
/// `forwards_cookie`, every `Cookie` header is passed on (the cookie gate
/// splits the browser's cookies over two), and the session cookie goes under
/// the browser's name: the peer's gate reads the request as a browser's and
/// drops the inner name as the old domain-wide cookie.
fn forwarded_headers(
    request_headers: &poem::http::HeaderMap,
    forwards_cookie: bool,
) -> poem::http::HeaderMap {
    let mut headers = poem::http::HeaderMap::new();
    let filter = ForwardFilter::new(request_headers);
    for (name, value) in request_headers {
        if forwards_cookie && name == COOKIE {
            headers.append(COOKIE, browser_cookie_header(value));
        } else if should_forward(&filter, name) {
            headers.insert(name.clone(), value.clone());
        }
    }
    headers
}

/// `value` with an exact inner session cookie pair renamed to the browser's
/// name; every other byte is kept as it is.
fn browser_cookie_header(value: &poem::http::HeaderValue) -> poem::http::HeaderValue {
    let mut renamed = false;
    let mut out = Vec::with_capacity(value.len() + 8);
    for (index, pair) in value.as_bytes().split(|byte| *byte == b';').enumerate() {
        if index > 0 {
            out.push(b';');
        }
        let rest = pair.trim_ascii_start();
        out.extend_from_slice(&pair[..pair.len() - rest.len()]);
        match rest
            .strip_prefix(INNER_SESSION_COOKIE_NAME)
            .filter(|tail| tail.first() == Some(&b'='))
        {
            Some(tail) => {
                renamed = true;
                out.extend_from_slice(HOST_SESSION_COOKIE_NAME);
                out.extend_from_slice(tail);
            }
            None => out.extend_from_slice(rest),
        }
    }
    if !renamed {
        return value.clone();
    }
    poem::http::HeaderValue::from_bytes(&out).unwrap_or_else(|_| value.clone())
}

pub trait ReparseForwardedResponse: Sized {
    fn reparse_forwarded_response(
        response: Response,
    ) -> impl Future<Output = poem::Result<Self>> + Send;
}

/// Parses a forwarded response body as a poem-openapi object, which have no
/// serde impls of their own.
pub async fn parse_forwarded_body<T: ParseFromJSON>(response: Response) -> poem::Result<T> {
    let bytes = response
        .into_body()
        .into_bytes()
        .await
        .map_err(poem::error::InternalServerError)?;
    let value = serde_json::from_slice(&bytes).map_err(poem::error::InternalServerError)?;
    T::parse_from_json(Some(value))
        .map_err(|e| poem::Error::from_string(e.into_message(), StatusCode::INTERNAL_SERVER_ERROR))
}

/// A peer response outside the endpoint's own set of outcomes, surfaced with the
/// peer's status and body rather than parsed as one of them.
pub async fn forwarded_error(response: Response) -> poem::Error {
    let status = response.status();
    let body = response.into_body().into_string().await.unwrap_or_default();
    poem::Error::from_string(body, status)
}

impl ReparseForwardedResponse for Response {
    async fn reparse_forwarded_response(response: Response) -> poem::Result<Self> {
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use poem::http::HeaderName;
    use warpgate_common::http_headers::{
        X_FORWARDED_FOR, X_FORWARDED_HOST, X_FORWARDED_PROTO, X_REAL_IP,
    };
    use warpgate_common_http::{
        X_WARPGATE_CLUSTER_CLIENT_HOST, X_WARPGATE_CLUSTER_CLIENT_IP,
        X_WARPGATE_CLUSTER_CLIENT_PROTO, X_WARPGATE_CLUSTER_IDENTITY,
    };

    use poem::http::HeaderMap;

    use super::{ForwardFilter, forwarded_headers, should_forward as should_forward_with};

    fn should_forward(name: &HeaderName) -> bool {
        should_forward_with(&ForwardFilter::new(&HeaderMap::new()), name)
    }

    #[test]
    fn should_forward_drops_the_clients_forwarding_headers() {
        for name in [
            &X_FORWARDED_FOR,
            &X_FORWARDED_HOST,
            &X_FORWARDED_PROTO,
            &X_REAL_IP,
            &poem::http::header::FORWARDED,
        ] {
            assert!(!should_forward(name), "{name} was forwarded");
        }
    }

    #[test]
    fn should_forward_drops_client_sent_cluster_headers() {
        for name in [
            &X_WARPGATE_CLUSTER_CLIENT_HOST,
            &X_WARPGATE_CLUSTER_CLIENT_IP,
            &X_WARPGATE_CLUSTER_CLIENT_PROTO,
            &X_WARPGATE_CLUSTER_IDENTITY,
        ] {
            assert!(!should_forward(name), "{name} was forwarded");
        }
    }

    #[test]
    fn should_forward_keeps_ordinary_headers() {
        assert!(should_forward(&HeaderName::from_static("accept")));
    }

    /// A peer that refuses the WebSocket upgrade is logged by its status
    /// alone: the headers and body of its answer are not.
    #[tokio::test]
    async fn a_refused_peer_upgrade_is_logged_by_its_status() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio_tungstenite::Connector;
        use warpgate_common_http::logging::log_request_error;
        use warpgate_common_http::test_log::logged;

        const COOKIE: &str = "sid-sentinel-4d17";
        const LOCATION: &str = "loc-sentinel-a0c3";
        const BODY: &str = "body-sentinel-e62b";

        let (client, mut peer) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let mut request = Vec::new();
            let mut buf = [0u8; 1024];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = peer.read(&mut buf).await.unwrap();
                assert!(n > 0, "the request ended early");
                request.extend_from_slice(buf.get(..n).unwrap());
            }
            let answer = format!(
                "HTTP/1.1 302 Found\r\nSet-Cookie: sid={COOKIE}\r\n\
                 Location: /login?next={LOCATION}\r\nContent-Length: {}\r\n\r\n{BODY}",
                BODY.len()
            );
            peer.write_all(answer.as_bytes()).await.unwrap();
            peer.flush().await.unwrap();
        });
        let request = poem::http::Request::builder()
            .uri("ws://peer.invalid/x")
            .header(poem::http::header::CONNECTION, "Upgrade")
            .header(poem::http::header::UPGRADE, "websocket")
            .header(poem::http::header::SEC_WEBSOCKET_VERSION, "13")
            .header(
                poem::http::header::SEC_WEBSOCKET_KEY,
                tokio_tungstenite::tungstenite::handshake::client::generate_key(),
            )
            .header(poem::http::header::HOST, "peer.invalid")
            .body(())
            .unwrap();
        // The refused upgrade is an error.
        let error = super::upgrade_to_peer(request, client, Connector::Plain)
            .await
            .err()
            .unwrap();
        assert_eq!(error.status(), poem::http::StatusCode::BAD_GATEWAY);

        let uri: poem::http::Uri = "/x".parse().unwrap();
        let line = logged(|| {
            log_request_error(&poem::http::Method::GET, &uri, None, &error);
        });
        assert!(line.contains("Request failed"), "{line}");
        assert!(line.contains("302"), "{line}");
        // A response's body is logged as its bytes, not as text.
        let body_bytes = format!("{:?}", BODY.as_bytes());
        let body_bytes = body_bytes.trim_matches(['[', ']']);
        for secret in [COOKIE, LOCATION, BODY, body_bytes] {
            assert!(!line.contains(secret), "{line}");
        }
    }

    #[test]
    fn should_forward_drops_connection_listed_headers() {
        let mut headers = HeaderMap::new();
        headers.append(
            poem::http::header::CONNECTION,
            "close, X-Hop-One".parse().unwrap(),
        );
        headers.append("x-hop-one", "1".parse().unwrap());
        headers.append("x-other", "1".parse().unwrap());
        let filter = ForwardFilter::new(&headers);
        assert!(!should_forward_with(
            &filter,
            &HeaderName::from_static("x-hop-one")
        ));
        assert!(should_forward_with(
            &filter,
            &HeaderName::from_static("x-other")
        ));
    }

    /// A forwarded login step carries both of the cookie gate's `Cookie`
    /// headers, the session under the name the peer's gate accepts, and the
    /// other header's bytes (not ASCII here) unchanged.
    #[test]
    fn a_forwarded_login_step_keeps_every_cookie_header() {
        use poem::http::HeaderValue;
        use poem::http::header::COOKIE;
        let mut headers = HeaderMap::new();
        headers.append(
            COOKIE,
            HeaderValue::from_static("warpgate-http-session=s3ss; x=1"),
        );
        let other = HeaderValue::from_bytes("planted=caf\u{e9}; y=2".as_bytes()).unwrap();
        headers.append(COOKIE, other.clone());
        headers.append("accept", HeaderValue::from_static("*/*"));

        let forwarded = forwarded_headers(&headers, true);
        let cookies: Vec<_> = forwarded.get_all(COOKIE).iter().cloned().collect();
        assert_eq!(
            cookies,
            vec![
                HeaderValue::from_static("__Host-warpgate-http-session=s3ss; x=1"),
                other,
            ]
        );
        assert!(forwarded.contains_key("accept"));

        // Without the browser's cookie, none is forwarded.
        assert!(!forwarded_headers(&headers, false).contains_key(COOKIE));
    }

    /// Only the exact session pair is renamed.
    #[test]
    fn only_the_exact_session_pair_is_renamed() {
        use poem::http::HeaderValue;
        use poem::http::header::COOKIE;
        let mut headers = HeaderMap::new();
        headers.append(
            COOKIE,
            HeaderValue::from_static("warpgate-http-session-x=1;warpgate-http-session=2"),
        );
        let forwarded = forwarded_headers(&headers, true);
        assert_eq!(
            forwarded.get(COOKIE).unwrap(),
            "warpgate-http-session-x=1;__Host-warpgate-http-session=2"
        );
    }
}
