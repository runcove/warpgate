use std::collections::HashSet;
use std::sync::LazyLock;

use poem::http::{self, HeaderName};

/// Headers that should not be forwarded to upstream when proxying HTTP requests
/// (or back to the client in responses). Includes the hop-by-hop headers, which
/// describe a single connection rather than the message: each side of the proxy
/// sets its own framing, keep-alive and proxy credentials.
static DONT_FORWARD_HEADERS: LazyLock<HashSet<HeaderName>> = LazyLock::new(|| {
    #[allow(clippy::mutable_key_type)]
    let mut s = HashSet::new();
    s.insert(http::header::ACCEPT_ENCODING);
    s.insert(http::header::SEC_WEBSOCKET_EXTENSIONS);
    s.insert(http::header::SEC_WEBSOCKET_ACCEPT);
    s.insert(http::header::SEC_WEBSOCKET_KEY);
    s.insert(http::header::SEC_WEBSOCKET_VERSION);
    s.insert(http::header::UPGRADE);
    s.insert(http::header::HOST);
    s.insert(http::header::CONNECTION);
    s.insert(http::header::PROXY_AUTHORIZATION);
    s.insert(http::header::TE);
    s.insert(http::header::TRAILER);
    s.insert(http::header::TRANSFER_ENCODING);
    s.insert(HeaderName::from_static("keep-alive"));
    s.insert(HeaderName::from_static("proxy-connection"));
    s.insert(http::header::STRICT_TRANSPORT_SECURITY);
    s.insert(http::header::UPGRADE_INSECURE_REQUESTS);
    s
});

pub fn is_forwarding_header(header_name: &HeaderName) -> bool {
    header_name == http::header::FORWARDED
        || header_name == X_FORWARDED_FOR
        || header_name == X_FORWARDED_HOST
        || header_name == X_FORWARDED_PROTO
        || header_name == X_REAL_IP
}

pub static X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
pub static X_FORWARDED_HOST: HeaderName = HeaderName::from_static("x-forwarded-host");
pub static X_FORWARDED_PROTO: HeaderName = HeaderName::from_static("x-forwarded-proto");
pub static X_REAL_IP: HeaderName = HeaderName::from_static("x-real-ip");

pub static X_WARPGATE_TOKEN: HeaderName = HeaderName::from_static("x-warpgate-token");
pub static X_WARPGATE_CLUSTER_NODE: HeaderName = HeaderName::from_static("x-warpgate-cluster-node");
/// Acting user ID of intra cluster request
pub static X_WARPGATE_CLUSTER_IDENTITY: HeaderName =
    HeaderName::from_static("x-warpgate-cluster-identity");
/// Acting origin client IP for intra cluster request
pub static X_WARPGATE_CLUSTER_CLIENT_IP: HeaderName =
    HeaderName::from_static("x-warpgate-cluster-client-ip");
/// Host the client asked for, as resolved by the forwarding node
pub static X_WARPGATE_CLUSTER_CLIENT_HOST: HeaderName =
    HeaderName::from_static("x-warpgate-cluster-client-host");
/// Scheme the client used, as resolved by the forwarding node
pub static X_WARPGATE_CLUSTER_CLIENT_PROTO: HeaderName =
    HeaderName::from_static("x-warpgate-cluster-client-proto");

/// The header names a message lists in its `Connection` header: they describe
/// that connection only and are not forwarded. Tokens that are not valid header
/// names (such as `close`) are ignored.
pub fn connection_listed_headers(headers: &http::HeaderMap) -> Vec<HeaderName> {
    headers
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|token| HeaderName::from_bytes(token.trim().as_bytes()).ok())
        .collect()
}

pub fn may_forward_header(header_name: &HeaderName) -> bool {
    !DONT_FORWARD_HEADERS.contains(header_name)
        && !is_forwarding_header(header_name)
        && !header_name.as_str().starts_with("x-warpgate-")
}
