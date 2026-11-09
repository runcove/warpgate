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
    s.insert(http::header::PROXY_AUTHENTICATE);
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
/// that connection only and are not forwarded. The value is split on commas as
/// bytes, so a value that is not valid UTF-8 still names its other tokens.
/// Tokens are trimmed and matched ASCII case-insensitively. Tokens that are not
/// valid header names are ignored; `close` is collected like any other token
/// (it is harmless, since no such header is forwarded).
pub fn connection_listed_headers(headers: &http::HeaderMap) -> Vec<HeaderName> {
    headers
        .get_all(http::header::CONNECTION)
        .iter()
        .flat_map(|v| v.as_bytes().split(|b| *b == b','))
        .filter_map(|token| HeaderName::from_bytes(token.trim_ascii()).ok())
        .collect()
}

/// Decides which headers of one message may be forwarded. It combines the
/// static deny-list, the headers the message's own `Connection` header lists,
/// and the RFC 9112 framing rule: when `Transfer-Encoding` was present the
/// `Content-Length` is dropped too, so the next hop recomputes the framing
/// and never receives both.
///
/// Every proxy path (HTTP proxy, cluster hop, Kubernetes) builds one from the
/// message it is copying so they apply the same rules.
pub struct ForwardFilter {
    listed: Vec<HeaderName>,
    has_transfer_encoding: bool,
}

impl ForwardFilter {
    pub fn new(headers: &http::HeaderMap) -> Self {
        Self {
            listed: connection_listed_headers(headers),
            has_transfer_encoding: headers.contains_key(http::header::TRANSFER_ENCODING),
        }
    }

    pub fn allows(&self, header_name: &HeaderName) -> bool {
        may_forward_header(header_name)
            && !self.listed.contains(header_name)
            && !(self.has_transfer_encoding && header_name == http::header::CONTENT_LENGTH)
    }
}

pub fn may_forward_header(header_name: &HeaderName) -> bool {
    !DONT_FORWARD_HEADERS.contains(header_name)
        && !is_forwarding_header(header_name)
        && !header_name.as_str().starts_with("x-warpgate-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hop_by_hop_headers_are_not_forwarded() {
        for name in [
            "connection",
            "upgrade",
            "te",
            "trailer",
            "transfer-encoding",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "proxy-connection",
        ] {
            assert!(
                !may_forward_header(&HeaderName::from_static(name)),
                "{name}"
            );
        }
        assert!(may_forward_header(&HeaderName::from_static("x-custom")));
    }

    #[test]
    fn connection_listed_headers_reads_every_token_of_every_line() {
        let mut headers = http::HeaderMap::new();
        headers.append(
            http::header::CONNECTION,
            "close,  X-One ,, keep-alive".parse().unwrap(),
        );
        headers.append(http::header::CONNECTION, "X-TWO".parse().unwrap());
        let listed = connection_listed_headers(&headers);
        assert_eq!(
            listed,
            [
                HeaderName::from_static("close"),
                HeaderName::from_static("x-one"),
                HeaderName::from_static("keep-alive"),
                HeaderName::from_static("x-two"),
            ]
        );
        assert!(connection_listed_headers(&http::HeaderMap::new()).is_empty());
    }

    #[test]
    fn forward_filter_drops_connection_listed_headers() {
        let mut headers = http::HeaderMap::new();
        headers.append(http::header::CONNECTION, "close, X-Hop".parse().unwrap());
        headers.append("x-hop", "1".parse().unwrap());
        headers.append("x-keep", "1".parse().unwrap());
        let filter = ForwardFilter::new(&headers);
        assert!(!filter.allows(&HeaderName::from_static("x-hop")));
        assert!(!filter.allows(&http::header::CONNECTION));
        assert!(filter.allows(&HeaderName::from_static("x-keep")));
    }

    #[test]
    fn connection_listed_headers_survive_a_non_utf8_value() {
        let mut headers = http::HeaderMap::new();
        headers.append(
            http::header::CONNECTION,
            http::HeaderValue::from_bytes(b"\xff, X-Hop").unwrap(),
        );
        headers.append("x-hop", "1".parse().unwrap());
        let filter = ForwardFilter::new(&headers);
        assert!(!filter.allows(&HeaderName::from_static("x-hop")));
    }

    #[test]
    fn forward_filter_matches_tokens_across_lines_and_case() {
        let mut headers = http::HeaderMap::new();
        headers.append(http::header::CONNECTION, "X-ONE".parse().unwrap());
        headers.append(
            http::header::CONNECTION,
            " x-Two ,keep-alive".parse().unwrap(),
        );
        let filter = ForwardFilter::new(&headers);
        assert!(!filter.allows(&HeaderName::from_static("x-one")));
        assert!(!filter.allows(&HeaderName::from_static("x-two")));
        assert!(filter.allows(&HeaderName::from_static("x-three")));
    }

    #[test]
    fn forward_filter_drops_content_length_only_with_transfer_encoding() {
        let mut headers = http::HeaderMap::new();
        headers.append(http::header::CONTENT_LENGTH, "5".parse().unwrap());
        assert!(ForwardFilter::new(&headers).allows(&http::header::CONTENT_LENGTH));

        headers.append(http::header::TRANSFER_ENCODING, "chunked".parse().unwrap());
        let filter = ForwardFilter::new(&headers);
        assert!(!filter.allows(&http::header::CONTENT_LENGTH));
        assert!(!filter.allows(&http::header::TRANSFER_ENCODING));
    }
}
