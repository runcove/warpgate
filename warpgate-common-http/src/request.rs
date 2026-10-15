use poem::Request;
use poem::http::header::HOST;
use poem::http::uri::Scheme;
use warpgate_common::Secret;
use warpgate_common::http_headers::{X_FORWARDED_HOST, X_FORWARDED_PROTO};

use crate::{X_WARPGATE_CLUSTER_CLIENT_IP, is_cluster_peer_request};

pub fn first_forwarded_header_value(value: &str) -> Option<&str> {
    value
        .split(',')
        .map(str::trim)
        .find(|value| !value.is_empty())
}

pub fn trusted_host_header(should_trust_x_forwarded: bool, req: &Request) -> Option<String> {
    if should_trust_x_forwarded
        && let Some(host) = req
            .header(&X_FORWARDED_HOST)
            .and_then(first_forwarded_header_value)
    {
        return Some(host.to_string());
    }

    req.header(HOST).map(ToString::to_string).or_else(|| {
        let uri = req.original_uri();
        uri.authority().map(|authority| authority.to_string())
    })
}

/// Request data from the HTTP listener: whether it serves plain HTTP
/// (`http.plain_http_on_loopback`). A request without it came over TLS.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PlainHttpListener(pub bool);

pub fn trusted_proto(should_trust_x_forwarded: bool, req: &Request) -> Scheme {
    if should_trust_x_forwarded
        && let Some(proto) = req
            .header(&X_FORWARDED_PROTO)
            .and_then(first_forwarded_header_value)
        && let Ok(s) = Scheme::try_from(proto)
    {
        s
    } else {
        req.original_uri().scheme().cloned().unwrap_or_else(|| {
            if req
                .data::<PlainHttpListener>()
                .is_some_and(|listener| listener.0)
            {
                Scheme::HTTP
            } else {
                Scheme::HTTPS
            }
        })
    }
}

/// The client address for a web request: a cluster peer's word (it holds the
/// cluster token), else the header the operator named in `client_ip_header`,
/// else the socket peer. `X-Forwarded-For` is never read here: the caller writes
/// it, so it cannot say who the caller is. A proxy in front of Warpgate names
/// the header it sets itself (e.g. `CF-Connecting-IP`, `X-Real-IP`).
pub fn trusted_client_ip(
    req: &Request,
    cluster_token: &Secret<String>,
    remote_ip: Option<String>,
    client_ip_header: Option<&str>,
) -> Option<String> {
    if is_cluster_peer_request(req, cluster_token)
        && let Some(ip) = req.header(&X_WARPGATE_CLUSTER_CLIENT_IP)
    {
        Some(ip.to_string())
    } else if let Some(name) = client_ip_header {
        req.header(name)
            .and_then(|value| value.trim().parse::<std::net::IpAddr>().ok())
            .map(|ip| ip.to_string())
            .or(remote_ip)
    } else {
        remote_ip
    }
}

#[cfg(test)]
mod tests {
    use poem::Request;
    use poem::http::header::HOST;
    use warpgate_common::http_headers::X_FORWARDED_FOR;

    use super::*;
    use crate::X_WARPGATE_CLUSTER_TOKEN;

    fn trusted_header_request(
        forwarded_host: Option<&str>,
        forwarded_proto: Option<&str>,
    ) -> Request {
        let mut builder = Request::builder()
            .uri_str("http://internal.example")
            .header(HOST, "fallback.example");

        if let Some(value) = forwarded_host {
            builder = builder.header(&X_FORWARDED_HOST, value);
        }
        if let Some(value) = forwarded_proto {
            builder = builder.header(&X_FORWARDED_PROTO, value);
        }

        builder.finish()
    }

    #[test]
    fn trusted_host_uses_first_forwarded_host() {
        let req = trusted_header_request(Some("public.example, proxy.local"), None);

        assert_eq!(
            trusted_host_header(true, &req),
            Some("public.example".to_string())
        );
    }

    #[test]
    fn trusted_host_header_preserves_port() {
        let req = Request::builder()
            .uri_str("http://internal.example")
            .header(HOST, "vm.example.com:3000")
            .finish();

        assert_eq!(
            trusted_host_header(false, &req),
            Some("vm.example.com:3000".to_string())
        );
    }

    #[test]
    fn trusted_host_falls_back_when_forwarded_host_is_empty() {
        let req = trusted_header_request(Some(" , "), None);

        assert_eq!(
            trusted_host_header(true, &req),
            Some("fallback.example".to_string())
        );
    }

    #[test]
    fn trusted_proto_is_https_by_default() {
        for listener in [None, Some(PlainHttpListener(false))] {
            let mut builder = Request::builder().header(HOST, "warpgate.example");
            if let Some(listener) = listener {
                builder = builder.extension(listener);
            }
            assert_eq!(trusted_proto(false, &builder.finish()), Scheme::HTTPS);
        }
    }

    #[test]
    fn trusted_proto_is_http_on_a_plain_http_listener() {
        let req = Request::builder()
            .header(HOST, "localhost:8888")
            .extension(PlainHttpListener(true))
            .finish();

        assert_eq!(trusted_proto(false, &req), Scheme::HTTP);
    }

    #[test]
    fn trusted_proto_uses_first_forwarded_proto() {
        let req = trusted_header_request(None, Some("https, http"));

        assert_eq!(trusted_proto(true, &req), Scheme::HTTPS);
    }

    #[test]
    fn first_forwarded_header_value_skips_empty_items() {
        assert_eq!(
            first_forwarded_header_value(" , public.example, proxy.local"),
            Some("public.example")
        );
        assert_eq!(first_forwarded_header_value(" , "), None);
    }

    #[test]
    fn client_ip_never_comes_from_forwarded_for() {
        let req = Request::builder()
            .header(&X_FORWARDED_FOR, "203.0.113.10, 10.0.0.2")
            .finish();

        assert_eq!(
            trusted_client_ip(
                &req,
                &Secret::new("".into()),
                Some("10.0.0.1".to_string()),
                None
            ),
            Some("10.0.0.1".to_string())
        );
    }

    #[test]
    fn trusted_client_ip_falls_back_when_forwarded_for_is_empty() {
        let req = Request::builder().header(&X_FORWARDED_FOR, " , ").finish();

        assert_eq!(
            trusted_client_ip(
                &req,
                &Secret::new("".into()),
                Some("10.0.0.1".to_string()),
                None
            ),
            Some("10.0.0.1".to_string())
        );
    }

    #[test]
    fn client_ip_ignores_forwarded_for_when_not_trusted() {
        let req = Request::builder()
            .header(&X_FORWARDED_FOR, "203.0.113.10")
            .finish();

        assert_eq!(
            trusted_client_ip(
                &req,
                &Secret::new("".into()),
                Some("10.0.0.1".to_string()),
                None
            ),
            Some("10.0.0.1".to_string())
        );
    }

    #[test]
    fn client_ip_takes_the_forwarding_peers_word_for_it() {
        let req = Request::builder()
            .header(&X_WARPGATE_CLUSTER_TOKEN, "s3cret")
            .header(&X_WARPGATE_CLUSTER_CLIENT_IP, "203.0.113.10")
            .finish();

        assert_eq!(
            trusted_client_ip(
                &req,
                &Secret::new("s3cret".into()),
                Some("10.0.0.1".to_string()),
                None
            ),
            Some("203.0.113.10".to_string())
        );
    }

    #[test]
    fn client_ip_ignores_a_forged_cluster_client_ip() {
        let req = Request::builder()
            .header(&X_WARPGATE_CLUSTER_TOKEN, "guess")
            .header(&X_WARPGATE_CLUSTER_CLIENT_IP, "203.0.113.10")
            .finish();

        assert_eq!(
            trusted_client_ip(
                &req,
                &Secret::new("s3cret".into()),
                Some("10.0.0.1".to_string()),
                None
            ),
            Some("10.0.0.1".to_string())
        );
    }

    #[test]
    fn client_ip_header_wins_over_forwarded_for() {
        let req = Request::builder()
            .header(&X_FORWARDED_FOR, "198.51.100.66")
            .header("cf-connecting-ip", "203.0.113.10")
            .finish();

        assert_eq!(
            trusted_client_ip(
                &req,
                &Secret::new("".into()),
                Some("10.244.1.5".to_string()),
                Some("CF-Connecting-IP")
            ),
            Some("203.0.113.10".to_string())
        );
    }

    #[test]
    fn client_ip_header_missing_falls_back_to_peer_not_forwarded_for() {
        let req = Request::builder()
            .header(&X_FORWARDED_FOR, "198.51.100.66")
            .finish();

        assert_eq!(
            trusted_client_ip(
                &req,
                &Secret::new("".into()),
                Some("10.244.1.5".to_string()),
                Some("CF-Connecting-IP")
            ),
            Some("10.244.1.5".to_string())
        );
    }

    #[test]
    fn client_ip_header_rejects_a_value_that_is_not_an_address() {
        let req = Request::builder()
            .header("cf-connecting-ip", "203.0.113.10, 198.51.100.66")
            .finish();

        assert_eq!(
            trusted_client_ip(
                &req,
                &Secret::new("".into()),
                Some("10.244.1.5".to_string()),
                Some("CF-Connecting-IP")
            ),
            Some("10.244.1.5".to_string())
        );
    }

    #[test]
    fn client_ip_header_accepts_ipv6() {
        let req = Request::builder()
            .header("cf-connecting-ip", "2001:db8::7")
            .finish();

        assert_eq!(
            trusted_client_ip(
                &req,
                &Secret::new("".into()),
                None,
                Some("CF-Connecting-IP")
            ),
            Some("2001:db8::7".to_string())
        );
    }
}
