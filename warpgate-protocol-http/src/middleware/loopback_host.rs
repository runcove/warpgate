use std::sync::Arc;

use http::uri::Authority;
use http::{StatusCode, header};
use poem::{Endpoint, IntoResponse, Middleware, Request, Response};
use tokio::sync::Mutex;
use warpgate_common::WarpgateConfig;

use crate::common::is_localhost_host;

/// On a plain-HTTP loopback listener (`http.plain_http_on_loopback`), answers
/// 421 to a request whose `Host` is not a loopback name for this listener.
/// Installed outermost, so such a request reaches nothing else.
#[derive(Clone)]
pub struct LoopbackHostMiddleware {
    listen_port: u16,
    config: Arc<Mutex<WarpgateConfig>>,
}

impl LoopbackHostMiddleware {
    pub const fn new(listen_port: u16, config: Arc<Mutex<WarpgateConfig>>) -> Self {
        Self {
            listen_port,
            config,
        }
    }
}

impl<E: Endpoint> Middleware<E> for LoopbackHostMiddleware {
    type Output = LoopbackHostEndpoint<E>;

    fn transform(&self, inner: E) -> Self::Output {
        LoopbackHostEndpoint {
            inner,
            listen_port: self.listen_port,
            config: self.config.clone(),
        }
    }
}

pub struct LoopbackHostEndpoint<E: Endpoint> {
    inner: E,
    listen_port: u16,
    config: Arc<Mutex<WarpgateConfig>>,
}

impl<E: Endpoint> Endpoint for LoopbackHostEndpoint<E> {
    type Output = Response;

    async fn call(&self, req: Request) -> poem::Result<Self::Output> {
        let external_host = self.config.lock().await.external_host_name();
        if !loopback_listener_accepts_host(
            request_host(&req).as_deref(),
            self.listen_port,
            external_host.as_deref(),
        ) {
            return Ok(Response::builder()
                .status(StatusCode::MISDIRECTED_REQUEST)
                .finish());
        }
        Ok(self.inner.call(req).await?.into_response())
    }
}

/// The host the client asked for: the raw `Host` header, never
/// `X-Forwarded-Host`; without one (HTTP/2), the request's own authority.
fn request_host(req: &Request) -> Option<String> {
    match req.headers().get(header::HOST) {
        Some(value) => value.to_str().ok().map(ToOwned::to_owned),
        None => req
            .original_uri()
            .authority()
            .map(|authority| authority.as_str().to_owned()),
    }
}

/// Whether a plain-HTTP loopback listener serves a request for `host`: it
/// must carry the listening port (or none, on port 80) and name `localhost`,
/// a loopback IP literal, or the configured `external_host`. Names compare
/// without regard to ASCII case; IP literals are compared as parsed.
pub(crate) fn loopback_listener_accepts_host(
    host: Option<&str>,
    listen_port: u16,
    external_host: Option<&str>,
) -> bool {
    let Some(host) = host else {
        return false;
    };
    if host.contains('@') {
        return false;
    }
    let Ok(authority) = host.parse::<Authority>() else {
        return false;
    };
    let port_matches = match authority.port_u16() {
        Some(port) => port == listen_port,
        None => listen_port == 80 && !authority.as_str().ends_with(':'),
    };
    if !port_matches {
        return false;
    }
    let name = authority.host();
    name.eq_ignore_ascii_case("localhost")
        || is_localhost_host(name)
        || external_host.is_some_and(|external| name.eq_ignore_ascii_case(external))
}

#[cfg(test)]
mod tests {
    use super::loopback_listener_accepts_host;

    #[test]
    fn unit_loopback_host_accepts_loopback_hosts_on_the_listening_port() {
        for host in [
            "localhost:8888",
            "127.0.0.1:8888",
            "127.4.5.6:8888",
            "[::1]:8888",
            "[::ffff:127.0.0.1]:8888",
        ] {
            assert!(
                loopback_listener_accepts_host(Some(host), 8888, None),
                "{host}"
            );
        }
    }

    #[test]
    fn unit_loopback_host_accepts_the_external_host() {
        assert!(loopback_listener_accepts_host(
            Some("warpgate.local:8888"),
            8888,
            Some("warpgate.local")
        ));
        assert!(!loopback_listener_accepts_host(
            Some("warpgate.local:8888"),
            8888,
            None
        ));
    }

    #[test]
    fn unit_loopback_host_ignores_case() {
        for host in [
            "LOCALHOST:8888",
            "LocalHost:8888",
            "[::FFFF:127.0.0.1]:8888",
        ] {
            assert!(
                loopback_listener_accepts_host(Some(host), 8888, None),
                "{host}"
            );
        }
        assert!(loopback_listener_accepts_host(
            Some("warpgate.local:8888"),
            8888,
            Some("WarpGate.Local")
        ));
        assert!(loopback_listener_accepts_host(
            Some("WARPGATE.local:8888"),
            8888,
            Some("warpgate.LOCAL")
        ));
        assert!(!loopback_listener_accepts_host(
            Some("LOCALHOST.evil.com:8888"),
            8888,
            Some("WarpGate.Local")
        ));
    }

    #[test]
    fn unit_loopback_host_refuses_other_hosts() {
        for host in [
            "evil.example:8888",
            "127.evil.com:8888",
            "127.0.0.1.evil.com:8888",
            "localhost.evil.com:8888",
            "0.0.0.0:8888",
            "[::]:8888",
            "203.0.113.10:8888",
            "user@127.0.0.1:8888",
            "",
        ] {
            assert!(
                !loopback_listener_accepts_host(Some(host), 8888, Some("warpgate.local")),
                "{host}"
            );
        }
        assert!(!loopback_listener_accepts_host(None, 8888, None));
    }

    #[test]
    fn unit_loopback_host_refuses_a_wrong_or_missing_port() {
        for host in [
            "localhost:9999",
            "127.0.0.1:80",
            "[::1]:443",
            "localhost",
            "localhost:",
        ] {
            assert!(
                !loopback_listener_accepts_host(Some(host), 8888, None),
                "{host}"
            );
        }
        // Port 80 may be left out, as browsers do.
        assert!(loopback_listener_accepts_host(Some("localhost"), 80, None));
        assert!(loopback_listener_accepts_host(
            Some("localhost:80"),
            80,
            None
        ));
    }
}
