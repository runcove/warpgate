use std::borrow::Cow;
use std::net::{IpAddr, ToSocketAddrs};

use poem::http::{Method, StatusCode, Uri};
use poem::web::RemoteAddr;
use poem::{Addr, Request};
use tracing::*;
use url::form_urlencoded;
use warpgate_core::{Services, WarpgateServerHandle};

use crate::request::trusted_client_ip;

/// The peer IP of the connection itself, ignoring any forwarding headers.
pub fn raw_remote_ip(req: &Request) -> Option<String> {
    let socket_addr = match req.remote_addr() {
        // An acceptor that learned something during the TLS handshake carries
        // it after the socket address (see `tls_acceptor::annotate_remote_addr`)
        RemoteAddr(Addr::Custom(_, value)) => value
            .split('|')
            .next()
            .and_then(|addr| addr.to_socket_addrs().ok())
            .and_then(|mut addrs| addrs.next()),
        other => other.as_socket_addr().copied(),
    };

    socket_addr.map(|x| x.ip().to_string())
}

pub async fn get_client_ip(req: &Request, services: &Services) -> Option<String> {
    let client_ip_header = services
        .config
        .lock()
        .await
        .store
        .http
        .client_ip_header
        .clone();

    trusted_client_ip(req, raw_remote_ip(req), client_ip_header.as_deref())
}

pub async fn get_client_ip_addr(req: &Request, services: &Services) -> Option<IpAddr> {
    get_client_ip(req, services)
        .await
        .and_then(|ip| ip.parse().ok())
}

pub async fn span_for_request(
    req: &Request,
    services: &Services,
    handle: Option<&WarpgateServerHandle>,
) -> poem::Result<Span> {
    let client_ip = get_client_ip(req, services)
        .await
        .unwrap_or_else(|| "<unknown>".into());

    Ok(if let Some(handle) = handle {
        let ss = handle.user_session_state().lock().await;
        if let Some(ref user_info) = ss.user_info.clone() {
            info_span!("HTTP", session=%handle.user_session_id(), session_username=%user_info.username, %client_ip)
        } else {
            info_span!("HTTP", session=%handle.user_session_id(), %client_ip)
        }
    } else {
        info_span!("HTTP")
    })
}

/// The request URI for logs: a `warpgate-ticket` query value is a credential.
pub fn redacted_uri(uri: &Uri) -> String {
    let Some(query) = uri.query() else {
        return uri.to_string();
    };
    let is_ticket = |key: &str| key == "warpgate-ticket";
    if !form_urlencoded::parse(query.as_bytes()).any(|(key, _)| is_ticket(&key)) {
        return uri.to_string();
    }
    let query = form_urlencoded::Serializer::new(String::new())
        .extend_pairs(
            form_urlencoded::parse(query.as_bytes()).map(|(key, value)| {
                let value = if is_ticket(&key) {
                    Cow::Borrowed("redacted")
                } else {
                    value
                };
                (key, value)
            }),
        )
        .finish();
    format!("{}?{query}", uri.path())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticket_query_value_is_redacted() {
        let uri: Uri = "/app/x?a=1&warpgate-ticket=s3cret&b=2".parse().unwrap();
        assert_eq!(
            redacted_uri(&uri),
            "/app/x?a=1&warpgate-ticket=redacted&b=2"
        );
        let plain: Uri = "/app/x?a=1".parse().unwrap();
        assert_eq!(redacted_uri(&plain), "/app/x?a=1");
    }
}

/// An upstream address for logs. A target's URL can carry its credentials
/// (`https://user:password@host/`), so the userinfo is left out, and a ticket
/// in the query is redacted as in [`redacted_uri`].
pub fn upstream_uri_for_log(uri: &Uri) -> String {
    let Some((_, host)) = uri.authority().and_then(|a| a.as_str().rsplit_once('@')) else {
        return redacted_uri(uri);
    };
    let mut parts = uri.clone().into_parts();
    let stripped = host.parse().ok().and_then(|host| {
        parts.authority = Some(host);
        Uri::from_parts(parts).ok()
    });
    match stripped {
        Some(stripped) => redacted_uri(&stripped),
        None => "<address withheld>".to_owned(),
    }
}

pub fn log_request_result(method: &Method, url: &Uri, client_ip: Option<&str>, status: StatusCode) {
    let url = redacted_uri(url);
    let client_ip = client_ip.unwrap_or("<unknown>");
    if status.is_server_error() || status.is_client_error() {
        warn!(%method, %url, %status, %client_ip, "Request failed");
    } else {
        info!(%method, %url, %status, %client_ip, "Request");
    }
}

pub fn log_request_error(method: &Method, url: &Uri, client_ip: Option<&str>, error: &poem::Error) {
    let status = error.status();
    if !status.is_client_error() && !status.is_server_error() {
        log_request_result(method, url, client_ip, status);
        return;
    }
    let url = redacted_uri(url);
    let client_ip = client_ip.unwrap_or("<unknown>");
    error!(%method, %url, ?error, %client_ip, "Request failed");
}

#[cfg(test)]
mod log_line_tests {
    use poem::http::{Method, StatusCode, Uri};

    use super::{log_request_error, log_request_result, redacted_uri, upstream_uri_for_log};
    use crate::test_log::logged;

    const SECRET: &str = "s3cr3t-ticket-value";

    /// A request carrying a ticket in its query is logged with the ticket's
    /// value redacted, whether it succeeded, failed or errored. Each line is
    /// checked to contain the redacted address, so an empty or missing line
    /// cannot pass.
    #[test]
    fn a_logged_request_never_contains_the_ticket() {
        let uri: Uri = format!("/app?a=1&warpgate-ticket={SECRET}")
            .parse()
            .unwrap();
        let mut lines = Vec::new();
        for status in [StatusCode::OK, StatusCode::NOT_FOUND] {
            lines.push(logged(|| {
                log_request_result(&Method::GET, &uri, Some("192.0.2.1"), status);
            }));
        }
        for status in [StatusCode::FOUND, StatusCode::INTERNAL_SERVER_ERROR] {
            let error = poem::Error::from_status(status);
            lines.push(logged(|| {
                log_request_error(&Method::GET, &uri, None, &error);
            }));
        }
        for line in lines {
            assert!(line.contains("/app?a=1&warpgate-ticket=redacted"), "{line}");
            assert!(!line.contains(SECRET), "{line}");
        }
    }

    /// Kept from 1f4bb16e against upstream's `redacted_uri`: a logged address
    /// never contains a ticket's value, wherever the parameter sits, however
    /// its key is encoded and however often it appears, and still shows that
    /// a ticket was presented.
    #[test]
    fn a_logged_uri_never_contains_the_ticket() {
        for uri in [
            format!("/?warpgate-ticket={SECRET}"),
            format!("/app?a=1&warpgate-ticket={SECRET}&b=two%20words"),
            format!("https://app.example:8443/x?warpgate%2Dticket={SECRET}"),
            format!("/?warpgate-ticket={SECRET}&warpgate-ticket={SECRET}"),
        ] {
            let parsed: Uri = uri.parse().unwrap();
            let logged = redacted_uri(&parsed);
            assert!(!logged.contains(SECRET), "{uri} logged as {logged}");
            assert!(
                logged.contains("warpgate-ticket=redacted"),
                "{uri} logged as {logged}"
            );
        }
    }

    /// An address without the parameter is logged exactly as it came in.
    #[test]
    fn a_uri_without_a_ticket_is_logged_unchanged() {
        for uri in [
            "/",
            "/app?a=1&b=two%20words",
            "/app?q=warpgate-ticket",
            "/app?not-warpgate-ticket=1&warpgate-tickets=2",
            "/app?warpgate-target=app",
        ] {
            let parsed: Uri = uri.parse().unwrap();
            assert_eq!(redacted_uri(&parsed), uri);
        }
    }

    /// A target URL's credentials never reach a logged upstream address; the
    /// scheme, host, port, path and query do.
    #[test]
    fn a_logged_upstream_uri_never_contains_the_password() {
        const PASSWORD: &str = "pa55-w0rd";
        for (uri, expected) in [
            (
                format!("https://user:{PASSWORD}@app.example:8443/x?a=1"),
                "https://app.example:8443/x?a=1".to_owned(),
            ),
            (
                format!("http://{PASSWORD}@app.example/"),
                "http://app.example/".to_owned(),
            ),
            (
                format!("wss://user:{PASSWORD}@app.example/socket"),
                "wss://app.example/socket".to_owned(),
            ),
            (
                format!("https://us%40er:{PASSWORD}@app.example/"),
                "https://app.example/".to_owned(),
            ),
        ] {
            let parsed: Uri = uri.parse().unwrap();
            let logged = upstream_uri_for_log(&parsed);
            assert!(!logged.contains(PASSWORD), "{uri} logged as {logged}");
            assert_eq!(logged, expected, "{uri}");
        }
    }

    /// An upstream address without userinfo is logged as it is, ticket
    /// redaction included.
    #[test]
    fn an_upstream_uri_without_userinfo_is_logged_as_redacted_uri() {
        for uri in [
            "https://app.example:8443/x?a=1",
            "http://127.0.0.1/",
            "https://app.example/?warpgate-ticket=s3cr3t",
        ] {
            let parsed: Uri = uri.parse().unwrap();
            assert_eq!(upstream_uri_for_log(&parsed), redacted_uri(&parsed));
        }
    }
}
