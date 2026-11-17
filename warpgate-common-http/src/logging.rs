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

/// What replaces a query value in a logged address.
const REDACTED: &str = "redacted";

/// A pair that is not `key=value`: no `=` at all, or only base64 padding after
/// the name, so the "key" is the credential itself.
fn is_bare_token(pair: &str) -> bool {
    match pair.split_once('=') {
        None => true,
        Some((_, rest)) => !rest.is_empty() && rest.bytes().all(|b| b == b'='),
    }
}

/// The request URI for logs. Query values are credentials as often as not (a
/// ticket, an application's own access token), so every value is replaced by
/// `redacted` and only the keys are kept: `/app?a=1&b=2` is logged as
/// `/app?a=redacted&b=redacted`. A pair with no `=`, or with only base64
/// padding after the name, is replaced whole: the query of some applications
/// is a bare token. Scheme, host and path are
/// logged as they came in, and a fragment is never logged.
pub fn redacted_uri(uri: &Uri) -> String {
    let full = uri.to_string();
    let without_fragment = full.split('#').next().unwrap_or_default();
    let Some(query) = uri.query().filter(|query| !query.is_empty()) else {
        return without_fragment.to_owned();
    };
    let base = without_fragment
        .split_once('?')
        .map_or(without_fragment, |(base, _)| base);
    let query = query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            if is_bare_token(pair) {
                return REDACTED.to_owned();
            }
            form_urlencoded::parse(pair.as_bytes()).next().map_or_else(
                || REDACTED.to_owned(),
                |(key, _)| {
                    form_urlencoded::Serializer::new(String::new())
                        .append_pair(&key, REDACTED)
                        .finish()
                },
            )
        })
        .collect::<Vec<_>>()
        .join("&");
    format!("{base}?{query}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticket_query_value_is_redacted() {
        let uri: Uri = "/app/x?a=1&warpgate-ticket=s3cret&b=2".parse().unwrap();
        assert_eq!(
            redacted_uri(&uri),
            "/app/x?a=redacted&warpgate-ticket=redacted&b=redacted"
        );
        let plain: Uri = "/app/x?a=1".parse().unwrap();
        assert_eq!(redacted_uri(&plain), "/app/x?a=redacted");
    }
}

/// An upstream address for logs. A target's URL can carry its credentials
/// (`https://user:password@host/`), so the userinfo is left out, and the query
/// values are redacted as in [`redacted_uri`].
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
            assert!(
                line.contains("/app?a=redacted&warpgate-ticket=redacted"),
                "{line}"
            );
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

    /// Every query value is a possible credential, not only a ticket's: the
    /// keys are logged, the values never are.
    #[test]
    fn a_logged_uri_has_no_query_value() {
        for (uri, expected) in [
            ("/app?a=1&b=two%20words", "/app?a=redacted&b=redacted"),
            ("/ws?access_token=s3cr3t", "/ws?access_token=redacted"),
            // a key with an empty value, and the same key repeated
            ("/app?a=&b=", "/app?a=redacted&b=redacted"),
            (
                "/app?k=one&k=two&k=three",
                "/app?k=redacted&k=redacted&k=redacted",
            ),
            // percent-encoded keys are logged decoded, values never
            (
                "/app?our%20key=v&a%2Db=w",
                "/app?our+key=redacted&a-b=redacted",
            ),
            // a pair with no `=` may be a bare token: it is replaced whole
            ("/app?eyJhIjoxfQ&flag", "/app?redacted&redacted"),
            ("/app?eyJhIjoxfQ==&a=1", "/app?redacted&a=redacted"),
            // scheme, host and path are kept
            (
                "https://app.example:8443/a/b?t=s3cr3t",
                "https://app.example:8443/a/b?t=redacted",
            ),
            ("/a/b/", "/a/b/"),
        ] {
            let parsed: Uri = uri.parse().unwrap();
            assert_eq!(redacted_uri(&parsed), expected, "{uri}");
        }
    }

    /// A fragment is never logged, whether `http::Uri` keeps it in the path
    /// or in the query.
    #[test]
    fn a_logged_uri_has_no_fragment() {
        for uri in [
            "/app?a=1#frag=secret",
            "/app#frag=secret",
            "/app?#frag=secret",
        ] {
            let parsed: Uri = uri.parse().unwrap();
            let logged = redacted_uri(&parsed);
            assert!(!logged.contains("frag"), "{uri} logged as {logged}");
            assert!(!logged.contains("secret"), "{uri} logged as {logged}");
            assert!(!logged.contains('#'), "{uri} logged as {logged}");
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
                "https://app.example:8443/x?a=redacted".to_owned(),
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
