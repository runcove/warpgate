use std::net::{IpAddr, ToSocketAddrs};

use poem::http::{Method, StatusCode, Uri};
use poem::web::RemoteAddr;
use poem::{Addr, Request};
use tracing::*;
use warpgate_core::{Services, WarpgateServerHandle};

use crate::request::trusted_client_ip;
use crate::ticket_query::loggable_uri;

/// The peer IP of the connection itself, ignoring any forwarding headers.
pub fn raw_remote_ip(req: &Request) -> Option<String> {
    let socket_addr = match req.remote_addr() {
        // See [CertificateExtractorEndpoint]
        RemoteAddr(Addr::Custom("captured-cert", value)) => {
            #[allow(clippy::unwrap_used)]
            let original_remote_addr = value.split('|').next().unwrap();
            original_remote_addr
                .to_socket_addrs()
                .ok()
                .and_then(|i| i.into_iter().next())
        }
        other => other.as_socket_addr().copied(),
    };

    socket_addr.map(|x| x.ip().to_string())
}

pub async fn get_client_ip(req: &Request, services: &Services) -> Option<String> {
    let (trust_x_forwarded_headers, client_ip_header) = {
        let config = services.config.lock().await;
        (
            config.store.http.trust_x_forwarded_headers,
            config.store.http.client_ip_header.clone(),
        )
    };

    trusted_client_ip(
        req,
        &services.cluster.cluster_token,
        raw_remote_ip(req),
        trust_x_forwarded_headers,
        client_ip_header.as_deref(),
    )
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

/// Logs a finished request. The address is logged with the value of any
/// `warpgate-ticket` parameter redacted: a ticket in the query is a
/// credential, and log lines outlive it and travel further than it should.
pub fn log_request_result(method: &Method, url: &Uri, client_ip: Option<&str>, status: StatusCode) {
    let url = loggable_uri(url);
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
    let url = loggable_uri(url);
    let client_ip = client_ip.unwrap_or("<unknown>");
    error!(%method, %url, ?error, %client_ip, "Request failed");
}

#[cfg(test)]
mod tests {
    use poem::http::{Method, StatusCode, Uri};

    use super::{log_request_error, log_request_result};
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
                line.contains("/app?a=1&warpgate-ticket=[REDACTED]"),
                "{line}"
            );
            assert!(!line.contains(SECRET), "{line}");
        }
    }
}
