use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use futures::{StreamExt, TryStreamExt};
use poem::web::Data;
use poem::web::websocket::{WebSocket, WebSocketStream};
use poem::{Body, IntoResponse, Request, Response, handler};
use reqwest_websocket::Upgrade;
use serde::Deserialize;
use tokio::sync::{Mutex, mpsc};
use tokio_tungstenite::tungstenite;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, error, warn};
use url::Url;
use warpgate_common::helpers::websocket::pump_websocket;
use warpgate_common::http_headers::ForwardFilter;
use warpgate_common::{TargetKubernetesOptions, TargetSessionId, WarpgateError};
use warpgate_common_http::auth::UnauthenticatedRequestContext;
use warpgate_common_http::logging::{
    get_client_ip, log_request_error, log_request_result, span_for_request, upstream_uri_for_log,
};
use warpgate_core::logging::KubernetesAuditSubject;
use warpgate_core::recordings::{
    RecordingOwner, SessionRecordings, TerminalRecorder, TerminalRecordingStreamId,
};
use warpgate_core::{Services, WarpgateServerHandle};

use crate::audit::{StreamOperation, classify_mutating, classify_stream};
use crate::correlator::{AdmittedSession, RequestCorrelator, correlated_authorization};
use crate::recording::{
    KubernetesRecorder, SessionRecordingMetadata, start_recording_api, start_recording_exec,
};
use crate::server::UpstreamClientCache;
use crate::server::auth::{
    KubernetesIdentity, authenticate_kubernetes_user, create_authenticated_client, unauthorized,
    url_for_log,
};

/// A client-supplied impersonation header (`Impersonate-User`,
/// `Impersonate-Group`, `Impersonate-Uid`, `Impersonate-Extra-*`). These let a
/// caller assume another identity on the cluster and must never be forwarded,
/// recorded, or logged.
fn is_impersonation_header(name: &str) -> bool {
    name.to_ascii_lowercase().starts_with("impersonate-")
}

/// Request-header filter for the Kubernetes API: the shared forwarding rules
/// (hop-by-hop, `Connection`-listed and framing headers are dropped), except
/// that `Accept-Encoding` is kept.
fn should_forward_to_cluster(filter: &ForwardFilter, name: &http::HeaderName) -> bool {
    name == http::header::ACCEPT_ENCODING || filter.allows(name)
}

/// Headers whose values are secrets or identity-spoofing vectors and so must
/// never be written to a recording or a log line.
fn is_sensitive_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == "authorization" || lower == "cookie" || is_impersonation_header(&lower)
}

/// Copy of `headers` with sensitive entries removed, for recording and logging.
fn redact_headers(headers: &HashMap<String, String>) -> HashMap<String, String> {
    headers
        .iter()
        .filter(|(name, _)| !is_sensitive_header(name))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Whether a pump failure only means a peer had already gone: a client killed
/// mid-stream drops its TCP connection without a websocket close (how a
/// `kubectl port-forward` ordinarily ends), and the close handshake itself can
/// leave one direction writing into the socket the other has just closed.
/// Neither is an error an operator needs to see.
///
/// `tungstenite`'s `AlreadyClosed` / `ConnectionClosed` are matched on text:
/// poem stringifies them into `io::Error::other` on the server side, and the
/// client side's `tungstenite` is a different version from the one this crate
/// links, so a `downcast_ref` would never match either.
fn is_peer_gone(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        if let Some(io_error) = cause.downcast_ref::<std::io::Error>() {
            return matches!(
                io_error.kind(),
                std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    // rustls reports a peer that vanished without a TLS
                    // close_notify as an unexpected EOF.
                    | std::io::ErrorKind::UnexpectedEof
            );
        }
        let text = cause.to_string();
        text.contains("Trying to work with closed connection")
            || text.contains("Connection closed normally")
    })
}

fn construct_target_url(
    req: &Request,
    api_path: &str,
    k8s_options: &TargetKubernetesOptions,
) -> Result<Url> {
    let query = req.uri().query().unwrap_or("");

    Ok(Url::parse(&if query.is_empty() {
        format!("{}{}", k8s_options.cluster_url, api_path)
    } else {
        format!("{}{}?{}", k8s_options.cluster_url, api_path, query)
    })?)
}

#[handler]
#[allow(clippy::too_many_arguments)]
pub async fn handle_api_request(
    ws: Option<WebSocket>,
    req: &Request,
    body: Body,
    correlator: Data<&Arc<Mutex<RequestCorrelator>>>,
    upstream_clients: Data<&UpstreamClientCache>,
    ctx: Data<&UnauthenticatedRequestContext>,
) -> Result<Response, poem::Error> {
    debug!(
        full_uri = %upstream_uri_for_log(req.uri()),
        "Handling Kubernetes API request"
    );

    // Authenticate the transport credential on every request (cheap; also enforces
    // account status). Authorization — the credential policy / web approval — is
    // resolved once per correlated session and reused, so a single `kubectl`
    // command's fan-out of requests only prompts for approval once.
    let identity = authenticate_kubernetes_user(req, ctx.services()).await?;
    let (target_name, path) = match &identity {
        // Ticket credentials select the target; the entire URI belongs to the
        // upstream API, including discovery endpoints such as /api and /version.
        KubernetesIdentity::Ticket(ticket) => (
            ticket.target().name.clone(),
            req.uri().path().trim_start_matches('/').to_owned(),
        ),
        KubernetesIdentity::User { .. } => named_target_path(req.uri().path())?,
    };

    // The path exactly as the API server will see it. The url crate resolves
    // `.` and `..` segments, so a request cannot name one pod to the audit
    // classifier and another to the cluster; the classifiers and the upstream
    // URL are all built from this one value.
    let api_path = Url::parse(&format!("http://localhost/{path}"))
        .map_err(poem::error::BadRequest)?
        .path()
        .to_owned();

    let (handle, admitted, closed) =
        correlated_authorization(correlator.0, req, identity, &target_name, ctx.services()).await?;
    // Close may have arrived after the correlator lookup.
    if closed.is_cancelled() {
        return Err(unauthorized());
    }

    let (user_session_id, log_span) = {
        // The user info is already on the session: it is set when the session is
        // registered, before its authorization is resolved.
        let handle = handle.lock().await;
        (
            handle.user_session_id(),
            span_for_request(req, ctx.services(), Some(&*handle)).await?,
        )
    };

    // Built once per request and handed to both branches, so every Kubernetes
    // audit event names the same actor, session and target. The *user* session
    // id is the one the log layer keys entries by — recordings key off the
    // target session id instead, and the two must not be confused.
    let audit_subject = {
        let target = admitted.target();
        KubernetesAuditSubject {
            session_id: user_session_id.0,
            user_id: admitted.user_info().id,
            username: admitted.user_info().username.clone(),
            target_id: target.id,
            target_name: target.name.clone(),
        }
    };

    async {
        let response = if let Some(ws) = ws {
            _handle_websocket_request_inner(
                ws,
                req,
                admitted,
                &api_path,
                &audit_subject,
                ctx.services(),
                closed.clone(),
                handle.clone(),
            )
            .await
            .map(IntoResponse::into_response)
            .map_err(poem::Error::from)
        } else {
            // Not `.context(...)`: that converts the `WarpgateError` to an
            // `anyhow::Error`, which poem renders through `Display` instead
            // of `as_response()`.
            _handle_normal_request_inner(
                req,
                body,
                admitted,
                upstream_clients.0,
                &api_path,
                &audit_subject,
                ctx.services(),
                closed,
                handle.clone(),
            )
            .await
            .map(IntoResponse::into_response)
            .map_err(|error| match error {
                // Closed mid-request: the caller is no longer authorized.
                WarpgateError::UserSessionEnded => unauthorized(),
                error => poem::Error::from(error),
            })
        };

        let client_ip = get_client_ip(req, ctx.services()).await;
        let response = response.inspect_err(|e| {
            log_request_error(req.method(), req.original_uri(), client_ip.as_deref(), e);
        })?;

        log_request_result(
            req.method(),
            req.original_uri(),
            client_ip.as_deref(),
            response.status(),
        );

        Ok(response)
    }
    .instrument(log_span)
    .await
}

/// Normal credentials retain the /<target>/<api-path> route. Decode only the
/// target selector; upstream paths must keep their original escaping.
fn named_target_path(path: &str) -> poem::Result<(String, String)> {
    let (target, path) = path
        .strip_prefix('/')
        .and_then(|p| p.split_once('/'))
        .filter(|(target, _)| !target.is_empty())
        .ok_or_else(|| poem::Error::from_status(poem::http::StatusCode::NOT_FOUND))?;
    let target = percent_encoding::percent_decode_str(target)
        .decode_utf8()
        .map_err(|_| poem::Error::from_status(poem::http::StatusCode::BAD_REQUEST))?;
    Ok((target.into_owned(), path.to_owned()))
}

/// Ends `upstream` with an error once the session closes, so the client sees a
/// truncated body rather than a clean end. Holds the session handle so the
/// session stays open for as long as the stream does, even past its correlator
/// entry.
fn end_on_close<S>(
    upstream: S,
    closed: CancellationToken,
    handle: Arc<Mutex<WarpgateServerHandle>>,
) -> impl futures::Stream<Item = std::io::Result<bytes::Bytes>> + Send + 'static
where
    S: futures::Stream<Item = std::io::Result<bytes::Bytes>> + Unpin + Send + 'static,
{
    futures::stream::unfold(Some((upstream, closed, handle)), |state| async move {
        let (mut upstream, closed, handle) = state?;
        // Close first: a stream that is always ready must not starve it.
        tokio::select! {
            biased;
            () = closed.cancelled() => Some((
                Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "session closed",
                )),
                None,
            )),
            item = upstream.next() => {
                item.map(|item| (item, Some((upstream, closed, handle))))
            }
        }
    })
}

#[allow(clippy::too_many_arguments)]
async fn _handle_normal_request_inner(
    req: &Request,
    body: Body,
    admitted: AdmittedSession,
    upstream_clients: &UpstreamClientCache,
    api_path: &str,
    audit_subject: &KubernetesAuditSubject,
    services: &Services,
    closed: CancellationToken,
    handle: Arc<Mutex<WarpgateServerHandle>>,
) -> Result<Response, WarpgateError> {
    let k8s_options = admitted.options();
    let target_id = admitted.target().id;
    let client = upstream_clients
        .get_or_build(&target_id, k8s_options, || async {
            create_authenticated_client(k8s_options, services)
                .await?
                .build()
                .context("building reqwest client")
        })
        .await?;

    debug!(
        "Target Kubernetes options: cluster_url={}, auth={:?}",
        url_for_log(&k8s_options.cluster_url),
        match &k8s_options.auth {
            warpgate_common::KubernetesTargetAuth::Token(_) => "Token",
            warpgate_common::KubernetesTargetAuth::Certificate(_) => "Certificate",
            warpgate_common::KubernetesTargetAuth::IamRole(_) => "IamRole",
        }
    );

    let method = req.method().as_str();
    // Construct the full URL to the Kubernetes API server (without target prefix)
    let full_url =
        construct_target_url(req, api_path, k8s_options).context("constructing target URL")?;

    // Extract headers
    let mut headers = HashMap::new();
    let filter = ForwardFilter::new(req.headers());
    for (name, value) in req.headers() {
        // Client-supplied impersonation must never reach the cluster (nor be
        // recorded or logged), so drop it at the point of ingestion.
        if is_impersonation_header(name.as_str()) {
            continue;
        }
        // Still forward Accept-Encoding to allow for chunked encoding
        if !should_forward_to_cluster(&filter, name) {
            continue;
        }
        if let Ok(mut value_str) = value.to_str().map(ToString::to_string) {
            if name == http::header::ACCEPT {
                let values = value
                    .to_str()
                    .unwrap_or_default()
                    .split(',')
                    .map(str::trim)
                    .filter(|s| *s != "application/vnd.kubernetes.protobuf") // cannot parse protobuf yet
                    .collect::<Vec<_>>();
                value_str = values.join(", ");
            }
            headers.insert(name.to_string(), value_str.clone());
        }
    }

    // Bearer tokens and cookies must not be persisted to a recording or emitted
    // to a log line; this redacted view is used for both.
    let redacted_headers = redact_headers(&headers);

    // Cancel slow uploads when the session closes.
    let body_bytes = closed
        .run_until_cancelled(body.into_bytes())
        .await
        .ok_or(WarpgateError::UserSessionEnded)?
        .context("reading request body")?;

    let recorder_opt = start_api_recording(
        &recording_owner(audit_subject),
        &admitted.id(),
        &services.recordings,
    )
    .await?;

    // Forward request to Kubernetes API
    let mut request_builder = client.request(
        http::Method::from_bytes(method.as_bytes()).context("request method")?,
        full_url.clone(),
    );

    // Add headers (excluding authorization, host, and content-length as they'll be set by reqwest)
    let mut upstream_headers = HashMap::new();
    for (name, value) in &headers {
        let header_name_lower = name.to_lowercase();
        if [
            "host",
            "content-length",
            "connection",
            "transfer-encoding",
            "authorization",
        ]
        .contains(&header_name_lower.as_str())
        {
            debug!(header = name, "Filtering out header from upstream request");
        } else if let (Ok(header_name), Ok(header_value)) = (
            http::HeaderName::from_bytes(name.as_bytes()),
            http::HeaderValue::from_str(value),
        ) {
            request_builder = request_builder.header(header_name, header_value);
            upstream_headers.insert(name.clone(), value.clone());
        }
    }

    debug!(
        filtered_headers = ?redact_headers(&upstream_headers),
        "Headers being sent to upstream Kubernetes API"
    );

    if !body_bytes.is_empty() {
        request_builder = request_builder.body(body_bytes.to_vec());
    }

    // Debug logging for upstream request
    debug!(
        method = method,
        url = %url_for_log(full_url.as_str()),
        headers = ?redacted_headers,
        body_size = body_bytes.len(),
        "Sending request to upstream Kubernetes API"
    );

    // A write that reached the cluster runs to completion across a close, so
    // the client learns whether it was applied and an audited one keeps its
    // event. A close before dispatch still refuses it.
    let is_write = !req.method().is_safe();
    let response = if is_write {
        if closed.is_cancelled() {
            return Err(WarpgateError::UserSessionEnded);
        }
        request_builder.send().await?
    } else {
        closed
            .run_until_cancelled(request_builder.send())
            .await
            .ok_or(WarpgateError::UserSessionEnded)??
    };

    let status = response.status();
    let response_headers = response.headers().clone();

    // The cached client's credential may have been rotated or expired upstream;
    // build a fresh one for the next request.
    if status == http::StatusCode::UNAUTHORIZED {
        upstream_clients.remove(&target_id);
    }

    // Emitted after the response so a refused `kubectl debug` is audited as
    // clearly as an accepted one, and before the body is consumed so a failure
    // to read it cannot lose the event.
    if let Some(operation) = classify_mutating(method, api_path, req.uri().query(), &body_bytes) {
        for event in operation.audit_events(audit_subject, status.as_u16()) {
            event.emit();
        }
    }

    debug!(
        method = method,
        url = %url_for_log(full_url.as_str()),
        status = %status,
        response_headers = ?response_headers,
        "Received response from upstream Kubernetes API"
    );

    let (response_body, body_for_recording) = {
        // k8s uses streaming chunked responses for watch API
        let transfer_encoding = response_headers
            .get(poem::http::header::TRANSFER_ENCODING)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_lowercase();

        let query_pairs: Vec<_> = req
            .uri()
            .query()
            .map(|q| url::form_urlencoded::parse(q.as_bytes()).collect())
            .unwrap_or_default();

        // watch: used by kubectl to await changes
        // follow: used by kubectl logs
        let is_streaming_response = query_pairs
            .iter()
            .any(|(k, v)| (k == "watch" || k == "follow") && crate::audit::parse_bool(v));

        // A write's response is always read in full, even if it is framed as
        // chunked, so a close can't cut off its answer.
        if !is_write && (transfer_encoding == "chunked" || is_streaming_response) {
            let upstream = response
                .bytes_stream()
                .map_err(|error| std::io::Error::other(error.without_url()));
            (
                Body::from_bytes_stream(end_on_close(upstream, closed, handle)),
                None,
            )
        } else {
            let bytes = if is_write {
                response.bytes().await
            } else {
                closed
                    .run_until_cancelled(response.bytes())
                    .await
                    .ok_or(WarpgateError::UserSessionEnded)?
            }
            .map_err(reqwest::Error::without_url)
            .context("reading kubernetes response")?;

            (Body::from_bytes(bytes.clone()), Some(bytes.to_vec()))
        }
    };

    if let Some(recorder) = &recorder_opt {
        record_api_response(
            recorder,
            method,
            full_url.as_ref(),
            redacted_headers,
            &body_bytes,
            status.as_u16(),
            body_for_recording.unwrap_or_default().as_ref(),
        )
        .await;
    }

    let mut poem_response = Response::builder().status(status).body(response_body);
    copy_upstream_response_headers(&response_headers, poem_response.headers_mut());

    Ok(poem_response)
}

/// Copies the upstream response's headers onto the response sent to the
/// client, leaving out those the shared forwarding rules drop (hop-by-hop
/// headers, and framing headers the body is re-framed without).
fn copy_upstream_response_headers(src: &http::HeaderMap, dst: &mut poem::http::HeaderMap) {
    let filter = ForwardFilter::new(src);
    for (name, value) in src {
        if !filter.allows(name) {
            continue;
        }
        if let Ok(poem_name) = poem::http::HeaderName::from_bytes(name.as_str().as_bytes())
            && let Ok(poem_value) = poem::http::HeaderValue::from_bytes(value.as_bytes())
        {
            dst.append(poem_name, poem_value);
        }
    }
}

/// Records an API request and its response. A failure is logged and counted once,
/// and the response still goes out, even when unrecorded sessions are refused: the
/// request has already reached the cluster, and failing it would hide whether it was
/// applied. The next request starts a fresh recording, and is refused if that fails.
async fn record_api_response(
    recorder: &KubernetesRecorder,
    method: &str,
    path: &str,
    headers: HashMap<String, String>,
    request_body: &[u8],
    status: u16,
    response_body: &[u8],
) {
    if let Err(e) = recorder
        .record_response(method, path, headers, request_body, status, response_body)
        .await
    {
        recorder.write_failed(&e);
    }
}

/// Records an exec / attach stream. On a failed write the recording is reported
/// once and stops; when unrecorded sessions are refused, `recording_failed` is
/// cancelled, which ends the stream.
async fn run_websocket_recording(
    recorder: TerminalRecorder,
    mut rx: mpsc::Receiver<Vec<u8>>,
    recording_failed: CancellationToken,
) {
    while let Some(data) = rx.recv().await {
        if data.is_empty() {
            continue;
        }
        #[allow(clippy::indexing_slicing, reason = "length checked")]
        let msg_type = data[0];
        #[allow(clippy::indexing_slicing, reason = "length checked")]
        let data = data[1..].to_vec();

        let result = match msg_type {
            // stdin, stdout, stderr
            0..=2 => {
                recorder
                    .write(
                        TerminalRecordingStreamId::from_usual_fd_number(msg_type)
                            .unwrap_or_default(),
                        &data,
                    )
                    .await
            }
            4 => {
                #[derive(Deserialize)]
                struct ResizeData {
                    #[serde(rename = "Width")]
                    width: u32,
                    #[serde(rename = "Height")]
                    height: u32,
                }
                if let Ok(resize_data) = serde_json::from_slice::<ResizeData>(&data) {
                    recorder
                        .write_pty_resize(resize_data.width, resize_data.height)
                        .await
                } else {
                    continue;
                }
            }
            _ => continue,
        };
        if let Err(e) = result {
            if recorder.write_failed(&e) {
                recording_failed.cancel();
            }
            return;
        }
    }
}

/// The user and target named on a failed recording's log line.
fn recording_owner(subject: &KubernetesAuditSubject) -> RecordingOwner {
    RecordingOwner {
        protocol: "kubernetes",
        user: subject.username.clone(),
        target: subject.target_name.clone(),
    }
}

/// Start an API request's recording, before the request is forwarded. `Ok(None)` when
/// recording is disabled. A failure to start is logged (by `start_for`); it is then
/// [`WarpgateError::SessionNotRecorded`] when unrecorded sessions are refused, and
/// `Ok(None)` otherwise (the default).
async fn start_api_recording(
    owner: &RecordingOwner,
    target_session_id: &TargetSessionId,
    recordings: &SessionRecordings,
) -> Result<Option<KubernetesRecorder>, WarpgateError> {
    match start_recording_api(owner, target_session_id, recordings).await {
        Ok(recorder) => Ok(recorder),
        Err(_) => {
            if recordings.refuses_unrecorded_sessions() {
                return Err(WarpgateError::SessionNotRecorded);
            }
            Ok(None)
        }
    }
}

/// Start an exec or attach stream's recording, before the stream opens. As
/// [`start_api_recording`].
async fn start_stream_recording(
    owner: &RecordingOwner,
    target_session_id: &TargetSessionId,
    recordings: &SessionRecordings,
    metadata: SessionRecordingMetadata,
) -> Result<Option<TerminalRecorder>, WarpgateError> {
    match start_recording_exec(owner, target_session_id, recordings, metadata).await {
        Ok(recorder) => Ok(recorder),
        Err(_) => {
            if recordings.refuses_unrecorded_sessions() {
                return Err(WarpgateError::SessionNotRecorded);
            }
            Ok(None)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn _handle_websocket_request_inner(
    ws: WebSocket,
    req: &Request,
    admitted: AdmittedSession,
    api_path: &str,
    audit_subject: &KubernetesAuditSubject,
    services: &Services,
    closed: CancellationToken,
    handle: Arc<Mutex<WarpgateServerHandle>>,
) -> anyhow::Result<impl IntoResponse> {
    let k8s_options = admitted.options();
    let mut full_url = construct_target_url(req, api_path, k8s_options)?;
    if full_url.scheme() == "https" {
        let _ = full_url.set_scheme("wss");
    } else {
        let _ = full_url.set_scheme("ws");
    }

    let client = create_authenticated_client(k8s_options, services)
        .await?
        .http1_only()
        .build()?;

    // Classified independently of recording: an audit trail must not depend on
    // whether session recording happens to be switched on.
    let operation = classify_stream(api_path, req.uri().query());

    let (recorder_tx, recorder_rx) = mpsc::channel::<Vec<u8>>(1000);
    // Cancelled when the recording fails and unrecorded sessions are refused: the
    // stream then ends like a session close.
    let recording_failed = closed.child_token();
    if let Some(metadata) = operation
        .as_ref()
        .and_then(StreamOperation::recording_metadata)
        && let Some(recorder) = start_stream_recording(
            &recording_owner(audit_subject),
            &admitted.id(),
            &services.recordings,
            metadata,
        )
        .await?
    {
        tokio::spawn(run_websocket_recording(
            recorder,
            recorder_rx,
            recording_failed.clone(),
        ));
    }

    let ws_protocol = req
        .headers()
        .get("sec-websocket-protocol")
        .and_then(|h| h.to_str().ok())
        .context("missing Sec-Websocket-Protocol request header")?
        .to_string();

    let audit_subject = audit_subject.clone();

    let ws_handler_inner = async move |socket: WebSocketStream| {
        // Keep the session handle alive if the websocket outlives its cache entry.
        let _session_handle = handle;
        let client_response = closed
            .run_until_cancelled(
                client
                    .get(full_url.clone())
                    .upgrade()
                    .protocols(vec![ws_protocol])
                    .send(),
            )
            .await
            .context("Session closed while upgrading the Kubernetes websocket")?
            .map_err(websocket_error_without_url)
            .context("sending websocket request to Kubernetes API")?;

        let status = client_response.status();
        let established = status == http::StatusCode::SWITCHING_PROTOCOLS;
        // Audited on the cluster's verdict, so a stream it refused (most often
        // RBAC) and one it opened are told apart, and a stream that never
        // reached it is not recorded as having started.
        if let Some(operation) = &operation {
            if established {
                operation.audit_event(&audit_subject).emit();
            } else {
                operation
                    .rejection_event(&audit_subject, status.as_u16())
                    .emit();
            }
        }
        if !established {
            let client_response = client_response.into_inner();
            let body = closed
                .run_until_cancelled(client_response.text())
                .await
                .context("Session closed while reading Kubernetes API rejection response")?
                .map_err(reqwest::Error::without_url)?;
            bail!("Unexpected websocket response status from Kubernetes API: {status}: {body}");
        }

        let client_socket = closed
            .run_until_cancelled(client_response.into_websocket())
            .await
            .context("Session closed while negotiating the Kubernetes websocket")?
            .map_err(websocket_error_without_url)
            .context("negotiating websocket connection with Kubernetes")?;

        let (client_sink, client_source) = client_socket.split();
        let (server_sink, server_source) = socket.split();

        let server_to_client = {
            let recorder_tx = recorder_tx.clone();
            let recording_failed = recording_failed.clone();
            pump_websocket(
                server_source,
                client_sink,
                move |msg| {
                    let recorder_tx = recorder_tx.clone();
                    let recording_failed = recording_failed.clone();
                    async move {
                        tracing::debug!("Server: {:?}", msg);
                        if recording_failed.is_cancelled() {
                            return Err(WarpgateError::SessionRecordingFailed.into());
                        }
                        if let tungstenite::Message::Binary(data) = &msg {
                            let _ = recorder_tx.send(data.to_vec()).await;
                        }
                        anyhow::Ok(msg)
                    }
                },
                "k8s_browser_to_backend",
            )
        };

        let client_to_server = {
            let recording_failed = recording_failed.clone();
            pump_websocket(
                client_source,
                server_sink,
                move |msg| {
                    let recorder_tx = recorder_tx.clone();
                    let recording_failed = recording_failed.clone();
                    async move {
                        tracing::debug!("Client: {:?}", msg);
                        if recording_failed.is_cancelled() {
                            return Err(WarpgateError::SessionRecordingFailed.into());
                        }
                        if let tungstenite::Message::Binary(data) = &msg {
                            let _ = recorder_tx.send(data.to_vec()).await;
                        }
                        anyhow::Ok(msg)
                    }
                },
                "k8s_backend_to_browser",
            )
        };

        // Whichever direction ends first takes the stream down; the other is
        // dropped rather than left to fail writing into the closed socket. A
        // session close (admin close, or a user's deletion) takes the stream
        // down the same way, so a long-lived `exec`/`attach`/`port-forward`
        // cannot outlive the access that opened it.
        let result = tokio::select! {
            biased;
            () = closed.cancelled() => Ok(()),
            () = recording_failed.cancelled() => {
                warn!("Closing the Kubernetes stream: its recording failed");
                Ok(())
            }
            result = server_to_client => result,
            result = client_to_server => result,
        };
        match result {
            Err(error) if is_peer_gone(&error) => debug!("Websocket peer gone: {error:#}"),
            result => result?,
        }
        debug!("Closing Websocket stream");
        Ok::<(), anyhow::Error>(())
    };

    // poem drives the upgraded stream after this handler has returned, so the
    // request span is carried over explicitly; the database log layer keeps
    // only events that fall under a session span.
    let span = tracing::Span::current();

    Ok(ws
        .protocols(vec![
            "channel.k8s.io",
            "v2.channel.k8s.io",
            "v3.channel.k8s.io",
            "v4.channel.k8s.io",
            "v5.channel.k8s.io",
            "SPDY/3.1+portforward.k8s.io",
        ])
        .on_upgrade(move |socket| {
            async move {
                if let Err(error) = ws_handler_inner(socket).await {
                    error!("Websocket handling error: {error:?}");
                }
            }
            .instrument(span)
        })
        .into_response())
}

/// A WebSocket error from the cluster, without the URL a reqwest error inside
/// it would carry into the log: its query can hold a caller's values (an exec
/// command, for one).
fn websocket_error_without_url(error: reqwest_websocket::Error) -> reqwest_websocket::Error {
    match error {
        reqwest_websocket::Error::Reqwest(error) => {
            reqwest_websocket::Error::Reqwest(error.without_url())
        }
        error => error,
    }
}

#[cfg(test)]
mod websocket_error_tests {
    use super::websocket_error_without_url;

    /// A failed WebSocket request to the cluster is logged as `{error:?}` of
    /// an `anyhow` chain; no link of it names the URL, whose query carries
    /// the exec command.
    #[tokio::test]
    async fn a_websocket_error_is_logged_without_its_url() {
        const SENTINEL: &str = "cmd-sentinel-41fa";
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let error = reqwest::Client::new()
            .get(format!("http://127.0.0.1:{port}/exec?command={SENTINEL}"))
            .send()
            .await
            .unwrap_err();
        // The fixture carries the value, or the test would prove nothing.
        assert!(format!("{error:?}").contains(SENTINEL));
        let error = websocket_error_without_url(reqwest_websocket::Error::from(error));
        let logged = format!(
            "{:?}",
            anyhow::Error::from(error).context("sending websocket request")
        );
        assert!(logged.contains("reqwest error"), "{logged}");
        assert!(!logged.contains(SENTINEL), "{logged}");
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{
        ForwardFilter, copy_upstream_response_headers, is_impersonation_header, named_target_path,
        redact_headers, should_forward_to_cluster,
    };

    #[test]
    fn cluster_headers_follow_the_shared_forwarding_rules() {
        let mut headers = http::HeaderMap::new();
        headers.append(http::header::CONNECTION, "close, X-Hop".parse().unwrap());
        headers.append("x-hop", "1".parse().unwrap());
        headers.append("x-keep", "1".parse().unwrap());
        headers.append(http::header::ACCEPT_ENCODING, "gzip".parse().unwrap());
        headers.append(http::header::TRANSFER_ENCODING, "chunked".parse().unwrap());
        headers.append(http::header::CONTENT_LENGTH, "5".parse().unwrap());
        let filter = ForwardFilter::new(&headers);
        let forwarded = |name: &str| {
            should_forward_to_cluster(
                &filter,
                &http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            )
        };
        assert!(!forwarded("x-hop"));
        assert!(!forwarded("connection"));
        assert!(!forwarded("transfer-encoding"));
        assert!(!forwarded("content-length"));
        assert!(forwarded("x-keep"));
        assert!(forwarded("accept-encoding"));
    }

    #[test]
    fn upstream_response_headers_follow_the_shared_forwarding_rules() {
        let mut headers = http::HeaderMap::new();
        headers.append(http::header::CONNECTION, "close, X-Hop".parse().unwrap());
        headers.append("x-hop", "1".parse().unwrap());
        headers.append("x-keep", "1".parse().unwrap());
        headers.append("x-keep", "2".parse().unwrap());
        headers.append(
            http::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );
        headers.append(http::header::TRANSFER_ENCODING, "chunked".parse().unwrap());
        headers.append(http::header::CONTENT_LENGTH, "5".parse().unwrap());
        let mut copied = poem::http::HeaderMap::new();
        copy_upstream_response_headers(&headers, &mut copied);
        let mut names: Vec<&str> = copied.keys().map(|n| n.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, ["content-type", "x-keep"]);
        assert_eq!(copied.get_all("x-keep").iter().count(), 2);
    }

    #[test]
    fn named_routes_decode_only_the_target_selector() {
        assert_eq!(
            named_target_path("/my%20cluster/api/v1/namespaces/default/pods/a%2Fb").unwrap(),
            (
                "my cluster".into(),
                "api/v1/namespaces/default/pods/a%2Fb".into()
            ),
        );
        assert!(named_target_path("/api").is_err());
        assert!(named_target_path("/").is_err());
        assert!(named_target_path("//api").is_err());
    }

    #[test]
    fn normal_stream_teardown_is_not_an_error() {
        // One direction closes, the other fails writing into it.
        let closed =
            anyhow::anyhow!("Trying to work with closed connection").context("tungstenite error");
        assert!(super::is_peer_gone(&closed));

        for kind in [
            std::io::ErrorKind::BrokenPipe,
            // A killed client: the TLS session ends without a close_notify.
            std::io::ErrorKind::UnexpectedEof,
        ] {
            let error = anyhow::Error::new(std::io::Error::new(kind, "peer gone"));
            assert!(super::is_peer_gone(&error), "{kind:?}");
        }
    }

    #[test]
    fn real_stream_failures_are_still_errors() {
        let refused = anyhow::Error::new(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "no route",
        ));
        assert!(!super::is_peer_gone(&refused));
        assert!(!super::is_peer_gone(&anyhow::anyhow!(
            "stream error: protocol violation"
        )));
    }

    #[test]
    fn impersonation_detection_is_case_insensitive() {
        assert!(is_impersonation_header("Impersonate-User"));
        assert!(is_impersonation_header("impersonate-group"));
        assert!(is_impersonation_header("Impersonate-Uid"));
        assert!(is_impersonation_header("IMPERSONATE-Extra-scopes"));
        assert!(!is_impersonation_header("authorization"));
        assert!(!is_impersonation_header("accept"));
    }

    #[test]
    fn redact_drops_secrets_and_impersonation() {
        let mut headers = HashMap::new();
        headers.insert("Authorization".into(), "Bearer secret".into());
        headers.insert("Cookie".into(), "session=1".into());
        headers.insert("Impersonate-User".into(), "root".into());
        headers.insert("Impersonate-Group".into(), "system:masters".into());
        headers.insert("Accept".into(), "application/json".into());

        let redacted = redact_headers(&headers);

        assert_eq!(redacted.len(), 1);
        assert!(redacted.contains_key("Accept"));
        assert!(!redacted.contains_key("Authorization"));
        assert!(!redacted.contains_key("Cookie"));
        assert!(!redacted.keys().any(|k| is_impersonation_header(k)));
    }

    /// A recording whose start fails for real: recordings on,
    /// `--recordings-keep-group-read` with files secured, and the session's directory
    /// under the recordings root a symlink, which the start refuses to follow.
    mod unrecorded {
        use sea_orm::ActiveValue::Set;
        use sea_orm::{ActiveModelTrait, Database, IntoActiveModel};
        use uuid::Uuid;
        use warpgate_common::{GlobalParams, TargetSessionId, WarpgateError};
        use warpgate_core::recordings::{RecordingOwner, SessionRecordings};
        use warpgate_db_entities::Parameters::{
            self, ConfigMigrationValues, RecordingsDiskConfig, RecordingsStorageConfig,
            set_config_migration_values,
        };
        use warpgate_db_migrations::migrate_database;

        use super::super::{SessionRecordingMetadata, start_api_recording, start_stream_recording};

        struct Failing {
            recordings: SessionRecordings,
            id: TargetSessionId,
            _dir: tempfile::TempDir,
        }

        async fn failing(refuse: bool) -> Failing {
            let dir = tempfile::tempdir().unwrap();
            let id = TargetSessionId(Uuid::new_v4());
            set_config_migration_values(ConfigMigrationValues::default());
            let db = Database::connect("sqlite::memory:").await.unwrap();
            migrate_database(&db).await.unwrap();
            let root = dir.path().join("recordings");
            std::fs::create_dir_all(&root).unwrap();
            std::fs::create_dir_all(dir.path().join("elsewhere")).unwrap();
            std::os::unix::fs::symlink(dir.path().join("elsewhere"), root.join(id.to_string()))
                .unwrap();
            let mut parameters = Parameters::Entity::get(&db)
                .await
                .unwrap()
                .into_active_model();
            parameters.recordings_enable = Set(true);
            parameters.recordings_storage = Set(serde_json::to_string(
                &RecordingsStorageConfig::Disk(RecordingsDiskConfig {
                    path: "recordings".into(),
                }),
            )
            .unwrap());
            parameters.update(&db).await.unwrap();
            let params = GlobalParams::new(dir.path().join("warpgate.yaml"), true)
                .unwrap()
                .with_recordings_keep_group_read(true)
                .with_refuse_unrecorded_sessions(refuse);
            Failing {
                recordings: SessionRecordings::new(db, &params),
                id,
                _dir: dir,
            }
        }

        fn owner() -> RecordingOwner {
            RecordingOwner {
                protocol: "kubernetes",
                user: "alice".into(),
                target: "cluster".into(),
            }
        }

        fn exec() -> SessionRecordingMetadata {
            SessionRecordingMetadata::Exec {
                namespace: "default".into(),
                pod: "pod".into(),
                container: None,
                command: vec!["sh".into()],
            }
        }

        #[tokio::test]
        async fn an_api_request_whose_recording_fails_is_refused_when_required() {
            let f = failing(true).await;
            assert!(matches!(
                start_api_recording(&owner(), &f.id, &f.recordings).await,
                Err(WarpgateError::SessionNotRecorded)
            ));
        }

        #[tokio::test]
        async fn an_exec_stream_whose_recording_fails_is_refused_when_required() {
            let f = failing(true).await;
            assert!(matches!(
                start_stream_recording(&owner(), &f.id, &f.recordings, exec()).await,
                Err(WarpgateError::SessionNotRecorded)
            ));
        }

        #[tokio::test]
        async fn with_refusal_off_api_and_exec_continue_unrecorded() {
            let f = failing(false).await;
            assert!(matches!(
                start_api_recording(&owner(), &f.id, &f.recordings).await,
                Ok(None)
            ));
            assert!(matches!(
                start_stream_recording(&owner(), &f.id, &f.recordings, exec()).await,
                Ok(None)
            ));
        }
    }

    /// Recordings that start on a real disk root, then fail mid-session as a full
    /// disk would.
    mod failing_mid_session {
        use std::collections::HashMap;
        use std::path::PathBuf;
        use std::time::Duration;

        use sea_orm::ActiveValue::Set;
        use sea_orm::{ActiveModelTrait, Database, IntoActiveModel};
        use tokio::sync::mpsc;
        use tokio_util::sync::CancellationToken;
        use uuid::Uuid;
        use warpgate_common::{GlobalParams, TargetSessionId, UserSessionId};
        use warpgate_core::recordings::{RecordingOwner, SessionRecordings, test_support};
        use warpgate_db_entities::Parameters::{
            self, ConfigMigrationValues, RecordingsDiskConfig, RecordingsStorageConfig,
            set_config_migration_values,
        };
        use warpgate_db_migrations::migrate_database;

        use super::super::{
            SessionRecordingMetadata, record_api_response, run_websocket_recording,
            start_api_recording, start_stream_recording,
        };

        struct Recording {
            recordings: SessionRecordings,
            id: TargetSessionId,
            root: PathBuf,
            _dir: tempfile::TempDir,
        }

        async fn recording(refuse: bool) -> Recording {
            test_support::log_events();
            let dir = tempfile::tempdir().unwrap();
            set_config_migration_values(ConfigMigrationValues::default());
            let db = Database::connect("sqlite::memory:").await.unwrap();
            migrate_database(&db).await.unwrap();
            let mut parameters = Parameters::Entity::get(&db)
                .await
                .unwrap()
                .into_active_model();
            parameters.recordings_enable = Set(true);
            parameters.recordings_storage = Set(serde_json::to_string(
                &RecordingsStorageConfig::Disk(RecordingsDiskConfig {
                    path: "recordings".into(),
                }),
            )
            .unwrap());
            parameters.update(&db).await.unwrap();
            let id = TargetSessionId(Uuid::new_v4());
            warpgate_db_entities::TargetSession::ActiveModel {
                id: Set(id),
                user_session_id: Set(UserSessionId(Uuid::new_v4())),
                target_snapshot: Set("{}".into()),
                target_id: Set(Uuid::new_v4()),
                started: Set(time::OffsetDateTime::now_utc()),
                ..Default::default()
            }
            .insert(&db)
            .await
            .unwrap();
            let params = GlobalParams::new(dir.path().join("warpgate.yaml"), false)
                .unwrap()
                .with_refuse_unrecorded_sessions(refuse);
            Recording {
                recordings: SessionRecordings::new(db, &params),
                id,
                root: dir.path().join("recordings"),
                _dir: dir,
            }
        }

        impl Recording {
            fn fail(&self) {
                assert!(test_support::fail_open_recording_files(&self.root) >= 1);
            }

            fn assert_one_failure_line(&self, required: bool) {
                assert_eq!(self.recordings.failed_recordings(), 1);
                let lines = test_support::failed_recording_lines(&self.id);
                assert_eq!(lines.len(), 1, "{lines:?}");
                assert_eq!(lines[0]["protocol"], "kubernetes");
                assert_eq!(lines[0]["user"], "alice");
                assert_eq!(lines[0]["target"], "cluster");
                assert_eq!(lines[0]["stage"], "write");
                assert_eq!(lines[0]["required"], required.to_string());
            }
        }

        fn owner() -> RecordingOwner {
            RecordingOwner {
                protocol: "kubernetes",
                user: "alice".into(),
                target: "cluster".into(),
            }
        }

        fn exec() -> SessionRecordingMetadata {
            SessionRecordingMetadata::Exec {
                namespace: "default".into(),
                pod: "pod".into(),
                container: None,
                command: vec!["sh".into()],
            }
        }

        /// An exec stream whose recording fails: when required, the stream's
        /// `recording_failed` token is cancelled, which ends the stream; otherwise it
        /// goes on unrecorded. Either way the failure is logged and counted once.
        #[tokio::test]
        async fn an_exec_stream_whose_recording_fails_ends_only_when_required() {
            for required in [true, false] {
                let r = recording(required).await;
                let recorder = start_stream_recording(&owner(), &r.id, &r.recordings, exec())
                    .await
                    .unwrap()
                    .unwrap();
                let closed = CancellationToken::new();
                let recording_failed = closed.child_token();
                let (tx, rx) = mpsc::channel(1000);
                let task = tokio::spawn(run_websocket_recording(
                    recorder,
                    rx,
                    recording_failed.clone(),
                ));
                tx.send(b"\x00ls\n".to_vec()).await.unwrap();
                r.fail();
                for _ in 0..1000 {
                    if task.is_finished() {
                        break;
                    }
                    let _ = tx.send(b"\x01output".to_vec()).await;
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                assert!(task.is_finished(), "the recording stopped at its failure");
                assert_eq!(
                    recording_failed.is_cancelled(),
                    required,
                    "the stream ends only when recording is required"
                );
                r.assert_one_failure_line(required);
            }
        }

        /// An API request whose recording fails still gets its response, whether or
        /// not recording is required: it has already reached the cluster. Logged and
        /// counted once for the recording.
        #[tokio::test]
        async fn an_api_request_whose_recording_fails_is_logged_and_answered_either_way() {
            for required in [true, false] {
                let r = recording(required).await;
                let recorder = start_api_recording(&owner(), &r.id, &r.recordings)
                    .await
                    .unwrap()
                    .unwrap();
                r.fail();
                for _ in 0..1000 {
                    record_api_response(
                        &recorder,
                        "GET",
                        "/api/v1/pods",
                        HashMap::new(),
                        b"",
                        200,
                        b"{}",
                    )
                    .await;
                    if r.recordings.failed_recordings() > 0 {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                for _ in 0..3 {
                    record_api_response(
                        &recorder,
                        "GET",
                        "/api/v1/pods",
                        HashMap::new(),
                        b"",
                        200,
                        b"{}",
                    )
                    .await;
                }
                r.assert_one_failure_line(required);
            }
        }
    }
}
