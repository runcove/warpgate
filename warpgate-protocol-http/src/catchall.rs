use std::sync::Arc;

use poem::session::Session;
use poem::web::websocket::WebSocket;
use poem::web::{Data, FromRequest, Redirect};
use poem::{Body, IntoResponse, Request, Response, handler};
use serde::Deserialize;
use tokio::sync::{Mutex, broadcast};
use tracing::{Instrument, debug, info_span, warn};
use uuid::Uuid;
use warpgate_common::auth::AuthStateUserInfo;
use warpgate_common::{
    HostBindingConflict, Target, TargetHTTPOptions, TargetOptions, WarpgateError,
    host_binding_conflict, same_binding_hostname,
};
use warpgate_common_http::auth::UnauthenticatedRequestContext;
use warpgate_common_http::{
    AuthenticatedRequestContext, RequestAuthorization, SessionAuthorization, SessionKeepalive,
};
use warpgate_core::live_streams::{LiveStreamKind, host_binding};
use warpgate_core::{
    ConfigProvider, Services, TargetAuthorization, TargetSessionStart, authorize_for_target,
};

use crate::approval_gate::resolve_admin_approval;
use crate::client_cache::HttpClientCache;
use crate::common::SessionExt;
use crate::proxy::{proxy_normal_request, proxy_websocket_request};
use crate::session::SessionStore;

#[derive(Deserialize)]
struct QueryParams {
    #[serde(rename = "warpgate-target")]
    warpgate_target: Option<String>,
}

pub fn target_select_redirect() -> Response {
    Redirect::temporary("/@warpgate").into_response()
}

#[handler]
#[allow(clippy::too_many_arguments)]
pub async fn catchall_endpoint(
    req: &Request,
    ws: Option<WebSocket>,
    session: &Session,
    body: Body,
    ctx: Data<&AuthenticatedRequestContext>,
    unauthenticated_ctx: Data<&UnauthenticatedRequestContext>,
    http_client_cache: Data<&HttpClientCache>,
    session_store: Data<&Arc<Mutex<SessionStore>>>,
) -> poem::Result<Response> {
    let Some(authorization) = get_target_for_request(req, &ctx).await? else {
        return Ok(target_select_redirect());
    };

    session.set_target_name(authorization.target().name.clone());

    let RequestAuthorization::Session(_) = &ctx.auth else {
        return Err(poem::Error::from_status(
            poem::http::StatusCode::UNAUTHORIZED,
        ));
    };

    let (handle, close_rx, ws_keepalive) = {
        let mut store = session_store.lock().await;
        let handle = store.handle_for_request(req, &unauthenticated_ctx).await?;
        let id = handle.lock().await.user_session_id();
        let close_rx = store.close_receiver_by_id(id).ok_or_else(|| {
            poem::Error::from_status(poem::http::StatusCode::INTERNAL_SERVER_ERROR)
        })?;
        // A websocket outlives the request that upgraded it, and a public or
        // ticket session carries no keepalive of its own: take one here, so the
        // sweep doesn't cut the socket once the session is idle.
        let ws_keepalive = ws.is_some().then(|| store.keepalive_guard(id));
        (handle, close_rx, ws_keepalive)
    };

    // start_target_session already sets/checks session user info
    let started = handle
        .lock()
        .await
        .start_target_session(authorization)
        .await;
    let admitted = match started {
        Err(WarpgateError::UserSessionEnded) => {
            // got revoked in the meantime
            session.purge();
            return Err(poem::Error::from_status(
                poem::http::StatusCode::UNAUTHORIZED,
            ));
        }
        Ok(TargetSessionStart::Started(started)) => started,
        Err(error) => return Err(error.into()),
        Ok(TargetSessionStart::NeedsApproval(authorization)) => {
            // Fail early, before we get to websocket
            match resolve_admin_approval(req, &ctx, &handle, authorization).await? {
                Ok(started) => started,
                Err(response) => return Ok(response),
            }
        }
    };
    // A revocation of this user's access to the target ends the request if it
    // is still running (a websocket, a streamed body) without closing the
    // browser session. A request admitted by the public bypass (a ticket with
    // no ticket id, anonymous or logged in) is watched too, and ends when the
    // target stops being public. A real ticket, a token or a peer has no role
    // or public rule: it is held to the target's host binding alone.
    let close_rx = watch_admitted_live_stream(
        ctx.services(),
        &ctx.auth,
        close_rx,
        admitted.target().id,
        host_binding(&admitted.target().options),
    )
    .await?;
    let keepalive_guard = Data::<&SessionKeepalive>::from_request_without_body(req)
        .await
        .ok()
        .map(|keepalive| keepalive.guard());

    // `session` field is UserSession, not this
    let span = info_span!("", target_session=%admitted.id(), target=%admitted.target().name);

    Ok(match ws.zip(ws_keepalive) {
        Some((ws, ws_keepalive)) => {
            proxy_websocket_request(req, ws, &ctx, admitted, close_rx, ws_keepalive)
                .instrument(span)
                .await?
                .into_response()
        }
        None => proxy_normal_request(
            req,
            *ctx,
            body,
            *http_client_cache,
            admitted,
            close_rx,
            keepalive_guard,
        )
        .instrument(span)
        .await?
        .into_response(),
    })
}

/// True when the request path targets one of Warpgate's own management
/// mounts (`/@warpgate*` or `/_warpgate*`).
///
/// Defence-in-depth on the public-target bypass: a misconfigured
/// `public: true` target whose `external_host` matches Warpgate's base host
/// must never be able to serve a management surface anonymously. The two
/// management prefixes are nested ahead of the catchall in `lib.rs`, so
/// `page_auth` should not see these paths at all — this predicate keeps the
/// guarantee independent of routing order.
pub(crate) fn is_warpgate_management_path(path: &str) -> bool {
    path == "/@warpgate"
        || path.starts_with("/@warpgate/")
        || path == "/_warpgate"
        || path.starts_with("/_warpgate/")
}

/// Outcome of consulting the public-target bypass on an incoming HTTP
/// request. Pure decision over the resolved target and the request
/// authorization state — no async, no I/O — so it can be unit-tested
/// without spinning up a full `Services` fixture.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PublicTargetDecision {
    /// `public: true` target with anonymous or session-authed client.
    /// `page_auth` skips `_inner_auth` and the catchall proxies straight
    /// through on a throwaway session.
    Bypass,
    /// `public: true` target with an admin, user or cluster token. Tokens are
    /// not proxy-scoped, so proxy access via token is rejected with 401.
    Reject401,
    /// No target matched the host, the matched target isn't HTTP, it has
    /// `public: false`, or it requires admin approval. The existing auth
    /// path runs unchanged.
    NotApplicable,
}

/// Decide how the public-target bypass should affect a request.
///
/// `target_opts` is the resolved HTTP target options (`None` means no host
/// match or non-HTTP target). `require_approval` is the target's own
/// admin-approval flag: such a target is never bypassed, or anonymous
/// visitors would raise approval requests and one approval would let every
/// anonymous visitor in. `auth` is the request's authorization state (`None`
/// means anonymous).
pub(crate) fn decide_public_target_access(
    target_opts: Option<&TargetHTTPOptions>,
    require_approval: bool,
    auth: Option<&RequestAuthorization>,
) -> PublicTargetDecision {
    let Some(opts) = target_opts else {
        return PublicTargetDecision::NotApplicable;
    };
    if !opts.public || require_approval {
        return PublicTargetDecision::NotApplicable;
    }
    match auth {
        // Anonymous (no auth context) and session-authed users bypass the
        // role check and reach the proxy.
        None | Some(RequestAuthorization::Session(_)) => PublicTargetDecision::Bypass,
        // Admin/user API tokens are scoped to the admin REST API, and the
        // cluster token to peer-to-peer traffic; using any of them against a
        // public proxy target is a configuration error and returns 401
        // explicitly rather than silently proxying.
        Some(
            RequestAuthorization::AdminToken
            | RequestAuthorization::UserToken { .. }
            | RequestAuthorization::ClusterPeer,
        ) => PublicTargetDecision::Reject401,
    }
}

/// `host`, a Host header value, without its port when the port is 80 or 443,
/// the default ports of HTTP and HTTPS. A client may send the default port
/// (`v.example:443`) and still mean the host a target is bound to without one
/// (`v.example`). `None` when there is no such port to drop. An IPv6 literal
/// keeps its brackets; a bare IPv6 address is not a Host header and is left
/// alone.
pub(crate) fn host_without_default_port(host: &str) -> Option<&str> {
    let (name, port) = host.rsplit_once(':')?;
    let bracketed = name.starts_with('[') && name.ends_with(']');
    (matches!(port, "80" | "443") && !name.is_empty() && (bracketed || !name.contains(':')))
        .then_some(name)
}

/// Whether a request whose Host header is `request_host` is for the host a
/// target is bound to, `bound`: the same value, or the same value once the
/// request's default port is dropped ([`host_without_default_port`]). Any
/// other port must match exactly. (Two targets may not share a hostname at
/// any port: [`host_binding_conflict`].)
pub(crate) fn host_matches_binding(bound: &str, request_host: &str) -> bool {
    request_host == bound || host_without_default_port(request_host) == Some(bound)
}

/// The target bound to the request's Host header, `host`: the target whose
/// `external_host` is exactly `host`, else, when `host` carries a default
/// port, the one bound to the host without it. An exact binding wins.
///
/// A binding the admin API would refuse today is an error, not served: one
/// on the control-plane host (here) or on a hostname another target shares
/// (in the config provider's lookup), see [`host_binding_conflict`].
pub(crate) async fn get_target_by_request_host(
    services: &Services,
    host: &str,
) -> Result<Option<Target>, WarpgateError> {
    let config_provider = &services.config_provider;
    let mut found = config_provider.get_target_by_hostname(host).await?;
    if found.is_none()
        && let Some(name) = host_without_default_port(host)
    {
        found = config_provider.get_target_by_hostname(name).await?;
    }
    let Some(target) = found else {
        return Ok(None);
    };
    refuse_control_plane_binding(services, &target).await?;
    Ok(Some(target))
}

/// Refuses a target bound to the control-plane host, at any port.
async fn refuse_control_plane_binding(
    services: &Services,
    target: &Target,
) -> Result<(), WarpgateError> {
    let Some(binding) = target.options.external_host() else {
        return Ok(());
    };
    let control_plane = services.config.lock().await.control_plane_host();
    match host_binding_conflict(binding, control_plane.as_deref(), []) {
        None => Ok(()),
        Some(conflict) => {
            warn!(target = %target.name, %conflict, "Refusing a target's host binding");
            Err(WarpgateError::InconsistentState(format!(
                "target {} is not served: {conflict}",
                target.name
            )))
        }
    }
}

/// Filter a candidate target list down to an HTTP target whose
/// `external_host` matches the given host header ([`host_matches_binding`]:
/// port-aware, but a default port may be dropped). A match whose hostname
/// another candidate also binds, at any port, is refused
/// ([`host_binding_conflict`]).
///
/// Pure over `targets` so unit tests don't need a real config provider. The
/// async caller narrows the candidates first — `get_target_by_request_host`
/// does the indexed JSON-column lookup — and this helper enforces the
/// HTTP-only and `external_host` half of the contract.
pub(crate) fn find_http_target_by_external_host(
    targets: &[Target],
    host: &str,
) -> Result<Option<(Target, TargetHTTPOptions)>, HostBindingConflict> {
    fn bound(t: &Target) -> Option<(&str, &TargetHTTPOptions)> {
        match t.options {
            TargetOptions::Http(ref options) => options
                .external_host
                .as_deref()
                .filter(|bound| !bound.is_empty())
                .map(|bound| (bound, options)),
            _ => None,
        }
    }
    let Some((target, binding, options)) = targets.iter().find_map(|t| {
        bound(t)
            .filter(|(binding, _)| host_matches_binding(binding, host))
            .map(|(binding, options)| (t, binding, options))
    }) else {
        return Ok(None);
    };
    let others = targets
        .iter()
        .filter(|other| !std::ptr::eq(*other, target))
        .filter_map(|other| Some((other.name.as_str(), bound(other)?.0)));
    match host_binding_conflict(binding, None, others) {
        Some(conflict) => Err(conflict),
        None => Ok(Some((target.clone(), options.clone()))),
    }
}

/// Async wrapper around the host→target lookup + `decide_public_target_access`
/// helpers. Used by `page_auth` (in `common.rs`) to skip the redirect-to-login
/// when a request resolves to a public target. The decision is taken afresh on
/// every request, so turning `public` off takes effect on the next one.
pub(crate) async fn resolve_public_target_decision(
    services: &warpgate_core::Services,
    host: Option<&str>,
    auth: Option<&RequestAuthorization>,
) -> poem::Result<(Option<(Target, TargetHTTPOptions)>, PublicTargetDecision)> {
    let Some(host) = host else {
        return Ok((None, PublicTargetDecision::NotApplicable));
    };
    let candidates: Vec<Target> = get_target_by_request_host(services, host)
        .await?
        .into_iter()
        .collect();
    let resolved = find_http_target_by_external_host(&candidates, host).map_err(|conflict| {
        warn!(%conflict, "Refusing a target's host binding");
        WarpgateError::InconsistentState(conflict.to_string())
    })?;
    let decision = decide_public_target_access(
        resolved.as_ref().map(|(_, o)| o),
        resolved.as_ref().is_some_and(|(t, _)| t.require_approval),
        auth,
    );
    Ok((resolved, decision))
}

/// Which target a session-authorized request is for, by name. A hostname
/// bound to a target serves that target: the `warpgate-target` query
/// parameter is honoured there only when it names the same target, and any
/// other name is ignored. On a host with no binding, the query parameter
/// picks the target, else the one remembered in the session. Pure, so the
/// order can be tested without a config provider.
pub(crate) fn select_target_name(
    query: Option<&str>,
    host_target: Option<&str>,
    session_target: Option<String>,
) -> Option<String> {
    if let Some(host_target) = host_target {
        Some(host_target.to_owned())
    } else if let Some(query) = query {
        Some(query.to_owned())
    } else {
        session_target
    }
}

/// Whether a target may be served on a request whose Host header is
/// `request_host`, given the target's `external_host`. A target bound to a
/// host is served only on that host, compared as `get_target_by_request_host`
/// compares it ([`host_matches_binding`]: the full Host header, port included,
/// but a default port may be dropped); an unbound target is served on any
/// host. Pure, so it can be tested without a config provider.
pub(crate) fn served_on_host(external_host: Option<&str>, request_host: Option<&str>) -> bool {
    match external_host.filter(|host| !host.is_empty()) {
        Some(bound) => request_host.is_some_and(|host| host_matches_binding(bound, host)),
        None => true,
    }
}

/// [`served_on_host`] for a target row: its `external_host`, if it is an
/// HTTP target. A target with no hostname of its own is served only when
/// `serve_unbound` is true: [`unbound_targets_served_on_host`] for this
/// request's host.
fn target_served_on_host(target: &Target, request_host: Option<&str>, serve_unbound: bool) -> bool {
    let external_host = match &target.options {
        TargetOptions::Http(options) => options.external_host.as_deref(),
        _ => None,
    };
    match external_host.filter(|host| !host.is_empty()) {
        Some(bound) => served_on_host(Some(bound), request_host),
        None => serve_unbound,
    }
}

/// `http.serve_unbound_http_targets`: whether a web target with no hostname
/// of its own is served at all.
async fn serve_unbound_http_targets(services: &Services) -> bool {
    services
        .config
        .lock()
        .await
        .store
        .http
        .serve_unbound_http_targets
}

/// Whether a web target with no hostname of its own may be served on a
/// request whose Host header is `request_host`: only when
/// `http.serve_unbound_http_targets` is on, and never on a hostname a web
/// target is bound to, at any port (a browser's cookies do not tell ports
/// apart) and whether or not that binding is refused.
async fn unbound_targets_served_on_host(
    services: &Services,
    request_host: Option<&str>,
) -> Result<bool, WarpgateError> {
    if !serve_unbound_http_targets(services).await {
        return Ok(false);
    }
    let Some(host) = request_host else {
        return Ok(true);
    };
    let targets = services.config_provider.list_targets().await?;
    Ok(!targets.iter().any(|target| {
        target
            .options
            .external_host()
            .is_some_and(|bound| !bound.is_empty() && same_binding_hostname(bound, host))
    }))
}

/// [`target_served_on_host`] for a ticket's target, which is resolved by id,
/// not by host. The request's host is resolved as any request on it is
/// ([`get_target_by_request_host`]): a bound target is served only if that
/// lookup finds it, so a binding the lookup refuses (on the control-plane
/// host, at any port, or on a hostname another target shares) is refused for
/// a ticket too, as an error; an unbound target is served only on a host no
/// target is bound to, so a host bound to one target serves no other.
pub(crate) async fn ticket_target_served_on_host(
    services: &Services,
    target: &Target,
    request_host: Option<&str>,
) -> Result<bool, WarpgateError> {
    let bound = target
        .options
        .external_host()
        .is_some_and(|bound| !bound.is_empty());
    let serve_unbound = !bound && unbound_targets_served_on_host(services, request_host).await?;
    if !target_served_on_host(target, request_host, serve_unbound) {
        return Ok(false);
    }
    let (true, Some(host)) = (bound, request_host) else {
        return Ok(true);
    };
    let found = get_target_by_request_host(services, host).await?;
    Ok(found.is_some_and(|found| found.id == target.id))
}

/// Whether `target` is bound to `request_host`: it has a binding, and
/// [`served_on_host`] serves it there. With `get_target_by_request_host` this is
/// how the management scope tells a bound host, so it and the catchall agree
/// on which hosts are bound.
pub(crate) fn bound_to_host(target: &Target, request_host: &str) -> bool {
    let bound = match &target.options {
        TargetOptions::Http(options) => options.external_host.as_deref(),
        _ => None,
    };
    bound.is_some_and(|bound| !bound.is_empty())
        && target_served_on_host(target, Some(request_host), false)
}

fn is_http_authorization(
    authorization: TargetAuthorization,
) -> Option<TargetAuthorization<TargetHTTPOptions>> {
    authorization.narrow().ok()
}

async fn get_target_for_request(
    req: &Request,
    ctx: &AuthenticatedRequestContext,
) -> poem::Result<Option<TargetAuthorization<TargetHTTPOptions>>> {
    let config_provider = ctx.services().config_provider.as_ref();

    // A ticket is bound to one target row, and it was authorized against that row
    // when the session was established. Resolving by id keeps the request from
    // steering it elsewhere — via query param, host rebinding or session state —
    // and survives the target being renamed.
    if let RequestAuthorization::Session(SessionAuthorization::Ticket {
        user_id,
        username,
        target_id,
        ticket_id,
        ..
    }) = &ctx.auth
    {
        let Some(target) = config_provider.get_target_by_id(*target_id).await? else {
            return Ok(None);
        };

        if target.id != *target_id {
            return Err(WarpgateError::InconsistentState(
                "ticket session target does not match the ticket's target".into(),
            )
            .into());
        }

        // A target bound to a host is served only on that host, for a ticket
        // as for anyone else, and not at all if that binding is refused.
        let request_host = ctx.trusted_host_header(req);
        if !ticket_target_served_on_host(ctx.services(), &target, request_host.as_deref()).await? {
            debug!(
                "Ticket target {} is not served on host {:?}",
                target.name, request_host
            );
            return Ok(None);
        }

        return Ok(is_http_authorization(
            TargetAuthorization::for_ticket_session(
                AuthStateUserInfo {
                    id: *user_id,
                    username: username.clone(),
                },
                target,
                *ticket_id,
                crate::common::PROTOCOL_NAME,
            )?,
        ));
    }

    let RequestAuthorization::Session(SessionAuthorization::User { .. }) = &ctx.auth else {
        return Ok(None);
    };

    let session = <&Session>::from_request_without_body(req).await?;
    let params: QueryParams = req.params()?;

    // Full Host header including `:port`: `get_target_by_request_host` matches
    // `external_host` with the port, dropping only a default one.
    let request_host = ctx.trusted_host_header(req);

    let host_based_target = if let Some(host) = request_host.as_deref() {
        let found = get_target_by_request_host(ctx.services(), host).await?;
        if found.is_some() {
            debug!(
                "Domain rebinding detected: host={} -> target={:?}",
                host,
                found.as_ref().map(|target| &target.name)
            );
        }
        found
    } else {
        None
    };

    if let (Some(query), Some(bound)) = (&params.warpgate_target, &host_based_target)
        && *query != bound.name
    {
        debug!(
            "Ignoring a warpgate-target naming another target on a host bound to target {}",
            bound.name
        );
    }
    let selected_target_name = select_target_name(
        params.warpgate_target.as_deref(),
        host_based_target
            .as_ref()
            .map(|target| target.name.as_str()),
        session.get_target_name(),
    );

    let domain_rebinding_configured = host_based_target.is_some();

    if let Some(target_name) = selected_target_name {
        let target =
            if let Some(target) = host_based_target.filter(|target| target.name == target_name) {
                Some(target)
            } else {
                config_provider
                    .get_target_by_name(target_name.as_str())
                    .await?
            };
        let serve_unbound = match &target {
            Some(target) if target.options.external_host().is_none_or(str::is_empty) => {
                unbound_targets_served_on_host(ctx.services(), request_host.as_deref()).await?
            }
            _ => false,
        };
        let target = target.filter(|target| {
            let served = target_served_on_host(target, request_host.as_deref(), serve_unbound);
            if !served {
                debug!(
                    "Target {} is not served on host {:?}",
                    target.name, request_host
                );
            }
            served
        });

        // Reached only for a `SessionAuthorization::User` (ticket sessions are
        // handled separately above), so the session is the prior-auth evidence.
        let Some(full) = ctx.auth.as_full_user() else {
            return Ok(None);
        };
        let identity = full.identity(crate::common::PROTOCOL_NAME);

        if let Some(target) = target
            && let Some(authorization) =
                authorize_for_target(config_provider, &identity, target).await?
            && let Some(authorization) = is_http_authorization(authorization)
        {
            return Ok(Some(authorization));
        }
    }

    if domain_rebinding_configured {
        debug!(
            "Domain rebinding was configured for this host but target was not selected. This may indicate the target doesn't exist or user is not authorized."
        );
    }

    Ok(None)
}

/// Registers the request for revocation by the rule that admitted it: a
/// logged-in user is role-based, a ticket session with no ticket id came
/// through the public bypass (anonymous or logged in) and is public, and
/// anything else (a real ticket, a token, a peer) has no role or public rule
/// and is registered binding-only, so that only a change of the target's host
/// binding ends it (deleting the ticket or token is what cuts it otherwise).
/// `opened_binding` is the target's host binding the request was admitted
/// against.
async fn watch_admitted_live_stream(
    services: &Services,
    auth: &RequestAuthorization,
    close_rx: broadcast::Receiver<()>,
    target_id: Uuid,
    opened_binding: Option<String>,
) -> poem::Result<broadcast::Receiver<()>> {
    match auth {
        RequestAuthorization::Session(SessionAuthorization::User { user_id, .. }) => {
            watch_live_stream(services, close_rx, *user_id, target_id, opened_binding).await
        }
        RequestAuthorization::Session(SessionAuthorization::Ticket {
            user_id,
            ticket_id: None,
            ..
        }) => {
            watch_public_live_stream(services, close_rx, *user_id, target_id, opened_binding).await
        }
        RequestAuthorization::Session(SessionAuthorization::Ticket { user_id, .. })
        | RequestAuthorization::UserToken { user_id, .. } => {
            watch_binding_only_live_stream(services, close_rx, *user_id, target_id, opened_binding)
                .await
        }
        // No user: the nil id is one shared bucket for these. Only the host
        // binding check cancels a binding-only stream, so no per-user cancel
        // reaches it.
        RequestAuthorization::AdminToken | RequestAuthorization::ClusterPeer => {
            watch_binding_only_live_stream(
                services,
                close_rx,
                Uuid::nil(),
                target_id,
                opened_binding,
            )
            .await
        }
    }
}

/// [`watch_live_stream`] for a request with no role or public rule to
/// re-check: registered first, then only the host binding is checked again.
async fn watch_binding_only_live_stream(
    services: &Services,
    close_rx: broadcast::Receiver<()>,
    user_id: Uuid,
    target_id: Uuid,
    opened_binding: Option<String>,
) -> poem::Result<broadcast::Receiver<()>> {
    let close_rx = services.live_streams.watch(
        close_rx,
        user_id,
        target_id,
        LiveStreamKind::BindingOnly,
        opened_binding.clone(),
    );
    ensure_host_binding_unchanged(services, target_id, &opened_binding).await?;
    Ok(close_rx)
}

/// Registers a request with [`warpgate_core::live_streams::LiveStreams`], then
/// checks the user's access to the target again. A revocation either finds
/// the registration when it re-checks live streams, or was written before this
/// check and refuses the request here: none slips between the first check and
/// the registration. Fails closed: a check that errors refuses the request.
async fn watch_live_stream(
    services: &Services,
    close_rx: broadcast::Receiver<()>,
    user_id: Uuid,
    target_id: Uuid,
    opened_binding: Option<String>,
) -> poem::Result<broadcast::Receiver<()>> {
    let close_rx = services.live_streams.watch(
        close_rx,
        user_id,
        target_id,
        LiveStreamKind::RoleBased,
        opened_binding.clone(),
    );
    ensure_host_binding_unchanged(services, target_id, &opened_binding).await?;
    match services
        .config_provider
        .authorize_target_by_id(user_id, target_id)
        .await
    {
        Ok(true) => Ok(close_rx),
        Ok(false) => Err(poem::Error::from_status(poem::http::StatusCode::FORBIDDEN)),
        Err(error) => {
            warn!(%error, %user_id, %target_id, "Could not re-check access to the target; refusing");
            Err(poem::Error::from_status(poem::http::StatusCode::FORBIDDEN))
        }
    }
}

/// Refuses a request registered against a host binding the target no longer
/// has (or whose target cannot be read), as the re-check would end it later.
async fn ensure_host_binding_unchanged(
    services: &Services,
    target_id: Uuid,
    opened_binding: &Option<String>,
) -> poem::Result<()> {
    if services.current_host_binding(target_id).await.as_ref() == Some(opened_binding) {
        Ok(())
    } else {
        Err(poem::Error::from_status(poem::http::StatusCode::FORBIDDEN))
    }
}

/// [`watch_live_stream`] for a request the public bypass admitted: registered
/// first, then the target is checked again to still be public (HTTP, `public`,
/// no approval required), by the same rule as the revocation that ends it
/// ([`Services::public_target_still_shared`]). The user's roles play no part.
/// Fails closed: a check that errors refuses the request.
async fn watch_public_live_stream(
    services: &Services,
    close_rx: broadcast::Receiver<()>,
    user_id: Uuid,
    target_id: Uuid,
    opened_binding: Option<String>,
) -> poem::Result<broadcast::Receiver<()>> {
    let close_rx = services.live_streams.watch(
        close_rx,
        user_id,
        target_id,
        LiveStreamKind::Public,
        opened_binding.clone(),
    );
    ensure_host_binding_unchanged(services, target_id, &opened_binding).await?;
    if services.public_target_still_shared(target_id).await {
        Ok(close_rx)
    } else {
        Err(poem::Error::from_status(poem::http::StatusCode::FORBIDDEN))
    }
}

#[cfg(test)]
mod live_stream_tests {
    //! A proxied request is registered for revocation before its access is
    //! checked again, and refused if that check fails or errors.

    use sea_orm::ActiveValue::Set;
    use sea_orm::{ActiveModelTrait, ConnectionTrait, DatabaseConnection};
    use uuid::Uuid;
    use warpgate_common_http::{RequestAuthorization, SessionAuthorization};
    use warpgate_core::live_streams::LiveStreamKind;
    use warpgate_db_entities::Target::TargetKind;
    use warpgate_db_entities::{Role, Target, TargetRoleAssignment, User, UserRoleAssignment};

    use super::{
        ticket_target_served_on_host, unbound_targets_served_on_host, watch_admitted_live_stream,
        watch_live_stream, watch_public_live_stream,
    };
    use crate::test_db::{memory_db, services};

    async fn deregistered(services: &warpgate_core::Services) -> bool {
        for _ in 0..100 {
            if services.live_streams.in_use().unwrap().is_empty() {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        false
    }

    #[tokio::test]
    async fn access_gone_by_registration_refuses_the_request() {
        let services = services(memory_db().await).await;
        let (_session, close_rx) = tokio::sync::broadcast::channel(1);

        let watched =
            watch_live_stream(&services, close_rx, Uuid::new_v4(), Uuid::new_v4(), None).await;

        assert_eq!(
            watched.err().map(|e| e.status()),
            Some(poem::http::StatusCode::FORBIDDEN)
        );
        assert!(deregistered(&services).await);
    }

    #[tokio::test]
    async fn a_failing_access_check_refuses_the_request() {
        let db = memory_db().await;
        let services = services(db.clone()).await;
        db.execute_unprepared("DROP TABLE user_roles")
            .await
            .unwrap();
        let (_session, close_rx) = tokio::sync::broadcast::channel(1);

        let watched =
            watch_live_stream(&services, close_rx, Uuid::new_v4(), Uuid::new_v4(), None).await;

        assert_eq!(
            watched.err().map(|e| e.status()),
            Some(poem::http::StatusCode::FORBIDDEN)
        );
        assert!(deregistered(&services).await);
    }

    #[tokio::test]
    async fn a_public_registration_is_refused_when_the_target_is_gone() {
        let services = services(memory_db().await).await;
        let (_session, close_rx) = tokio::sync::broadcast::channel(1);

        // No such target: nothing shares it.
        let watched =
            watch_public_live_stream(&services, close_rx, Uuid::nil(), Uuid::new_v4(), None).await;

        assert_eq!(
            watched.err().map(|e| e.status()),
            Some(poem::http::StatusCode::FORBIDDEN)
        );
        assert!(deregistered(&services).await);
    }

    #[tokio::test]
    async fn a_failing_public_check_refuses_the_request() {
        let db = memory_db().await;
        let services = services(db.clone()).await;
        db.execute_unprepared("DROP TABLE targets").await.unwrap();
        let (_session, close_rx) = tokio::sync::broadcast::channel(1);

        let watched =
            watch_public_live_stream(&services, close_rx, Uuid::nil(), Uuid::new_v4(), None).await;

        assert_eq!(
            watched.err().map(|e| e.status()),
            Some(poem::http::StatusCode::FORBIDDEN)
        );
        assert!(deregistered(&services).await);
    }

    /// A public HTTP target, which a role check refuses a user with no role.
    async fn public_target(db: &DatabaseConnection) -> Uuid {
        let id = Uuid::new_v4();
        Target::ActiveModel {
            id: Set(id),
            name: Set(format!("target-{id}")),
            description: Set(String::new()),
            kind: Set(TargetKind::Http),
            options: Set(serde_json::json!({"http": {"url": "http://h", "public": true}})),
            rate_limit_bytes_per_second: Set(None),
            group_id: Set(None),
            ticket_max_duration_seconds: Set(None),
            ticket_requests_disabled: Set(false),
            ticket_require_approval: Set(false),
            ticket_max_uses: Set(None),
            require_approval: Set(false),
        }
        .insert(db)
        .await
        .unwrap();
        id
    }

    /// An HTTP target bound to `external_host`, read back as the ticket path
    /// reads it, by id.
    async fn bound_target(
        services: &warpgate_core::Services,
        db: &DatabaseConnection,
        name: &str,
        external_host: &str,
    ) -> warpgate_common::Target {
        use warpgate_core::ConfigProvider;

        let id = Uuid::new_v4();
        Target::ActiveModel {
            id: Set(id),
            name: Set(name.into()),
            description: Set(String::new()),
            kind: Set(TargetKind::Http),
            options: Set(serde_json::json!({
                "http": {"url": "http://h", "external_host": external_host}
            })),
            rate_limit_bytes_per_second: Set(None),
            group_id: Set(None),
            ticket_max_duration_seconds: Set(None),
            ticket_requests_disabled: Set(false),
            ticket_require_approval: Set(false),
            ticket_max_uses: Set(None),
            require_approval: Set(false),
        }
        .insert(db)
        .await
        .unwrap();
        services
            .config_provider
            .get_target_by_id(id)
            .await
            .unwrap()
            .unwrap()
    }

    /// A ticket's target is resolved by id, not by host, yet a binding the
    /// host lookup refuses is refused for it too: one on the control-plane
    /// host at any port, and one on a hostname another target shares.
    #[tokio::test]
    async fn a_ticket_target_with_a_refused_binding_is_not_served() {
        let db = memory_db().await;
        let services = services(db.clone()).await;
        services.config.lock().await.store.external_host = Some("warp.example.com".into());

        let own = bound_target(&services, &db, "own", "vm.example.com:3000").await;
        assert!(
            ticket_target_served_on_host(&services, &own, Some("vm.example.com:3000"))
                .await
                .unwrap()
        );
        assert!(
            !ticket_target_served_on_host(&services, &own, Some("warp.example.com"))
                .await
                .unwrap()
        );

        let control_plane = bound_target(&services, &db, "cp", "WARP.example.com:8443").await;
        assert!(
            ticket_target_served_on_host(&services, &control_plane, Some("WARP.example.com:8443"))
                .await
                .is_err()
        );

        let shared = bound_target(&services, &db, "a", "shared.example.com:3000").await;
        bound_target(&services, &db, "b", "shared.example.com:8080").await;
        assert!(
            ticket_target_served_on_host(&services, &shared, Some("shared.example.com:3000"))
                .await
                .is_err()
        );
    }

    /// A target with no hostname is never served on a hostname another
    /// target is bound to, at any port and whether or not that binding is
    /// refused, even with `http.serve_unbound_http_targets` on; elsewhere
    /// the switch decides.
    #[tokio::test]
    async fn an_unbound_ticket_target_is_not_served_on_a_bound_host() {
        use warpgate_core::ConfigProvider;

        let db = memory_db().await;
        let services = services(db.clone()).await;
        services.config.lock().await.store.external_host = Some("warp.example.com".into());
        bound_target(&services, &db, "own", "vm.example.com:3000").await;
        bound_target(&services, &db, "a", "shared.example.com:3000").await;
        bound_target(&services, &db, "b", "shared.example.com:8080").await;
        let unbound = public_target(&db).await;
        let unbound = services
            .config_provider
            .get_target_by_id(unbound)
            .await
            .unwrap()
            .unwrap();

        let served = async |host: Option<&str>| {
            ticket_target_served_on_host(&services, &unbound, host)
                .await
                .unwrap()
        };
        services
            .config
            .lock()
            .await
            .store
            .http
            .serve_unbound_http_targets = true;
        for host in [
            "vm.example.com:3000",
            "vm.example.com",
            "VM.example.com.:443",
            "shared.example.com:3000",
            "shared.example.com",
        ] {
            assert!(!served(Some(host)).await, "{host}");
        }
        for host in [Some("warp.example.com"), Some("free.example.com"), None] {
            assert!(served(host).await, "{host:?}");
        }
        services
            .config
            .lock()
            .await
            .store
            .http
            .serve_unbound_http_targets = false;
        for host in [Some("warp.example.com"), Some("free.example.com"), None] {
            assert!(!served(host).await, "{host:?}");
        }
    }

    /// A hostname serves one target whatever the port: with `vm.example.com`
    /// bound at :3000 and `app.example.com` bound without a port, a target
    /// bound to nothing is refused on the same hostname at another port, at
    /// a default port and with none, on the user path's `warpgate-target` as
    /// for a ticket; it is served elsewhere only while
    /// `http.serve_unbound_http_targets` is on.
    #[tokio::test]
    async fn an_unbound_target_is_not_served_on_a_bound_hostname_at_another_port() {
        let db = memory_db().await;
        let services = services(db.clone()).await;
        bound_target(&services, &db, "bound", "vm.example.com:3000").await;
        bound_target(&services, &db, "app", "app.example.com").await;
        services
            .config
            .lock()
            .await
            .store
            .http
            .serve_unbound_http_targets = true;

        for host in [
            "vm.example.com:4000",
            "vm.example.com",
            "VM.example.com.",
            "app.example.com:443",
        ] {
            assert!(
                !unbound_targets_served_on_host(&services, Some(host))
                    .await
                    .unwrap(),
                "user path on {host}"
            );
        }
        assert!(
            unbound_targets_served_on_host(&services, Some("other.example.com:4000"))
                .await
                .unwrap()
        );
        assert!(
            unbound_targets_served_on_host(&services, None)
                .await
                .unwrap()
        );
    }

    /// The user a real ticket session runs as in these tests.
    const TICKET_USER: Uuid = Uuid::from_u128(7);

    fn ticket(user_id: Uuid, ticket_id: Option<Uuid>, target_id: Uuid) -> RequestAuthorization {
        RequestAuthorization::Session(SessionAuthorization::Ticket {
            user_id,
            username: "ticket".into(),
            target_id,
            ticket_id,
        })
    }

    /// A ticket session with no ticket id came through the public bypass: it
    /// is registered as public and passes the public check, whatever roles it
    /// has.
    #[tokio::test]
    async fn a_ticket_session_without_a_ticket_id_is_watched_as_public() {
        let db = memory_db().await;
        let services = services(db.clone()).await;
        let target_id = public_target(&db).await;
        let (_session, close_rx) = tokio::sync::broadcast::channel(1);

        let watched = watch_admitted_live_stream(
            &services,
            &ticket(Uuid::nil(), None, target_id),
            close_rx,
            target_id,
            None,
        )
        .await;

        assert!(watched.is_ok());
        assert_eq!(
            services.live_streams.in_use().unwrap(),
            std::collections::HashSet::from([(
                Uuid::nil(),
                target_id,
                LiveStreamKind::Public,
                None
            )])
        );
    }

    /// A request admitted against a host binding the target no longer has is
    /// refused at registration, and leaves no registration behind.
    #[tokio::test]
    async fn a_registration_against_a_changed_host_binding_is_refused() {
        let db = memory_db().await;
        let services = services(db.clone()).await;
        let target_id = public_target(&db).await;
        let (_session, close_rx) = tokio::sync::broadcast::channel(1);

        let watched = watch_public_live_stream(
            &services,
            close_rx,
            Uuid::nil(),
            target_id,
            Some("old.example".into()),
        )
        .await;

        assert_eq!(
            watched.err().map(|e| e.status()),
            Some(poem::http::StatusCode::FORBIDDEN)
        );
        assert!(deregistered(&services).await);
    }

    /// A request a real ticket admitted is registered binding-only, under its
    /// own user and the binding it opened against.
    #[tokio::test]
    async fn a_real_ticket_session_is_watched_for_its_host_binding() {
        let db = memory_db().await;
        let services = services(db.clone()).await;
        let target_id = public_target(&db).await;
        let (_session, close_rx) = tokio::sync::broadcast::channel(1);

        let watched = watch_admitted_live_stream(
            &services,
            &ticket(TICKET_USER, Some(Uuid::new_v4()), target_id),
            close_rx,
            target_id,
            None,
        )
        .await;

        assert!(watched.is_ok());
        assert_eq!(
            services.live_streams.in_use().unwrap(),
            std::collections::HashSet::from([(
                TICKET_USER,
                target_id,
                LiveStreamKind::BindingOnly,
                None
            )])
        );
    }

    /// A token or a peer is registered binding-only too, under its user if it
    /// has one.
    #[tokio::test]
    async fn a_token_or_peer_request_is_watched_for_its_host_binding() {
        let db = memory_db().await;
        let services = services(db.clone()).await;
        let target_id = public_target(&db).await;
        let token_user = Uuid::new_v4();
        let mut kept = Vec::new();

        for (auth, expected_user) in [
            (
                RequestAuthorization::UserToken {
                    user_id: token_user,
                    username: "alice".into(),
                },
                token_user,
            ),
            (RequestAuthorization::AdminToken, Uuid::nil()),
            (RequestAuthorization::ClusterPeer, Uuid::nil()),
        ] {
            let (_session, close_rx) = tokio::sync::broadcast::channel(1);
            let watched =
                watch_admitted_live_stream(&services, &auth, close_rx, target_id, None).await;
            assert!(watched.is_ok());
            kept.push(watched);
            assert!(services.live_streams.in_use().unwrap().contains(&(
                expected_user,
                target_id,
                LiveStreamKind::BindingOnly,
                None
            )));
        }
    }

    /// A ticket request admitted against a host binding the target no longer
    /// has is refused at registration, and leaves no registration behind.
    #[tokio::test]
    async fn a_ticket_registration_against_a_changed_host_binding_is_refused() {
        let db = memory_db().await;
        let services = services(db.clone()).await;
        let target_id = public_target(&db).await;
        let (_session, close_rx) = tokio::sync::broadcast::channel(1);

        let watched = watch_admitted_live_stream(
            &services,
            &ticket(TICKET_USER, Some(Uuid::new_v4()), target_id),
            close_rx,
            target_id,
            Some("old.example".into()),
        )
        .await;

        assert_eq!(
            watched.err().map(|e| e.status()),
            Some(poem::http::StatusCode::FORBIDDEN)
        );
        assert!(deregistered(&services).await);
    }

    /// A user who holds a role granting the target is still refused when the
    /// binding they were admitted against is no longer the target's: the
    /// access check alone would pass them.
    #[tokio::test]
    async fn a_role_based_registration_against_a_changed_host_binding_is_refused() {
        let db = memory_db().await;
        let services = services(db.clone()).await;
        let target_id = public_target(&db).await;
        let user_id = Uuid::new_v4();
        User::ActiveModel {
            id: Set(user_id),
            username: Set(format!("user-{user_id}")),
            description: Set(String::new()),
            credential_policy: Set(serde_json::Value::Null),
            rate_limit_bytes_per_second: Set(None),
            ldap_server_id: Set(None),
            ldap_object_uuid: Set(None),
            allowed_ip_ranges: Set(serde_json::Value::Null),
        }
        .insert(&db)
        .await
        .unwrap();
        let role_id = Uuid::new_v4();
        Role::ActiveModel {
            id: Set(role_id),
            name: Set(format!("role-{role_id}")),
            description: Set(String::new()),
            is_default: Set(false),
        }
        .insert(&db)
        .await
        .unwrap();
        UserRoleAssignment::ActiveModel {
            user_id: Set(user_id),
            role_id: Set(role_id),
            granted_at: Set(Some(time::OffsetDateTime::now_utc())),
            expires_at: Set(None),
            revoked_at: Set(None),
        }
        .insert(&db)
        .await
        .unwrap();
        TargetRoleAssignment::ActiveModel {
            target_id: Set(target_id),
            role_id: Set(role_id),
        }
        .insert(&db)
        .await
        .unwrap();

        // The grant holds: the same binding is admitted.
        let (_session, close_rx) = tokio::sync::broadcast::channel(1);
        let admitted = watch_live_stream(&services, close_rx, user_id, target_id, None).await;
        assert!(admitted.is_ok());
        drop(admitted);
        assert!(deregistered(&services).await);

        // The target has no binding now; the stream was opened against one.
        let (_session, close_rx) = tokio::sync::broadcast::channel(1);
        let watched = watch_live_stream(
            &services,
            close_rx,
            user_id,
            target_id,
            Some("old.example".into()),
        )
        .await;

        assert_eq!(
            watched.err().map(|e| e.status()),
            Some(poem::http::StatusCode::FORBIDDEN)
        );
        assert!(deregistered(&services).await);
    }

    /// A logged-in user is watched by role: on a public target they have no
    /// role on, the request is refused, where the public rule would pass it.
    #[tokio::test]
    async fn a_user_session_is_watched_by_role() {
        let db = memory_db().await;
        let services = services(db.clone()).await;
        let target_id = public_target(&db).await;
        let (_session, close_rx) = tokio::sync::broadcast::channel(1);
        let auth = RequestAuthorization::Session(SessionAuthorization::User {
            user_id: Uuid::new_v4(),
            username: "alice".into(),
        });

        let watched = watch_admitted_live_stream(&services, &auth, close_rx, target_id, None).await;

        assert_eq!(
            watched.err().map(|e| e.status()),
            Some(poem::http::StatusCode::FORBIDDEN)
        );
        assert!(deregistered(&services).await);
    }
}

#[cfg(test)]
mod public_target_tests {
    //! Contract for the public-target bypass decision.
    //!
    //!   * Anonymous + public:true → Bypass (proxy through).
    //!   * Session-authed + public:true → Bypass.
    //!   * Admin/User/Cluster token + public:true → Reject401.
    //!   * public:false (default) → NotApplicable, regardless of auth.
    //!   * public:true + require_approval → NotApplicable (ordinary login).
    //!   * No host match → NotApplicable.
    //!   * Lookup is HTTP-only and port-aware.

    use uuid::Uuid;
    use warpgate_common::{HostBindingConflict, Target, TargetHTTPOptions, TargetOptions, Tls};
    use warpgate_common_http::{RequestAuthorization, SessionAuthorization};

    use super::{
        PublicTargetDecision, decide_public_target_access, find_http_target_by_external_host,
    };

    fn http_opts(public: bool, external_host: Option<&str>) -> TargetHTTPOptions {
        TargetHTTPOptions {
            url: "http://upstream:80".into(),
            tls: Tls::default(),
            headers: Default::default(),
            external_host: external_host.map(str::to_string),
            public,
            unix_socket: None,
        }
    }

    fn target_with_options(name: &str, options: TargetOptions) -> Target {
        Target {
            id: Uuid::nil(),
            name: name.into(),
            description: String::new(),
            allow_roles: vec![],
            options,
            rate_limit_bytes_per_second: None,
            group_id: None,
            ticket_max_duration_seconds: None,
            ticket_requests_disabled: false,
            ticket_require_approval: false,
            require_approval: false,
            ticket_max_uses: None,
        }
    }

    fn http_target(name: &str, public: bool, external_host: Option<&str>) -> Target {
        target_with_options(name, TargetOptions::Http(http_opts(public, external_host)))
    }

    fn user_token() -> RequestAuthorization {
        RequestAuthorization::UserToken {
            user_id: Uuid::nil(),
            username: "alice".into(),
        }
    }

    fn session_user() -> RequestAuthorization {
        RequestAuthorization::Session(SessionAuthorization::User {
            user_id: Uuid::nil(),
            username: "alice".into(),
        })
    }

    // ─── decide_public_target_access ──────────────────────────────────────

    #[test]
    fn anonymous_on_public_target_bypasses() {
        let opts = http_opts(true, Some("vm.example.com:3000"));
        assert_eq!(
            decide_public_target_access(Some(&opts), false, None),
            PublicTargetDecision::Bypass,
            "anonymous request on public target must bypass auth — this is \
             the whole point of public:true (webhook destinations).",
        );
    }

    #[test]
    fn session_user_on_public_target_bypasses() {
        let opts = http_opts(true, Some("vm.example.com:3000"));
        let auth = session_user();
        assert_eq!(
            decide_public_target_access(Some(&opts), false, Some(&auth)),
            PublicTargetDecision::Bypass,
            "session-authed user on public target also bypasses the role \
             check so the toggle is consistent regardless of who's hitting it.",
        );
    }

    #[test]
    fn admin_token_on_public_target_rejected_401() {
        let opts = http_opts(true, Some("vm.example.com:3000"));
        let auth = RequestAuthorization::AdminToken;
        assert_eq!(
            decide_public_target_access(Some(&opts), false, Some(&auth)),
            PublicTargetDecision::Reject401,
        );
    }

    /// A token on a public target is refused with 401, as on 0.28.6.
    #[test]
    fn user_token_on_public_target_rejected_401() {
        let opts = http_opts(true, Some("vm.example.com:3000"));
        let auth = user_token();
        assert_eq!(
            decide_public_target_access(Some(&opts), false, Some(&auth)),
            PublicTargetDecision::Reject401,
        );
    }

    #[test]
    fn cluster_token_on_public_target_rejected_401() {
        let opts = http_opts(true, Some("vm.example.com:3000"));
        let auth = RequestAuthorization::ClusterPeer;
        assert_eq!(
            decide_public_target_access(Some(&opts), false, Some(&auth)),
            PublicTargetDecision::Reject401,
        );
    }

    /// A target that needs admin approval is never bypassed: anonymous
    /// visitors would otherwise raise approval requests, and one approval
    /// would let every anonymous visitor in. It gets the ordinary login.
    #[test]
    fn public_target_requiring_approval_is_not_bypassed() {
        let opts = http_opts(true, Some("vm.example.com:3000"));
        for auth in [None, Some(session_user())] {
            assert_eq!(
                decide_public_target_access(Some(&opts), true, auth.as_ref()),
                PublicTargetDecision::NotApplicable,
            );
        }
    }

    /// Nothing about an earlier bypass is remembered: the decision is taken
    /// per request from the target's current options, so once `public` is
    /// turned off the very next request goes through the ordinary login.
    #[test]
    fn turning_public_off_takes_effect_on_the_next_request() {
        let on = http_opts(true, Some("vm.example.com:3000"));
        let off = http_opts(false, Some("vm.example.com:3000"));
        assert_eq!(
            decide_public_target_access(Some(&on), false, None),
            PublicTargetDecision::Bypass,
        );
        assert_eq!(
            decide_public_target_access(Some(&off), false, None),
            PublicTargetDecision::NotApplicable,
        );
    }

    #[test]
    fn private_target_default_is_not_applicable() {
        // The additive-default guarantee. With public:false (the serde
        // default) the decision MUST be NotApplicable so the existing auth
        // path runs unchanged.
        let opts = http_opts(false, Some("vm.example.com:3000"));
        for auth in [
            None,
            Some(session_user()),
            Some(user_token()),
            Some(RequestAuthorization::AdminToken),
        ] {
            assert_eq!(
                decide_public_target_access(Some(&opts), false, auth.as_ref()),
                PublicTargetDecision::NotApplicable,
                "public:false MUST never trigger the bypass — auth={auth:?}",
            );
        }
    }

    #[test]
    fn no_target_match_is_not_applicable() {
        for auth in [
            None,
            Some(session_user()),
            Some(user_token()),
            Some(RequestAuthorization::AdminToken),
        ] {
            assert_eq!(
                decide_public_target_access(None, false, auth.as_ref()),
                PublicTargetDecision::NotApplicable,
            );
        }
    }

    #[test]
    fn session_ticket_on_public_target_also_bypasses() {
        let opts = http_opts(true, Some("vm.example.com:3000"));
        let auth = RequestAuthorization::Session(SessionAuthorization::Ticket {
            user_id: Uuid::nil(),
            username: "alice".into(),
            target_id: Uuid::nil(),
            ticket_id: None,
        });
        assert_eq!(
            decide_public_target_access(Some(&opts), false, Some(&auth)),
            PublicTargetDecision::Bypass,
        );
    }

    // ─── find_http_target_by_external_host ────────────────────────────────

    #[test]
    fn finds_http_target_by_exact_host_with_port() {
        let targets = vec![
            http_target("vm-1-3000", true, Some("vm-1.example.com:3000")),
            http_target("vm-2-8080", true, Some("vm-2.example.com:8080")),
        ];
        let (t, _) = find_http_target_by_external_host(&targets, "vm-1.example.com:3000")
            .unwrap()
            .expect("must match the :3000 target");
        assert_eq!(t.name, "vm-1-3000");
        assert!(
            find_http_target_by_external_host(&targets, "vm-1.example.com:8080")
                .unwrap()
                .is_none()
        );
    }

    /// A hostname serves one target: two bindings that share it, at any port
    /// or case, are refused rather than one of them being served.
    #[test]
    fn a_hostname_shared_by_two_targets_is_refused_whatever_the_port() {
        for (first, second) in [
            ("vm-1.example.com:3000", "vm-1.example.com:8080"),
            ("vm-1.example.com:3000", "vm-1.example.com"),
            ("vm-1.example.com:3000", "VM-1.Example.com:3000"),
        ] {
            let targets = vec![
                http_target("vm-1-a", true, Some(first)),
                http_target("vm-1-b", true, Some(second)),
            ];
            assert_eq!(
                find_http_target_by_external_host(&targets, first).unwrap_err(),
                HostBindingConflict::Shared {
                    hostname: "vm-1.example.com".into(),
                    other: "vm-1-b".into(),
                },
                "{first} and {second}"
            );
        }
    }

    #[test]
    fn a_public_share_is_found_when_the_client_names_the_default_port() {
        // runcove-6gmui: a share bound to `vm-1.example.com` was missed for
        // `Host: vm-1.example.com:443`, so the client got 401, not the share.
        let targets = vec![http_target("vm-1", true, Some("vm-1.example.com"))];
        let (t, options) = find_http_target_by_external_host(&targets, "vm-1.example.com:443")
            .unwrap()
            .expect("the default port must not hide the share");
        assert_eq!(t.name, "vm-1");
        assert_eq!(
            decide_public_target_access(Some(&options), false, None),
            PublicTargetDecision::Bypass,
        );
        assert!(
            find_http_target_by_external_host(&targets, "vm-1.example.com:8443")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn returns_none_when_no_target_matches() {
        let targets = vec![http_target("vm-1", true, Some("vm-1.example.com:3000"))];
        assert!(
            find_http_target_by_external_host(&targets, "other.example.com:3000")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn skips_non_http_targets() {
        use warpgate_common::{SSHTargetAuth, TargetSSHOptions};
        let ssh_target = target_with_options(
            "ssh-collision",
            TargetOptions::Ssh(TargetSSHOptions {
                host: "vm-1.example.com".into(),
                port: 22,
                username: "root".into(),
                allow_insecure_algos: false,
                auth: SSHTargetAuth::default(),
                jump_host: None,
                env: None,
            }),
        );
        let targets = vec![ssh_target];
        assert!(
            find_http_target_by_external_host(&targets, "vm-1.example.com:3000")
                .unwrap()
                .is_none(),
            "non-HTTP targets must be skipped by the HTTP catchall lookup",
        );
    }

    #[test]
    fn ignores_targets_with_no_external_host() {
        let targets = vec![http_target("vm-1", true, None)];
        assert!(
            find_http_target_by_external_host(&targets, "vm-1.example.com:3000")
                .unwrap()
                .is_none()
        );
    }

    // ─── is_warpgate_management_path (defence-in-depth path guard) ──────

    #[test]
    fn warpgate_management_paths_are_guarded() {
        for path in [
            "/@warpgate",
            "/@warpgate/",
            "/@warpgate/admin",
            "/@warpgate/admin/index.html",
            "/@warpgate/api/openapi.json",
        ] {
            assert!(
                super::is_warpgate_management_path(path),
                "{path} must be classified as a Warpgate management path",
            );
        }
    }

    #[test]
    fn underscore_warpgate_alias_is_also_guarded() {
        assert!(super::is_warpgate_management_path("/_warpgate"));
        assert!(super::is_warpgate_management_path("/_warpgate/admin"));
    }

    #[test]
    fn ordinary_paths_are_not_management_paths() {
        for path in [
            "/",
            "/webhooks/incoming",
            "/api/v1/foo",
            "/atwarpgate",
            "/some/@warpgate/nested",
            "/_warp/something",
        ] {
            assert!(
                !super::is_warpgate_management_path(path),
                "{path} must not be classified as a management path",
            );
        }
    }
}

#[cfg(test)]
mod target_selection_tests {
    //! The order `get_target_for_request` picks a target name in, and the
    //! hosts a target selected by name may be served on.

    use uuid::Uuid;
    use warpgate_common::{Target, TargetHTTPOptions, TargetOptions, Tls};

    use super::{select_target_name, served_on_host, target_served_on_host};

    fn http_target(external_host: Option<&str>) -> Target {
        Target {
            id: Uuid::nil(),
            name: "t".into(),
            description: String::new(),
            allow_roles: vec![],
            options: TargetOptions::Http(TargetHTTPOptions {
                url: "http://upstream:80".into(),
                tls: Tls::default(),
                headers: Default::default(),
                external_host: external_host.map(str::to_string),
                public: false,
                unix_socket: None,
            }),
            rate_limit_bytes_per_second: None,
            group_id: None,
            ticket_max_duration_seconds: None,
            ticket_requests_disabled: false,
            ticket_require_approval: false,
            require_approval: false,
            ticket_max_uses: None,
        }
    }

    /// The check a ticket's target and a target selected by name both pass
    /// through.
    #[test]
    fn a_target_row_is_served_on_its_own_host_only() {
        let bound = http_target(Some("t.example"));
        for serve_unbound in [false, true] {
            assert!(target_served_on_host(
                &bound,
                Some("t.example"),
                serve_unbound
            ));
            assert!(!target_served_on_host(
                &bound,
                Some("warpgate.example"),
                serve_unbound
            ));
        }
    }

    /// A target with no hostname of its own is not served unless
    /// `http.serve_unbound_http_targets` is on; then it is served on any host.
    #[test]
    fn a_target_with_no_hostname_is_served_only_when_switched_on() {
        for unbound in [http_target(None), http_target(Some(""))] {
            for host in [Some("warpgate.example"), Some("t.example"), None] {
                assert!(!target_served_on_host(&unbound, host, false), "{host:?}");
                assert!(target_served_on_host(&unbound, host, true), "{host:?}");
            }
        }
    }

    /// Targets by name and `external_host`: `v` and `c` bound to their own
    /// hosts, `u` not bound to any.
    const TARGETS: &[(&str, Option<&str>)] = &[
        ("v", Some("v.example")),
        ("c", Some("c.example:8443")),
        ("u", None),
    ];

    /// What `get_target_for_request` serves for a request on `request_host`,
    /// over `TARGETS`: the host's own target if it has one, the selection,
    /// then whether the selected target may be served on that host.
    fn serve(query: Option<&str>, request_host: &str, session: Option<&str>) -> Option<String> {
        let host_target = TARGETS
            .iter()
            .find(|(_, host)| *host == Some(request_host))
            .map(|(name, _)| *name);
        let name = select_target_name(query, host_target, session.map(str::to_owned))?;
        let (_, external_host) = TARGETS.iter().find(|(n, _)| *n == name)?;
        served_on_host(*external_host, Some(request_host)).then_some(name)
    }

    #[test]
    fn a_bound_target_is_not_served_on_the_main_host() {
        assert_eq!(serve(Some("v"), "warpgate.example", None), None);
        assert_eq!(serve(None, "warpgate.example", Some("v")), None);
    }

    #[test]
    fn a_bound_target_is_not_served_on_another_targets_host() {
        assert_eq!(serve(Some("c"), "v.example", None), Some("v".into()));
        assert_eq!(serve(Some("c"), "x.example", None), None);
        assert_eq!(serve(None, "x.example", Some("c")), None);
    }

    #[test]
    fn a_bound_target_is_served_on_its_own_host() {
        assert_eq!(serve(Some("v"), "v.example", None), Some("v".into()));
        assert_eq!(serve(None, "v.example", None), Some("v".into()));
        assert_eq!(serve(None, "c.example:8443", Some("u")), Some("c".into()));
    }

    #[test]
    fn an_unbound_target_is_served_on_any_host() {
        assert_eq!(serve(Some("u"), "warpgate.example", None), Some("u".into()));
        assert_eq!(serve(None, "warpgate.example", Some("u")), Some("u".into()));
        assert_eq!(serve(Some("u"), "x.example", None), Some("u".into()));
    }

    #[test]
    fn the_host_must_match_the_binding_exactly() {
        // As `get_target_by_request_host` matches it: the full Host header,
        // port included (a default port is the one exception, below).
        assert!(served_on_host(
            Some("c.example:8443"),
            Some("c.example:8443")
        ));
        assert!(!served_on_host(Some("c.example:8443"), Some("c.example")));
        assert!(!served_on_host(Some("v.example"), Some("v.example:8443")));
        assert!(!served_on_host(Some("v.example"), None));
        assert!(served_on_host(None, None));
        // An empty `external_host` binds nothing.
        assert!(served_on_host(Some(""), Some("warpgate.example")));
    }

    #[test]
    fn a_default_port_in_the_host_header_still_matches_a_binding_without_one() {
        // A client may name the default port (an iOS app sends
        // `v.example:443`); it means the same host.
        assert!(served_on_host(Some("v.example"), Some("v.example:443")));
        assert!(served_on_host(Some("v.example"), Some("v.example:80")));
        // A binding that names the default port is still matched exactly, and
        // does not take requests without it.
        assert!(served_on_host(Some("v.example:443"), Some("v.example:443")));
        assert!(!served_on_host(Some("v.example:443"), Some("v.example")));
        // Only the port is dropped: another host is still another host.
        assert!(!served_on_host(Some("v.example"), Some("w.example:443")));
        assert!(!served_on_host(
            Some("v.example"),
            Some("v.example.evil:443")
        ));
    }

    #[test]
    fn only_a_default_port_is_dropped_from_the_host_header() {
        use super::host_without_default_port as strip;

        assert_eq!(strip("v.example:443"), Some("v.example"));
        assert_eq!(strip("v.example:80"), Some("v.example"));
        assert_eq!(strip("[::1]:443"), Some("[::1]"));
        assert_eq!(strip("v.example"), None);
        assert_eq!(strip("v.example:8443"), None);
        assert_eq!(strip("v.example:4430"), None);
        assert_eq!(strip("v.example:"), None);
        assert_eq!(strip(":443"), None);
        // A bare IPv6 address is not a Host header with a port.
        assert_eq!(strip("fe80::443"), None);
        assert_eq!(strip("[::1]"), None);
    }

    #[test]
    fn a_hostname_bound_target_is_not_switched_by_the_query_parameter() {
        assert_eq!(
            select_target_name(Some("b"), Some("a"), None),
            Some("a".into())
        );
        assert_eq!(
            select_target_name(Some("b"), Some("a"), Some("c".into())),
            Some("a".into())
        );
    }

    #[test]
    fn a_hostname_bound_target_honours_a_query_parameter_naming_it() {
        assert_eq!(
            select_target_name(Some("a"), Some("a"), None),
            Some("a".into())
        );
        assert_eq!(
            select_target_name(Some("a"), Some("a"), Some("c".into())),
            Some("a".into())
        );
    }

    #[test]
    fn an_unbound_host_takes_the_query_parameter() {
        assert_eq!(select_target_name(Some("b"), None, None), Some("b".into()));
        assert_eq!(
            select_target_name(Some("b"), None, Some("c".into())),
            Some("b".into())
        );
    }

    #[test]
    fn a_hostname_bound_target_wins_over_the_session() {
        assert_eq!(
            select_target_name(None, Some("a"), Some("c".into())),
            Some("a".into())
        );
    }

    #[test]
    fn an_unbound_host_falls_back_to_the_session() {
        assert_eq!(
            select_target_name(None, None, Some("c".into())),
            Some("c".into())
        );
        assert_eq!(select_target_name(None, None, None), None);
    }
}
