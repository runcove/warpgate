use std::sync::Arc;

use poem::session::Session;
use poem::web::websocket::WebSocket;
use poem::web::{Data, FromRequest, Redirect};
use poem::{Body, IntoResponse, Request, Response, handler};
use serde::Deserialize;
use tokio::sync::Mutex;
use tracing::{Instrument, debug, info_span};
use warpgate_common::auth::AuthStateUserInfo;
use warpgate_common::{Target, TargetHTTPOptions, TargetOptions, WarpgateError};
use warpgate_common_http::auth::UnauthenticatedRequestContext;
use warpgate_common_http::{
    AuthenticatedRequestContext, RequestAuthorization, SessionAuthorization, SessionKeepalive,
};
use warpgate_core::{
    ConfigProvider, TargetAuthorization, TargetSessionStart, authorize_for_target,
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

    let (handle, close_rx) = {
        let mut store = session_store.lock().await;
        let handle = store.handle_for_request(req, &unauthenticated_ctx).await?;
        let id = handle.lock().await.user_session_id();
        let close_rx = store.close_receiver_by_id(id).ok_or_else(|| {
            poem::Error::from_status(poem::http::StatusCode::INTERNAL_SERVER_ERROR)
        })?;
        (handle, close_rx)
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
    let keepalive_guard = Data::<&SessionKeepalive>::from_request_without_body(req)
        .await
        .ok()
        .map(|keepalive| keepalive.guard());

    // `session` field is UserSession, not this
    let span = info_span!("", target_session=%admitted.id(), target=%admitted.target().name);

    Ok(match ws {
        Some(ws) => proxy_websocket_request(req, ws, &ctx, admitted, close_rx)
            .instrument(span)
            .await?
            .into_response(),
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
            | RequestAuthorization::ClusterToken,
        ) => PublicTargetDecision::Reject401,
    }
}

/// Filter a candidate target list down to an HTTP target whose
/// `external_host` matches the given host header verbatim (port-aware).
///
/// Pure over `targets` so unit tests don't need a real config provider. The
/// async caller narrows the candidates first — `get_target_by_hostname` does
/// the indexed JSON-column lookup — and this helper enforces the HTTP-only
/// and exact-`external_host` half of the contract.
pub(crate) fn find_http_target_by_external_host(
    targets: &[Target],
    host: &str,
) -> Option<(Target, TargetHTTPOptions)> {
    targets
        .iter()
        .filter_map(|t| match t.options {
            TargetOptions::Http(ref options) => Some((t, options)),
            _ => None,
        })
        .find(|(_, o)| o.external_host.as_deref() == Some(host))
        .map(|(t, o)| (t.clone(), o.clone()))
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
    let candidates: Vec<Target> = services
        .config_provider
        .get_target_by_hostname(host)
        .await?
        .into_iter()
        .collect();
    let resolved = find_http_target_by_external_host(&candidates, host);
    let decision = decide_public_target_access(
        resolved.as_ref().map(|(_, o)| o),
        resolved.as_ref().is_some_and(|(t, _)| t.require_approval),
        auth,
    );
    Ok((resolved, decision))
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

    // Full Host header including `:port` — two HTTP targets may share a hostname
    // and differ only by port (per-VM proxy), and `get_target_by_hostname` matches
    // `external_host` verbatim.
    let request_host = ctx.trusted_host_header(req);

    let host_based_target = if let Some(host) = request_host {
        let found = config_provider
            .get_target_by_hostname(host.as_str())
            .await?;
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

    let selected_target_name = if let Some(warpgate_target) = params.warpgate_target {
        Some(warpgate_target)
    } else if let Some(ref rebound_target) = host_based_target {
        Some(rebound_target.name.clone())
    } else {
        session.get_target_name()
    };

    let domain_rebinding_configured = host_based_target.is_some();
    let final_target_name = selected_target_name
        .or_else(|| host_based_target.as_ref().map(|target| target.name.clone()));

    if let Some(target_name) = final_target_name {
        let target =
            if let Some(target) = host_based_target.filter(|target| target.name == target_name) {
                Some(target)
            } else {
                config_provider
                    .get_target_by_name(target_name.as_str())
                    .await?
            };

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
    use warpgate_common::{Target, TargetHTTPOptions, TargetOptions, Tls};
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
        let auth = RequestAuthorization::ClusterToken;
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
            http_target("vm-1-8080", true, Some("vm-1.example.com:8080")),
        ];
        let (t, _) = find_http_target_by_external_host(&targets, "vm-1.example.com:3000")
            .expect("must match the :3000 target, not :8080");
        assert_eq!(t.name, "vm-1-3000");
    }

    #[test]
    fn returns_none_when_no_target_matches() {
        let targets = vec![http_target("vm-1", true, Some("vm-1.example.com:3000"))];
        assert!(find_http_target_by_external_host(&targets, "other.example.com:3000").is_none());
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
            find_http_target_by_external_host(&targets, "vm-1.example.com:3000").is_none(),
            "non-HTTP targets must be skipped by the HTTP catchall lookup",
        );
    }

    #[test]
    fn ignores_targets_with_no_external_host() {
        let targets = vec![http_target("vm-1", true, None)];
        assert!(find_http_target_by_external_host(&targets, "vm-1.example.com:3000").is_none());
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
