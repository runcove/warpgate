use anyhow::Context;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use poem::session::Session;
use poem::web::Data;
use poem::{FromRequest, Request};
use poem_openapi::param::{Path, Query};
use poem_openapi::payload::{Json, PlainText, Response};
use poem_openapi::{ApiResponse, Object, OpenApi};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};
use warpgate_common::WarpgateError;
use warpgate_common_http::auth::UnauthenticatedRequestContext;
use warpgate_common_http::ext::construct_external_url;
use warpgate_core::auth::step_up::reauth_max_age;
use warpgate_sso::{Reauth, SsoClient, SsoLoginRequest, SsoReturnUrlDomainPreference};

use crate::api::sso_provider_list::is_safe_redirect_target;
use crate::common::{host_is_subdomain_of_or_equal, is_ticket_session, should_auto_sso_redirect};

pub struct Api;

#[derive(Object)]
struct StartSsoResponseParams {
    url: String,
}

#[allow(clippy::large_enum_variant)]
#[derive(ApiResponse)]
enum StartSsoResponse {
    #[oai(status = 200)]
    Ok(Json<StartSsoResponseParams>),
    #[oai(status = 404)]
    NotFound,
    /// The request originates from a domain that has no cookie domain relationship
    /// with `external_host` while `return_url_domain` is `external_host`
    #[oai(status = 400)]
    IncompatibleSsoDomain,
    /// The browser session is authorized by a ticket, which never signs in
    #[oai(status = 403)]
    TicketSession(PlainText<String>),
}

#[derive(ApiResponse)]
enum AutoStartSsoResponse {
    /// Browser redirect — either straight to the IdP authorize URL (auto-SSO
    /// enabled, exactly one provider, or `force=1` with a provider to start)
    /// or back to the gateway login SPA (otherwise, or `?login=password`).
    #[oai(status = 302)]
    Redirect,
    /// The browser session is authorized by a ticket, which never signs in
    #[oai(status = 403)]
    TicketSession(PlainText<String>),
}

/// The body of the 403 a ticket session gets from every sign-in entry point.
pub(crate) const TICKET_SESSION_REFUSAL: &str = "This session was opened with a ticket and cannot sign in. Sign out, then sign in with single sign-on.";

/// The 403 a ticket session gets from an SSO start outside the OpenAPI
/// handlers (the page auto-redirect).
pub(crate) fn ticket_session_refusal() -> poem::Response {
    poem::Response::builder()
        .status(poem::http::StatusCode::FORBIDDEN)
        .content_type("text/plain; charset=utf-8")
        .body(TICKET_SESSION_REFUSAL)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SsoContext {
    pub provider: String,
    pub request: SsoLoginRequest,
    pub next_url: Option<String>,
    pub supports_single_logout: bool,
    /// Origin the identity provider will return the browser to, taken from the
    /// return URL rather than from the request, so it carries the same
    /// `return_domain_whitelist` validation. The post-login redirect is
    /// resolved against it.
    pub return_origin: String,
}

/// Outcome of [`start_sso_and_get_auth_url`]. Mirrors the arms of
/// [`StartSsoResponse`] so both the OpenAPI handler and the auto-redirect
/// path in `common::page_auth` can share the login-initiation machinery.
pub(crate) enum StartSsoOutcome {
    /// Provider found; SSO handshake stashed in the request store. Carries the
    /// IdP authorize URL to redirect the browser to.
    Ok(String),
    /// No SSO provider with the given name is configured.
    NotFound,
    /// The request host has no cookie-domain relationship with `external_host`
    /// while the provider prefers `external_host` for its return URL.
    IncompatibleSsoDomain,
    /// The browser session is authorized by a ticket. Nothing was stored;
    /// every caller answers 403, none falls through to a login page.
    TicketSession,
}

/// Begin an SSO login for `provider_name`: build the return URL, ask the IdP
/// client for an authorize URL, and stash the resulting [`SsoContext`] in the
/// [`crate::sso_request_store::SsoRequestStore`], keyed by the OAuth `state`,
/// so `sso/return` can complete the
/// handshake. Extracted from `api_start_sso` so the unauthenticated
/// auto-redirect path can reuse it. Locks `config` internally — callers must
/// NOT hold the config lock.
pub(crate) async fn start_sso_and_get_auth_url(
    req: &Request,
    // The handshake lives in the SsoRequestStore, not the Poem session; the
    // session is read only for its authorization.
    session: &Session,
    ctx: &UnauthenticatedRequestContext,
    provider_name: &str,
    next: Option<String>,
    // Demand a fresh login at the provider (`prompt=login`, `max_age=0`).
    force: bool,
) -> Result<StartSsoOutcome, WarpgateError> {
    // A ticket session never becomes a user session, so it never starts one.
    if is_ticket_session(session) {
        warn!("SSO start refused: the browser session is authorized by a ticket");
        return Ok(StartSsoOutcome::TicketSession);
    }

    let config = ctx.services().config.lock().await;

    let Some(provider_config) = config
        .store
        .sso_providers
        .iter()
        .find(|p| p.name == *provider_name)
    else {
        warn!(provider = %provider_name, "SSO login requested for a provider that is not configured");
        return Ok(StartSsoOutcome::NotFound);
    };

    if matches!(
        provider_config.return_url_domain,
        SsoReturnUrlDomainPreference::ExternalHost
    ) && let (Some(request_host), Some(external_host)) =
        (ctx.trusted_hostname(req), config.external_host_name())
        && !host_is_subdomain_of_or_equal(&request_host, &external_host)
    {
        warn!(
            %request_host,
            %external_host,
            provider = %provider_name,
            "SSO login refused: this provider returns to `external_host`, and the host the browser used is neither that host nor a subdomain of it. Point `external_host` at the hostname users open Warpgate on, or set `return_url_domain: host_header` on the provider."
        );
        return Ok(StartSsoOutcome::IncompatibleSsoDomain);
    }

    let mut return_url = construct_external_url(
        match provider_config.return_url_domain {
            // Let `construct_external_url` fall back to config file
            SsoReturnUrlDomainPreference::ExternalHost => None,
            SsoReturnUrlDomainPreference::HostHeader => Some(req),
        },
        &config,
        provider_config.return_domain_whitelist.as_deref(),
    )
    .await?;
    return_url.set_path(&format!(
        "{}warpgate/api/sso/return",
        provider_config.return_url_prefix
    ));
    debug!("Return URL: {return_url}");

    // The post-login redirect lands on the host the user started from, which
    // in `external_host` mode is not the return URL's host — the IdP callback
    // goes to the parent domain there and hands off via the shared cookie.
    // Built through `construct_external_url` so the authority is parsed
    // rather than interpolated from the raw `Host` header. No whitelist is
    // passed because this host has already been checked: `external_host` mode
    // by the `IncompatibleSsoDomain` guard above, `host_header` mode by the
    // return URL, which is this same host.
    let return_origin = construct_external_url(Some(req), &config, None)
        .await?
        .origin()
        .ascii_serialization();

    // Read under the lock, which is dropped below.
    let reauth = if force {
        Reauth::Force
    } else {
        config
            .store
            .step_up_interval
            .as_ref()
            .and_then(|s| s.http)
            .map_or(Reauth::None, |interval| {
                Reauth::MaxAge(reauth_max_age(interval))
            })
    };

    let client = SsoClient::new(provider_config.provider.clone())?;

    // Release the global `config` lock before the IdP network round-trip
    // (`start_login`) and `session_id_for_login` (which locks the SessionStore).
    // Both the SSH and HTTP front-ends take this same lock per connection, so
    // holding it across these awaits serializes the whole gateway and wedges it
    // under concurrent SSO load — new SSH handshakes and HTTP requests block on
    // `config` while a single login is mid-flight against the IdP.
    drop(config);

    let sso_req = client.start_login(return_url.to_string(), reauth).await?;

    let url = sso_req.auth_url().to_string();
    // The OAuth `state` (CSRF token) the IdP echoes back on the callback — the
    // key under which `/sso/return` retrieves this handshake.
    let state = sso_req.csrf_token().secret().clone();
    let supports_single_logout = client.supports_single_logout().await?;
    let context = SsoContext {
        provider: provider_name.to_owned(),
        request: sso_req,
        next_url: next,
        supports_single_logout,
        return_origin,
    };

    // Stash the handshake in the SsoRequestStore keyed by `state` and bound to
    // the initiating session — NOT in the Poem session, whose single
    // read-modify-write blob is clobbered by concurrent requests that share the
    // cross-subdomain cookie (the auto-SSO redirect, other subdomain tabs, the
    // SPA's auth-state polls). See `crate::sso_request_store`.
    let session_id = crate::common::session_id_for_login(req, ctx).await?;
    let sso_store =
        Data::<&crate::sso_request_store::SsoRequestStore<SsoContext>>::from_request_without_body(
            req,
        )
        .await
        .context("SsoRequestStore not in request")?;
    sso_store.insert(state, context, session_id).await;

    Ok(StartSsoOutcome::Ok(url))
}

#[OpenApi]
impl Api {
    #[oai(
        path = "/sso/providers/:name/start",
        method = "get",
        operation_id = "start_sso"
    )]
    async fn api_start_sso(
        &self,
        req: &Request,
        session: &Session,
        ctx: Data<&UnauthenticatedRequestContext>,
        name: Path<String>,
        next: Query<Option<String>>,
    ) -> Result<StartSsoResponse, WarpgateError> {
        match start_sso_and_get_auth_url(req, session, ctx.0, &name.0, next.0, false).await? {
            StartSsoOutcome::Ok(url) => {
                Ok(StartSsoResponse::Ok(Json(StartSsoResponseParams { url })))
            }
            StartSsoOutcome::NotFound => Ok(StartSsoResponse::NotFound),
            StartSsoOutcome::IncompatibleSsoDomain => Ok(StartSsoResponse::IncompatibleSsoDomain),
            StartSsoOutcome::TicketSession => Ok(StartSsoResponse::TicketSession(PlainText(
                TICKET_SESSION_REFUSAL.into(),
            ))),
        }
    }

    /// Server-side auto-SSO entry point.
    ///
    /// A front door that gates its own traffic and rides a `public` HTTP target
    /// (so Warpgate's own `page_auth` auto-redirect never sees the request)
    /// redirects unauthenticated browser navigations here instead of straight
    /// to the gateway login SPA. When the operator has opted into
    /// single-provider auto-redirect, this 302s directly to the IdP authorize
    /// URL — no SPA render, no button click. Otherwise (feature off, not
    /// exactly one provider, a provider/host mismatch, or the
    /// `?login=password` break-glass) it 302s to the normal gateway login page,
    /// preserving `next`.
    ///
    /// `force=1` always starts SSO, whether or not auto-redirect is on and
    /// whether or not the browser is already signed in: with the provider
    /// named in `provider`, or the sole one when exactly one is configured.
    /// An unknown provider, or none named among several, gets the login page.
    /// `?login=password` still wins.
    ///
    /// A session authorized by a ticket gets 403: it never signs in.
    ///
    /// Unauthenticated by design (mirrors `/sso/providers` + `/sso/*/start`):
    /// it only ever *initiates* a login, and the resulting `next` is validated
    /// against [`is_safe_redirect_target`] before use.
    #[oai(
        path = "/sso/auto-start",
        method = "get",
        operation_id = "auto_start_sso"
    )]
    #[allow(clippy::too_many_arguments)]
    async fn api_auto_start_sso(
        &self,
        req: &Request,
        session: &Session,
        ctx: Data<&UnauthenticatedRequestContext>,
        next: Query<Option<String>>,
        login: Query<Option<String>>,
        force: Query<Option<String>>,
        provider: Query<Option<String>>,
    ) -> Result<Response<AutoStartSsoResponse>, WarpgateError> {
        // Drop an unsafe `next` (javascript:, //host, ...) rather than propagate
        // it into either redirect target.
        let next = next.0.filter(|n| is_safe_redirect_target(n));
        let has_password_bypass = login.0.as_deref() == Some("password");
        let force = force.0.as_deref() == Some("1");

        // Read the toggle + provider set, then decide. Mirrors
        // `common::try_auto_sso_redirect`, but for the public-target front door.
        let chosen_provider = {
            let enabled = ctx.parameters().await?.sso_auto_redirect;
            let config = ctx.services().config.lock().await;
            let providers: Vec<&str> = config
                .store
                .sso_providers
                .iter()
                .map(|p| p.name.as_str())
                .collect();
            auto_start_provider(
                &providers,
                enabled,
                has_password_bypass,
                force,
                provider.0.as_deref(),
            )
        };

        if let Some(provider_name) = chosen_provider {
            match start_sso_and_get_auth_url(
                req,
                session,
                ctx.0,
                &provider_name,
                next.clone(),
                force,
            )
            .await?
            {
                StartSsoOutcome::Ok(url) => {
                    return Ok(
                        Response::new(AutoStartSsoResponse::Redirect).header("Location", url)
                    );
                }
                StartSsoOutcome::TicketSession => {
                    return Ok(Response::new(AutoStartSsoResponse::TicketSession(
                        PlainText(TICKET_SESSION_REFUSAL.into()),
                    )));
                }
                StartSsoOutcome::NotFound | StartSsoOutcome::IncompatibleSsoDomain => {}
            }
        } else if is_ticket_session(session) {
            // Refused here too, rather than sent on to a login page where a
            // sign-in would be refused anyway.
            return Ok(Response::new(AutoStartSsoResponse::TicketSession(
                PlainText(TICKET_SESSION_REFUSAL.into()),
            )));
        }

        // Fallback: gateway login SPA, preserving `next` and the break-glass.
        let url = login_spa_fallback_url(next.as_deref(), has_password_bypass);
        Ok(Response::new(AutoStartSsoResponse::Redirect).header("Location", url))
    }
}

/// The provider [`Api::api_auto_start_sso`] starts, or `None` for the login
/// page. `?login=password` always gets the login page. Without `force`, the
/// sole provider when auto-redirect is on. With `force`, the named provider if
/// it is configured, else (none named) the sole one; an unknown name, or none
/// named among several, gets the login page.
fn auto_start_provider(
    providers: &[&str],
    auto_redirect_enabled: bool,
    has_password_bypass: bool,
    force: bool,
    requested: Option<&str>,
) -> Option<String> {
    if has_password_bypass {
        return None;
    }
    if !force {
        return should_auto_sso_redirect(
            auto_redirect_enabled,
            providers.len(),
            true,  // only reached as a top-level browser navigation
            false, // break-glass handled above
            false, // dedicated endpoint, not a management-path proxy hit
        )
        .then(|| providers.first().map(|p| (*p).to_owned()))
        .flatten();
    }
    match requested {
        Some(name) => providers
            .iter()
            .find(|p| **p == name)
            .map(|p| (*p).to_owned()),
        None => match providers {
            [only] => Some((*only).to_owned()),
            _ => None,
        },
    }
}

/// Build the gateway-login-SPA fallback URL for [`Api::api_auto_start_sso`],
/// preserving `next` (percent-encoded) and re-emitting the `?login=password`
/// break-glass. The re-emit is load-bearing: when auto-SSO is enabled with a
/// single provider, the SPA's own on-load auto-start (`Login.svelte`) would
/// otherwise immediately bounce the operator back to the IdP — so dropping the
/// break-glass here silently neuters it. `#` fragment routing matches what
/// `common::gateway_redirect` emits. Pure so the round-trip is unit-testable
/// without a `Services` fixture.
fn login_spa_fallback_url(next: Option<&str>, has_password_bypass: bool) -> String {
    let mut url = match next {
        Some(n) => format!(
            "/@warpgate#/login?next={}",
            utf8_percent_encode(n, NON_ALPHANUMERIC)
        ),
        None => "/@warpgate#/login".to_owned(),
    };
    if has_password_bypass {
        url.push_str(if url.contains('?') {
            "&login=password"
        } else {
            "?login=password"
        });
    }
    url
}

#[cfg(test)]
mod tests {
    use super::login_spa_fallback_url;

    #[test]
    fn fallback_url_preserves_next_and_reemits_break_glass() {
        // No break-glass: encoded next, no login param.
        let u = login_spa_fallback_url(Some("/vms"), false);
        assert_eq!(u, "/@warpgate#/login?next=%2Fvms");
        assert!(!u.contains("login=password"));

        // Break-glass with a next → appended as an extra query param.
        let u = login_spa_fallback_url(Some("/vms"), true);
        assert!(u.starts_with("/@warpgate#/login?next=%2Fvms"), "got: {u}");
        assert!(u.ends_with("&login=password"), "got: {u}");

        // Break-glass with no next → starts the query string.
        assert_eq!(
            login_spa_fallback_url(None, true),
            "/@warpgate#/login?login=password"
        );

        // No next, no break-glass → bare login route.
        assert_eq!(login_spa_fallback_url(None, false), "/@warpgate#/login");
    }
}

#[cfg(test)]
mod auto_start_tests {
    use super::auto_start_provider;

    #[test]
    fn without_force_only_the_sole_provider_with_auto_redirect_on_starts() {
        assert_eq!(
            auto_start_provider(&["idp"], true, false, false, None).as_deref(),
            Some("idp")
        );
        assert_eq!(
            auto_start_provider(&["idp"], false, false, false, None),
            None
        );
        assert_eq!(
            auto_start_provider(&["a", "b"], true, false, false, None),
            None
        );
        // `provider` means nothing without `force`.
        assert_eq!(
            auto_start_provider(&["a", "b"], false, false, false, Some("a")),
            None
        );
    }

    #[test]
    fn force_starts_the_named_or_sole_provider_whatever_auto_redirect_says() {
        assert_eq!(
            auto_start_provider(&["a", "b"], false, false, true, Some("b")).as_deref(),
            Some("b")
        );
        assert_eq!(
            auto_start_provider(&["idp"], false, false, true, None).as_deref(),
            Some("idp")
        );
    }

    #[test]
    fn force_with_an_unknown_provider_or_none_named_among_several_gets_the_login_page() {
        assert_eq!(
            auto_start_provider(&["a", "b"], true, false, true, Some("c")),
            None
        );
        assert_eq!(
            auto_start_provider(&["a", "b"], true, false, true, None),
            None
        );
        assert_eq!(auto_start_provider(&[], true, false, true, None), None);
        // Names are compared exactly.
        assert_eq!(
            auto_start_provider(&["idp"], true, false, true, Some("IDP")),
            None
        );
    }

    #[test]
    fn the_password_break_glass_wins_over_force() {
        assert_eq!(
            auto_start_provider(&["idp"], true, true, true, Some("idp")),
            None
        );
        assert_eq!(auto_start_provider(&["idp"], true, true, false, None), None);
    }
}

/// The SSO entry points against a stand-in identity provider: `force=1`
/// starts SSO for a signed-in browser, and a ticket session gets 403 at the
/// start and at the return, with nothing stored and its authorization kept.
#[cfg(test)]
mod ticket_session_tests {
    use std::sync::Arc;

    use poem::http::StatusCode;
    use poem::session::{ServerSession, Session};
    use poem::test::{TestClient, TestResponse};
    use poem::web::Data;
    use poem::{Endpoint, EndpointExt, Request, Route, get, handler};
    use poem_openapi::OpenApiService;
    use tokio::sync::Mutex;
    use uuid::Uuid;
    use warpgate_common::auth::AuthStateUserInfo;
    use warpgate_common_http::SessionAuthorization;
    use warpgate_common_http::auth::UnauthenticatedRequestContext;
    use warpgate_sso::SsoProviderConfig;

    use crate::common::{SessionExt, session_cookie_config};
    use crate::session::SessionStore;
    use crate::session_storage::SharedSessionStorage;
    use crate::sso_request_store::SsoRequestStore;
    use crate::test_db::{insert_user, memory_db, services};

    const HOST: &str = "warpgate.test";
    const ALICE: Uuid = Uuid::from_u128(0xa11ce);

    /// An identity provider that serves only its discovery document and an
    /// empty key set: enough for a login to start, never to finish.
    async fn stand_in_idp() -> String {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        let discovery = serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
            "jwks_uri": format!("{issuer}/jwks"),
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        });
        let app = Route::new()
            .at(
                "/.well-known/openid-configuration",
                get(poem::endpoint::make_sync(move |_| {
                    poem::web::Json(discovery.clone())
                })),
            )
            .at(
                "/jwks",
                get(poem::endpoint::make_sync(|_| {
                    poem::web::Json(serde_json::json!({"keys": []}))
                })),
            );
        let acceptor = poem::listener::TcpAcceptor::from_tokio(listener).unwrap();
        tokio::spawn(poem::Server::new_with_acceptor(acceptor).run(app));
        issuer
    }

    fn provider(name: &str, issuer: &str) -> SsoProviderConfig {
        serde_json::from_value(serde_json::json!({
            "name": name,
            "provider": {
                "type": "custom",
                "client_id": "client",
                "client_secret": "unused",
                "issuer_url": issuer,
                "scopes": [],
                "role_mappings": null,
                "admin_role_mappings": null,
                "roles_claim": null,
                "admin_roles_claim": null,
            },
            "return_domain_whitelist": null,
        }))
        .unwrap()
    }

    /// Signs the browser in as alice, as a completed login leaves it.
    #[handler]
    async fn as_user(
        req: &Request,
        session: &Session,
        store: Data<&Arc<Mutex<SessionStore>>>,
        ctx: Data<&UnauthenticatedRequestContext>,
    ) -> poem::Result<()> {
        let handle = store.lock().await.handle_for_request(req, ctx.0).await?;
        handle
            .lock()
            .await
            .set_user_info(AuthStateUserInfo {
                id: ALICE,
                username: "alice".into(),
            })
            .await?;
        session.set_auth(SessionAuthorization::User {
            user_id: ALICE,
            username: "alice".into(),
        });
        Ok(())
    }

    /// Marks the browser session as opened with a ticket, as the ticket
    /// middleware leaves it.
    #[handler]
    fn as_ticket(session: &Session) {
        session.set_auth(SessionAuthorization::Ticket {
            user_id: ALICE,
            username: "alice".into(),
            target_id: Uuid::from_u128(7),
            ticket_id: Some(Uuid::from_u128(8)),
        });
    }

    #[handler]
    fn auth_kind(session: &Session) -> &'static str {
        match session.get_auth() {
            Some(SessionAuthorization::User { .. }) => "user",
            Some(SessionAuthorization::Ticket { .. }) => "ticket",
            None => "none",
        }
    }

    #[handler]
    fn stamp(session: &Session) -> String {
        use crate::step_up::StepUpSessionExt;
        session
            .get_last_sso_at()
            .map_or_else(|| "none".into(), |at| at.unix_timestamp().to_string())
    }

    async fn app(providers: Vec<SsoProviderConfig>) -> (impl Endpoint, SsoRequestStore) {
        app_with(providers, None).await
    }

    async fn app_with(
        providers: Vec<SsoProviderConfig>,
        step_up_http: Option<std::time::Duration>,
    ) -> (impl Endpoint, SsoRequestStore) {
        use sea_orm::ActiveModelTrait;
        use sea_orm::ActiveValue::Set;

        let db = memory_db().await;
        insert_user(&db, ALICE, "alice").await;
        // The e-mail the stand-in provider's ID tokens carry.
        warpgate_db_entities::SsoCredential::ActiveModel {
            id: Set(Uuid::from_u128(0xc0de)),
            user_id: Set(ALICE),
            provider: Set(None),
            email: Set("alice@example.test".into()),
        }
        .insert(&db)
        .await
        .unwrap();
        let services = services(db.clone()).await;
        {
            let mut config = services.config.lock().await;
            config.store.external_host = Some(HOST.into());
            config.store.sso_providers = providers;
            if let Some(http) = step_up_http {
                config.store.step_up_interval = Some(warpgate_common::StepUpIntervalConfig {
                    http: Some(http),
                    ..Default::default()
                });
            }
        }
        let ctx = UnauthenticatedRequestContext::new(services).await;
        let storage = SharedSessionStorage::new(db);
        let sso_store = SsoRequestStore::new();
        let api = OpenApiService::new(
            (super::Api, crate::api::sso_provider_list::Api),
            "test",
            "0",
        );
        let app = Route::new()
            .nest("/api", api)
            .at("/as-user", get(as_user))
            .at("/as-ticket", get(as_ticket))
            .at("/kind", get(auth_kind))
            .at("/stamp", get(stamp))
            .data(SessionStore::new())
            .data(ctx)
            .data(sso_store.clone())
            .data(storage.clone())
            .with(ServerSession::new(session_cookie_config(), storage));
        (app, sso_store)
    }

    /// The cookie a response set, if it set one, else `previous`.
    fn cookie_after(resp: &TestResponse, previous: Option<String>) -> Option<String> {
        resp.0
            .headers()
            .get("set-cookie")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .map(ToOwned::to_owned)
            .or(previous)
    }

    async fn fetch<E: Endpoint>(
        cli: &TestClient<E>,
        cookie: &mut Option<String>,
        path: &str,
    ) -> TestResponse {
        let mut req = cli.get(path).header("host", HOST);
        if let Some(cookie) = cookie.as_deref() {
            req = req.header("cookie", cookie);
        }
        let resp = req.send().await;
        *cookie = cookie_after(&resp, cookie.take());
        resp
    }

    fn location(resp: &TestResponse) -> String {
        resp.0
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned()
    }

    #[tokio::test]
    async fn force_starts_sso_for_a_signed_in_browser_with_auto_redirect_off() {
        let issuer = stand_in_idp().await;
        let (app, sso_store) = app(vec![provider("idp", &issuer)]).await;
        let cli = TestClient::new(app);
        let mut cookie = None;
        fetch(&cli, &mut cookie, "/as-user")
            .await
            .assert_status_is_ok();
        fetch(&cli, &mut cookie, "/kind")
            .await
            .assert_text("user")
            .await;

        // Control: without the flag, auto-redirect being off, the login page.
        let resp = fetch(&cli, &mut cookie, "/api/sso/auto-start?next=/vms").await;
        resp.assert_status(StatusCode::FOUND);
        assert_eq!(location(&resp), "/@warpgate#/login?next=%2Fvms");

        let resp = fetch(&cli, &mut cookie, "/api/sso/auto-start?force=1&next=/vms").await;
        resp.assert_status(StatusCode::FOUND);
        assert!(
            location(&resp).starts_with(&format!("{issuer}/authorize?")),
            "{}",
            location(&resp)
        );
        assert_eq!(sso_store.len().await, 1);
    }

    #[tokio::test]
    async fn force_with_a_named_provider_starts_that_one() {
        let issuer = stand_in_idp().await;
        let (app, _) = app(vec![provider("a", &issuer), provider("b", &issuer)]).await;
        let cli = TestClient::new(app);
        let mut cookie = None;

        let resp = fetch(&cli, &mut cookie, "/api/sso/auto-start?force=1").await;
        assert_eq!(location(&resp), "/@warpgate#/login", "several, none named");

        let resp = fetch(&cli, &mut cookie, "/api/sso/auto-start?force=1&provider=b").await;
        resp.assert_status(StatusCode::FOUND);
        assert!(location(&resp).starts_with(&format!("{issuer}/authorize?")));
    }

    #[tokio::test]
    async fn force_with_an_unknown_provider_gets_the_login_page_and_drops_an_unsafe_next() {
        let issuer = stand_in_idp().await;
        let (app, sso_store) = app(vec![provider("idp", &issuer)]).await;
        let cli = TestClient::new(app);
        let mut cookie = None;

        let resp = fetch(
            &cli,
            &mut cookie,
            "/api/sso/auto-start?force=1&provider=nope&next=/vms",
        )
        .await;
        resp.assert_status(StatusCode::FOUND);
        assert_eq!(location(&resp), "/@warpgate#/login?next=%2Fvms");

        for unsafe_next in [
            "//evil.example/x",
            "https://evil.example/",
            "/\\evil.example",
        ] {
            let path = format!(
                "/api/sso/auto-start?force=1&provider=nope&next={}",
                utf8_percent_encode_all(unsafe_next)
            );
            let resp = fetch(&cli, &mut cookie, &path).await;
            resp.assert_status(StatusCode::FOUND);
            assert_eq!(location(&resp), "/@warpgate#/login", "{unsafe_next}");
        }
        assert_eq!(sso_store.len().await, 0);
    }

    fn utf8_percent_encode_all(s: &str) -> String {
        percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC).to_string()
    }

    #[tokio::test]
    async fn a_ticket_session_gets_403_at_every_sso_start_and_nothing_is_stored() {
        let issuer = stand_in_idp().await;
        let (app, sso_store) = app(vec![provider("idp", &issuer)]).await;
        let cli = TestClient::new(app);
        let mut cookie = None;
        fetch(&cli, &mut cookie, "/as-ticket")
            .await
            .assert_status_is_ok();

        for path in [
            "/api/sso/auto-start?force=1",
            "/api/sso/auto-start?force=1&provider=idp",
            "/api/sso/auto-start",
            "/api/sso/providers/idp/start",
        ] {
            let resp = fetch(&cli, &mut cookie, path).await;
            resp.assert_status(StatusCode::FORBIDDEN);
            assert_eq!(location(&resp), "", "{path}");
        }
        assert_eq!(sso_store.len().await, 0);
        fetch(&cli, &mut cookie, "/kind")
            .await
            .assert_text("ticket")
            .await;
    }

    #[tokio::test]
    async fn a_ticket_session_with_a_pending_handshake_gets_403_at_the_return_and_stays_a_ticket() {
        let issuer = stand_in_idp().await;
        let (app, sso_store) = app(vec![provider("idp", &issuer)]).await;
        let cli = TestClient::new(app);
        let mut cookie = None;

        // The handshake starts on an anonymous session...
        let resp = fetch(&cli, &mut cookie, "/api/sso/auto-start?force=1").await;
        resp.assert_status(StatusCode::FOUND);
        let authorize = url::Url::parse(&location(&resp)).unwrap();
        let state = authorize
            .query_pairs()
            .find(|(k, _)| k == "state")
            .map(|(_, v)| v.into_owned())
            .unwrap();
        assert_eq!(sso_store.len().await, 1);

        // ...which a ticket then authorizes.
        fetch(&cli, &mut cookie, "/as-ticket")
            .await
            .assert_status_is_ok();

        let resp = fetch(
            &cli,
            &mut cookie,
            &format!("/api/sso/return?code=anything&state={state}"),
        )
        .await;
        resp.assert_status(StatusCode::FORBIDDEN);
        fetch(&cli, &mut cookie, "/kind")
            .await
            .assert_text("ticket")
            .await;
    }

    // ---- the return path against an identity provider that signs ID tokens ----

    use std::sync::Mutex as StdMutex;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    fn unix_now() -> i64 {
        i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap()
    }

    /// A provider whose token endpoint hands back whatever ID token the test
    /// last put in the slot, signed with a fresh P-256 key it publishes.
    struct SigningIdp {
        issuer: String,
        slot: Arc<StdMutex<String>>,
        key: jsonwebtoken::EncodingKey,
    }

    #[handler]
    fn token_endpoint(slot: Data<&Arc<StdMutex<String>>>) -> poem::web::Json<serde_json::Value> {
        poem::web::Json(serde_json::json!({
            "access_token": "access",
            "token_type": "bearer",
            "id_token": slot.0.lock().unwrap().clone(),
        }))
    }

    async fn signing_idp() -> SigningIdp {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        // An uncompressed SEC1 point: 0x04, then x, then y.
        let point = key_pair.public_key_raw();
        let coordinate = |range| data_encoding::BASE64URL_NOPAD.encode(point.get(range).unwrap());
        let jwks = serde_json::json!({ "keys": [{
            "kty": "EC", "crv": "P-256", "kid": "k1", "use": "sig",
            "x": coordinate(1..33), "y": coordinate(33..65),
        }]});
        let key =
            jsonwebtoken::EncodingKey::from_ec_pem(key_pair.serialize_pem().as_bytes()).unwrap();
        let discovery = serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
            "jwks_uri": format!("{issuer}/jwks"),
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["ES256"],
        });
        let slot = Arc::new(StdMutex::new(String::new()));
        let app = Route::new()
            .at(
                "/.well-known/openid-configuration",
                get(poem::endpoint::make_sync(move |_| {
                    poem::web::Json(discovery.clone())
                })),
            )
            .at(
                "/jwks",
                get(poem::endpoint::make_sync(move |_| {
                    poem::web::Json(jwks.clone())
                })),
            )
            .at("/token", poem::post(token_endpoint))
            .data(slot.clone());
        let acceptor = poem::listener::TcpAcceptor::from_tokio(listener).unwrap();
        tokio::spawn(poem::Server::new_with_acceptor(acceptor).run(app));
        SigningIdp { issuer, slot, key }
    }

    impl SigningIdp {
        /// Makes the token endpoint answer with an ID token for `nonce`.
        fn issue(&self, nonce: &str, auth_time: Option<i64>) {
            self.issue_raw(nonce, auth_time.map(serde_json::Value::from));
        }

        /// As `issue`, with the `auth_time` claim given as raw JSON so a
        /// malformed one can be sent.
        fn issue_raw(&self, nonce: &str, auth_time: Option<serde_json::Value>) {
            let now = unix_now();
            let mut claims = serde_json::json!({
                "iss": self.issuer,
                "sub": "alice-sub",
                "aud": "client",
                "iat": now,
                "exp": now + 300,
                "nonce": nonce,
                "email": "alice@example.test",
                "email_verified": true,
                "preferred_username": "alice",
            });
            if let Some(auth_time) = auth_time {
                claims["auth_time"] = auth_time;
            }
            let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
            header.kid = Some("k1".into());
            *self.slot.lock().unwrap() = jsonwebtoken::encode(&header, &claims, &self.key).unwrap();
        }
    }

    /// One browser against the app and the signing provider.
    struct Browser<E> {
        cli: TestClient<E>,
        cookie: Option<String>,
        idp: SigningIdp,
    }

    struct Started {
        state: String,
        nonce: String,
        query: std::collections::HashMap<String, String>,
    }

    async fn browser(step_up_http: Option<Duration>) -> Browser<impl Endpoint> {
        let idp = signing_idp().await;
        let (app, _) = app_with(vec![provider("idp", &idp.issuer)], step_up_http).await;
        Browser {
            cli: TestClient::new(app),
            cookie: None,
            idp,
        }
    }

    impl<E: Endpoint> Browser<E> {
        async fn get(&mut self, path: &str) -> TestResponse {
            fetch(&self.cli, &mut self.cookie, path).await
        }

        /// Starts a login through `path` and reads the authorize URL it sends
        /// the browser to.
        async fn start(&mut self, path: &str) -> Started {
            let resp = self.get(path).await;
            let url = if resp.0.status() == StatusCode::FOUND {
                location(&resp)
            } else {
                resp.assert_status_is_ok();
                let body = resp.json().await;
                body.value().object().get("url").string().to_owned()
            };
            let query: std::collections::HashMap<String, String> = url::Url::parse(&url)
                .unwrap()
                .query_pairs()
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect();
            Started {
                state: query["state"].clone(),
                nonce: query["nonce"].clone(),
                query,
            }
        }

        /// Returns from the provider on `started`, with an ID token for
        /// `nonce` carrying `auth_time`.
        async fn finish(&mut self, started: &Started, nonce: &str, auth_time: Option<i64>) {
            self.idp.issue(nonce, auth_time);
            self.get(&format!(
                "/api/sso/return?code=code&state={}",
                started.state
            ))
            .await;
        }

        /// As `finish`, with `auth_time` as raw JSON.
        async fn finish_raw(
            &mut self,
            started: &Started,
            nonce: &str,
            auth_time: Option<serde_json::Value>,
        ) {
            self.idp.issue_raw(nonce, auth_time);
            self.get(&format!(
                "/api/sso/return?code=code&state={}",
                started.state
            ))
            .await;
        }

        async fn stamp(&mut self) -> String {
            let resp = self.get("/stamp").await;
            resp.0.into_body().into_string().await.unwrap()
        }

        async fn kind(&mut self) -> String {
            let resp = self.get("/kind").await;
            resp.0.into_body().into_string().await.unwrap()
        }
    }

    const FORCE_START: &str = "/api/sso/auto-start?force=1";
    const PLAIN_START: &str = "/api/sso/providers/idp/start";

    #[tokio::test]
    async fn force_sends_prompt_login_and_max_age_zero_even_with_step_up_set() {
        for interval in [None, Some(Duration::from_secs(3600))] {
            let mut b = browser(interval).await;
            let started = b.start(FORCE_START).await;
            assert_eq!(started.query["prompt"], "login");
            assert_eq!(started.query["max_age"], "0");
        }
    }

    #[tokio::test]
    async fn a_plain_start_sends_the_step_up_interval_less_its_margin_as_max_age_only_when_set() {
        let mut b = browser(Some(Duration::from_secs(3600))).await;
        let started = b.start(PLAIN_START).await;
        // 3600 s less a quarter of it.
        assert_eq!(started.query["max_age"], "2700");
        assert!(!started.query.contains_key("prompt"));

        let mut b = browser(None).await;
        let started = b.start(PLAIN_START).await;
        assert!(!started.query.contains_key("max_age"));
        assert!(!started.query.contains_key("prompt"));
    }

    #[tokio::test]
    async fn a_fresh_auth_time_stamps_the_session_with_that_time() {
        let mut b = browser(None).await;
        let started = b.start(PLAIN_START).await;
        let auth_time = unix_now() - 45;
        b.finish(&started, &started.nonce, Some(auth_time)).await;
        assert_eq!(b.kind().await, "user");
        assert_eq!(b.stamp().await, auth_time.to_string());
    }

    #[tokio::test]
    async fn an_absent_or_future_auth_time_signs_in_without_a_stamp() {
        for auth_time in [None, Some(unix_now() + 3600)] {
            let mut b = browser(None).await;
            let started = b.start(PLAIN_START).await;
            b.finish(&started, &started.nonce, auth_time).await;
            assert_eq!(b.kind().await, "user", "{auth_time:?}");
            assert_eq!(b.stamp().await, "none", "{auth_time:?}");
        }
    }

    #[tokio::test]
    async fn a_forced_return_does_not_take_a_replayed_older_id_token() {
        let mut b = browser(None).await;
        // A normal login leaves an old stamp, and an ID token for its handshake.
        let first = b.start(PLAIN_START).await;
        let old = unix_now() - 3000;
        b.finish(&first, &first.nonce, Some(old)).await;
        assert_eq!(b.stamp().await, old.to_string());

        // The forced handshake gets the first handshake's token replayed, bound
        // to the first nonce: refused, and the stamp does not move.
        let forced = b.start(FORCE_START).await;
        b.finish(&forced, &first.nonce, Some(old)).await;
        assert_eq!(b.stamp().await, old.to_string());

        // Even a token bound to the forced handshake does not advance the
        // stamp when its auth_time predates the handshake: the provider did
        // not log the user in again. The forced sign-in is refused; the
        // stamp stays.
        let forced = b.start(FORCE_START).await;
        b.finish(&forced, &forced.nonce, Some(old + 10)).await;
        assert_eq!(b.stamp().await, old.to_string());

        // A real fresh login does advance it.
        let forced = b.start(FORCE_START).await;
        let fresh = unix_now();
        b.finish(&forced, &forced.nonce, Some(fresh)).await;
        assert_eq!(b.stamp().await, fresh.to_string());
    }

    #[tokio::test]
    async fn with_step_up_on_a_return_that_leaves_the_stamp_stale_is_refused() {
        // No auth_time at all, and an auth_time older than the interval.
        for auth_time in [None, Some(unix_now() - 7200)] {
            let mut b = browser(Some(Duration::from_secs(3600))).await;
            let started = b.start(PLAIN_START).await;
            b.finish(&started, &started.nonce, auth_time).await;
            assert_eq!(b.kind().await, "none", "{auth_time:?}");
            assert_eq!(b.stamp().await, "none", "{auth_time:?}");
        }

        // A recent one is let in and stamped.
        let mut b = browser(Some(Duration::from_secs(3600))).await;
        let started = b.start(PLAIN_START).await;
        let recent = unix_now() - 60;
        b.finish(&started, &started.nonce, Some(recent)).await;
        assert_eq!(b.kind().await, "user");
        assert_eq!(b.stamp().await, recent.to_string());
    }

    #[tokio::test]
    async fn a_stale_forced_return_is_refused_even_over_a_fresh_stamp() {
        let mut b = browser(Some(Duration::from_secs(3600))).await;
        let started = b.start(PLAIN_START).await;
        let recent = unix_now() - 60;
        b.finish(&started, &started.nonce, Some(recent)).await;
        assert_eq!(b.stamp().await, recent.to_string());

        // The provider reports a login from before the forced handshake: the
        // forced return is refused, so the stamp does not advance. (The
        // session was already signed in; it is untouched.)
        let forced = b.start(FORCE_START).await;
        b.finish(&forced, &forced.nonce, Some(unix_now() - 1800))
            .await;
        assert_eq!(b.stamp().await, recent.to_string());
    }

    /// A provider that answers the forced handshake from its own session
    /// reports the same `auth_time` as the sign-in it already stamped. That
    /// time can sit inside the forced window, so only "not newer than the
    /// stamp" refuses it, and the user gets the same no-recent-authentication
    /// refusal as every other return that yields no new stamp.
    #[tokio::test]
    async fn a_forced_return_with_an_unchanged_auth_time_is_refused_as_no_new_stamp() {
        let mut b = browser(None).await;
        let started = b.start(PLAIN_START).await;
        let signed_in = unix_now() - 5;
        b.finish(&started, &started.nonce, Some(signed_in)).await;
        assert_eq!(b.stamp().await, signed_in.to_string());

        let forced = b.start(FORCE_START).await;
        b.idp.issue(&forced.nonce, Some(signed_in));
        let resp = b
            .get(&format!("/api/sso/return?code=code&state={}", forced.state))
            .await;
        assert_eq!(resp.0.status(), StatusCode::TEMPORARY_REDIRECT);
        assert!(
            location(&resp).ends_with(
                "/@warpgate?login_error=The+SSO+provider+did+not+report+a+recent+authentication"
            ),
            "{}",
            location(&resp)
        );
        assert_eq!(b.stamp().await, signed_in.to_string());

        // Control: one second newer is a fresh login and is stamped.
        let forced = b.start(FORCE_START).await;
        b.finish(&forced, &forced.nonce, Some(signed_in + 1)).await;
        assert_eq!(b.stamp().await, (signed_in + 1).to_string());
    }

    /// Forced returns on a fresh browser with step-up NOT configured: each
    /// is refused, so no session and no stamp.
    async fn assert_forced_return_refused(auth_time: Option<serde_json::Value>) {
        let mut b = browser(None).await;
        let started = b.start(FORCE_START).await;
        b.finish_raw(&started, &started.nonce, auth_time.clone())
            .await;
        assert_eq!(b.kind().await, "none", "{auth_time:?}");
        assert_eq!(b.stamp().await, "none", "{auth_time:?}");
    }

    #[tokio::test]
    async fn a_forced_return_without_auth_time_is_refused_without_step_up() {
        assert_forced_return_refused(None).await;
    }

    #[tokio::test]
    async fn a_forced_return_with_a_malformed_auth_time_is_refused_without_step_up() {
        for bad in [
            serde_json::json!("yesterday"),
            serde_json::json!(true),
            serde_json::json!({"t": 1}),
            serde_json::json!(null),
        ] {
            assert_forced_return_refused(Some(bad)).await;
        }
    }

    #[tokio::test]
    async fn a_forced_return_with_a_future_auth_time_is_refused_without_step_up() {
        assert_forced_return_refused(Some((unix_now() + 3600).into())).await;
    }

    #[tokio::test]
    async fn a_forced_return_with_an_auth_time_before_the_request_is_refused_without_step_up() {
        assert_forced_return_refused(Some((unix_now() - 3600).into())).await;
    }

    #[tokio::test]
    async fn a_forced_return_boundary_is_30_s_each_side() {
        // Behind the clock, the request began about now: -31 refused, -29 let in.
        assert_forced_return_refused(Some((unix_now() - 31 - 2).into())).await;
        // Ahead of the clock: +31 refused (with margin for the test's own time).
        assert_forced_return_refused(Some((unix_now() + 33).into())).await;
        for (offset, ok) in [(-25, true), (25, true)] {
            let mut b = browser(None).await;
            let started = b.start(FORCE_START).await;
            let at = unix_now() + offset;
            b.finish(&started, &started.nonce, Some(at)).await;
            assert_eq!(b.kind().await == "user", ok, "{offset}");
            assert_eq!(b.stamp().await, at.to_string(), "{offset}");
        }
    }

    #[tokio::test]
    async fn a_forced_return_stamps_exactly_the_auth_time_even_a_little_ahead() {
        let mut b = browser(None).await;
        let started = b.start(FORCE_START).await;
        let ahead = unix_now() + 20;
        b.finish(&started, &started.nonce, Some(ahead)).await;
        assert_eq!(b.kind().await, "user");
        assert_eq!(b.stamp().await, ahead.to_string());
    }
}
