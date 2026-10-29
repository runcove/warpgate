use std::sync::Arc;

use poem::Request;
use poem::session::Session;
use poem::web::{Data, Form};
use poem_openapi::param::Query;
use poem_openapi::payload::{Html, Json, Response};
use poem_openapi::{ApiResponse, Enum, Object, OpenApi};
use serde::Deserialize;
use time::OffsetDateTime;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};
use url::form_urlencoded;
use uuid::Uuid;
use warpgate_common::WarpgateError;
use warpgate_common::auth::AuthCredential;
use warpgate_common_http::auth::UnauthenticatedRequestContext;
use warpgate_common_http::ext::construct_external_url;
use warpgate_common_http::logging::get_client_ip_addr;
use warpgate_common_http::warpgate_csp_with_script_nonce;
use warpgate_core::ConfigProvider;
use warpgate_core::auth::submit_credential;
use warpgate_sso::{SsoClient, SsoInternalProviderConfig};

use crate::SsoLoginState;
use crate::api::auth_scheme::AuthedSession;
use crate::api::common::{emit_unknown_authentication_failed_event, logout};
use crate::common::{
    SessionExt, authorize_session, get_or_create_auth_state_for_request, session_id_for_login,
};
use crate::session::SessionStore;
use crate::step_up::StepUpSessionExt;

pub struct Api;

#[derive(Enum)]
pub enum SsoProviderKind {
    Google,
    Apple,
    Azure,
    Custom,
}

#[derive(Object)]
pub struct SsoProviderDescription {
    pub name: String,
    pub label: String,
    pub kind: SsoProviderKind,
}

#[derive(ApiResponse)]
enum GetSsoProvidersResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<SsoProviderDescription>>),
}

#[allow(clippy::large_enum_variant)]
#[derive(ApiResponse)]
enum ReturnToSsoResponse {
    #[oai(status = 307)]
    Ok,
}

#[allow(clippy::large_enum_variant)]
#[derive(ApiResponse)]
enum ReturnToSsoPostResponse {
    #[oai(status = 200)]
    Redirect(Html<String>),
}

#[derive(Deserialize)]
pub struct ReturnToSsoFormData {
    pub code: Option<String>,
    pub state: Option<String>,
}

#[derive(Object)]
struct StartSloResponseParams {
    url: String,
}

#[allow(clippy::large_enum_variant)]
#[derive(ApiResponse)]
enum StartSloResponse {
    #[oai(status = 200)]
    Ok(Json<StartSloResponseParams>),
    #[oai(status = 400)]
    NotInSsoSession,
    #[oai(status = 404)]
    NotFound,
}

#[derive(Object)]
pub struct SsoKubernetesConfigDescription {
    pub name: String,
    pub label: String,
    pub issuer_url: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub client_secret: Option<String>,
}

#[derive(ApiResponse)]
enum GetSsoKubernetesConfigsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<SsoKubernetesConfigDescription>>),
    #[oai(status = 403)]
    Forbidden,
}

fn make_redirect_url(err: &str) -> String {
    error!("SSO error: {err}");
    let query = form_urlencoded::Serializer::new(String::new())
        .append_pair("login_error", err)
        .finish();
    format!("/@warpgate?{query}")
}

/// The fixed `login_error` codes an SSO failure reports to a caller that
/// supplied a safe `next=`. They are a stable contract with the caller (see
/// `COVE.md`), so the wire strings are spelled out here and nowhere derived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SsoLoginError {
    /// Login protection rejected the credential because the client IP is blocked.
    IpBlocked,
    /// Any other SSO validation failure. A locked account lands here too, so an
    /// unproven caller cannot tell a locked account from a wrong one.
    SsoFailed,
    /// SSO succeeded but no Warpgate user matches.
    NoMatchingUser,
    /// The user exists but is not allowed in.
    AccessDenied,
}

impl SsoLoginError {
    const fn code(self) -> &'static str {
        match self {
            Self::IpBlocked => "ip_blocked",
            Self::SsoFailed => "sso_failed",
            Self::NoMatchingUser => "no_matching_user",
            Self::AccessDenied => "access_denied",
        }
    }
}

/// A failed SSO return: the coded reason for a caller that can be sent back to
/// its own `next=`, and the free-text reason for the server log and for the
/// `/@warpgate` page everyone else gets.
struct SsoFailure {
    code: SsoLoginError,
    reason: String,
    /// Seconds until the client IP is unblocked; only set for `IpBlocked`.
    retry_after: Option<u64>,
    /// `(origin, next)` of the SSO start, when it carried a `next`.
    return_to: Option<(String, String)>,
}

impl SsoFailure {
    fn new(code: SsoLoginError, reason: impl Into<String>) -> Self {
        Self {
            code,
            reason: reason.into(),
            retry_after: None,
            return_to: None,
        }
    }

    fn at(
        return_to: &Option<(String, String)>,
        code: SsoLoginError,
        reason: impl Into<String>,
    ) -> Self {
        let mut failure = Self::new(code, reason);
        failure.return_to = return_to.clone();
        failure
    }

    fn with_retry_after(mut self, retry_after: u64) -> Self {
        self.retry_after = Some(retry_after);
        self
    }

    /// Back to the caller's own `next` with the code when that is a safe
    /// site-relative target, otherwise today's `/@warpgate` page.
    fn into_redirect_url(self) -> String {
        match self.return_to {
            Some((origin, next)) if is_safe_redirect_target(&next) => {
                error!(code = self.code.code(), "SSO error: {}", self.reason);
                let retry_after = self
                    .retry_after
                    .filter(|_| self.code == SsoLoginError::IpBlocked);
                format!(
                    "{origin}{}",
                    next_with_login_error(&next, self.code, retry_after)
                )
            }
            _ => make_redirect_url(&self.reason),
        }
    }
}

/// The failure for a credential login protection rejected. The block check
/// and the recorded failure use the same client address, the one the rest of
/// the login code resolves.
async fn rejected_credential_failure(
    services: &warpgate_core::Services,
    client_ip: Option<std::net::IpAddr>,
    username: &str,
    return_to: &Option<(String, String)>,
) -> SsoFailure {
    // Asked before the failure is recorded, which can itself start a block:
    // the code names what rejected this credential. A locked account is not
    // told apart from any other failure.
    let blocked_until = match client_ip {
        Some(ip) => services
            .login_protection
            .check_ip_blocked(&ip)
            .await
            .inspect_err(|e| {
                warn!("Failed to check the IP block after an SSO failure: {e:?}");
            })
            .ok()
            .flatten()
            .map(|block| block.expires_at),
        None => None,
    };
    crate::api::auth::record_failed_login_attempt(services, client_ip, username, "sso").await;
    let reason = format!("Failed to validate SSO credential for {username}");
    match blocked_until {
        Some(expires_at) => SsoFailure::at(return_to, SsoLoginError::IpBlocked, reason)
            .with_retry_after(seconds_until(expires_at)),
        None => SsoFailure::at(return_to, SsoLoginError::SsoFailed, reason),
    }
}

/// The failure for a request whose client address login protection has
/// blocked, or `None`. Asked before the credential is submitted, as the
/// password login does.
async fn blocked_address_failure(
    services: &warpgate_core::Services,
    client_ip: Option<std::net::IpAddr>,
    return_to: &Option<(String, String)>,
) -> Result<Option<SsoFailure>, WarpgateError> {
    let Some(ip) = client_ip else {
        return Ok(None);
    };
    let Some(block) = services.login_protection.check_ip_blocked(&ip).await? else {
        return Ok(None);
    };
    warn!(%ip, expires_at = %block.expires_at, "SSO return from a blocked IP");
    Ok(Some(
        SsoFailure::at(
            return_to,
            SsoLoginError::IpBlocked,
            "SSO return from a blocked IP",
        )
        .with_retry_after(seconds_until(block.expires_at)),
    ))
}

/// `next` with `login_error` (and `retry_after`, if given) appended to its
/// query, after dropping any the caller already put there. The query comes
/// before a fragment, which stays last.
fn next_with_login_error(next: &str, code: SsoLoginError, retry_after: Option<u64>) -> String {
    let (before_fragment, fragment) = match next.split_once('#') {
        Some((head, fragment)) => (head, Some(fragment)),
        None => (next, None),
    };
    let (path, query) = match before_fragment.split_once('?') {
        Some((path, query)) => (path, query),
        None => (before_fragment, ""),
    };
    let kept = query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .filter(|pair| {
            // Compared by decoded name: `login%5Ferror` is `login_error` too.
            let (name, _) = form_urlencoded::parse(pair.as_bytes())
                .next()
                .unwrap_or_default();
            name != "login_error" && name != "retry_after"
        })
        .collect::<Vec<_>>()
        .join("&");

    let mut added = form_urlencoded::Serializer::new(String::new());
    added.append_pair("login_error", code.code());
    if let Some(seconds) = retry_after {
        added.append_pair("retry_after", &seconds.to_string());
    }
    let added = added.finish();

    let separator = if kept.is_empty() { "" } else { "&" };
    let mut url = format!("{path}?{kept}{separator}{added}");
    if let Some(fragment) = fragment {
        url.push('#');
        url.push_str(fragment);
    }
    url
}

/// Only site-relative paths are accepted as post-login redirect targets. An
/// absolute URL names its own authority, so allowing one would let `?next=`
/// carry the user to another site with a freshly authenticated session — the
/// origin is decided by the SSO return URL, never by the caller.
pub(crate) fn is_safe_redirect_target(next: &str) -> bool {
    let Some(rest) = next.strip_prefix('/') else {
        return false;
    };
    // Browsers read both `//host` and `/\host` as protocol-relative
    // authorities, so a leading slash alone doesn't make a path site-relative.
    !rest.starts_with(['/', '\\'])
}

/// Resolves the post-login redirect against the origin the identity provider
/// returned the browser to. Both halves are checked before they meet here — the
/// path by [`is_safe_redirect_target`], the origin by `construct_external_url`'s
/// domain whitelist — so neither a crafted `next` nor a forged `Host` header can
/// send the user off-site.
fn post_login_redirect(next: Option<&str>, return_origin: &str) -> String {
    let next = next
        .filter(|next| is_safe_redirect_target(next))
        .unwrap_or("/@warpgate#/login");
    format!("{return_origin}{next}")
}

/// Whole seconds from now to `expires_at`; zero once it has passed.
fn seconds_until(expires_at: OffsetDateTime) -> u64 {
    u64::try_from((expires_at - OffsetDateTime::now_utc()).whole_seconds()).unwrap_or(0)
}

#[OpenApi]
impl Api {
    #[oai(
        path = "/sso/providers",
        method = "get",
        operation_id = "get_sso_providers"
    )]
    async fn api_get_all_sso_providers(
        &self,
        ctx: Data<&UnauthenticatedRequestContext>,
    ) -> Result<GetSsoProvidersResponse, WarpgateError> {
        let mut providers = ctx
            .services()
            .config
            .lock()
            .await
            .store
            .sso_providers
            .clone();
        providers.sort_by(|a, b| a.label().cmp(b.label()));
        Ok(GetSsoProvidersResponse::Ok(Json(
            providers
                .into_iter()
                .map(|p| SsoProviderDescription {
                    name: p.name.clone(),
                    label: p.label().to_string(),
                    kind: match p.provider {
                        SsoInternalProviderConfig::Google { .. } => SsoProviderKind::Google,
                        SsoInternalProviderConfig::Apple { .. } => SsoProviderKind::Apple,
                        SsoInternalProviderConfig::Azure { .. } => SsoProviderKind::Azure,
                        SsoInternalProviderConfig::Custom { .. } => SsoProviderKind::Custom,
                    },
                })
                .collect(),
        )))
    }

    #[oai(path = "/sso/return", method = "get", operation_id = "return_to_sso")]
    async fn api_return_to_sso_get(
        &self,
        req: &Request,
        session: &Session,
        ctx: Data<&UnauthenticatedRequestContext>,
        sso_store: Data<&crate::sso_request_store::SsoRequestStore>,
        code: Query<Option<String>>,
        state: Query<Option<String>>,
    ) -> Result<Response<ReturnToSsoResponse>, WarpgateError> {
        let url = self
            .api_return_to_sso_get_common(
                req,
                session,
                ctx,
                sso_store,
                code.as_ref(),
                state.as_ref(),
            )
            .await?
            .unwrap_or_else(SsoFailure::into_redirect_url);

        Ok(Response::new(ReturnToSsoResponse::Ok).header("Location", url))
    }

    #[oai(
        path = "/sso/return",
        method = "post",
        operation_id = "return_to_sso_with_form_data"
    )]
    async fn api_return_to_sso_post(
        &self,
        req: &Request,
        session: &Session,
        ctx: Data<&UnauthenticatedRequestContext>,
        sso_store: Data<&crate::sso_request_store::SsoRequestStore>,
        data: Form<ReturnToSsoFormData>,
        state: Query<Option<String>>,
    ) -> Result<Response<ReturnToSsoPostResponse>, WarpgateError> {
        let url = self
            .api_return_to_sso_get_common(
                req,
                session,
                ctx,
                sso_store,
                data.code.as_ref(),
                data.state.as_ref().or(state.as_ref()),
            )
            .await?
            .unwrap_or_else(SsoFailure::into_redirect_url);

        let csp_nonce = Uuid::new_v4().simple().to_string();
        let serialized_url = html_escape::encode_script(&serde_json::to_string(&url)?).to_string();
        let attr_url = html_escape::encode_double_quoted_attribute(&url);
        let text_url = html_escape::encode_text(&url);
        Ok(Response::new(ReturnToSsoPostResponse::Redirect(
            poem_openapi::payload::Html(format!(
                "<!doctype html>\n
                <html>
                    <script nonce=\"{csp_nonce}\">location.href = {serialized_url};</script>
                    <body>
                        Redirecting to <a href=\"{attr_url}\">{text_url}</a>...
                    </body>
                </html>
            "
            )),
        ))
        .header(
            "content-security-policy",
            warpgate_csp_with_script_nonce(&csp_nonce),
        ))
    }

    async fn api_return_to_sso_get_common(
        &self,
        req: &Request,
        session: &Session,
        ctx: Data<&UnauthenticatedRequestContext>,
        sso_store: Data<&crate::sso_request_store::SsoRequestStore>,
        code: Option<&String>,
        state: Option<&String>,
    ) -> Result<Result<String, SsoFailure>, WarpgateError> {
        // pull services locally for convenience
        let services = ctx.services();
        let client_ip = get_client_ip_addr(req, services).await;

        let Some(state) = state else {
            return Ok(Err(SsoFailure::new(
                SsoLoginError::SsoFailed,
                "No SSO state parameter in the return request",
            )));
        };

        let Some(code) = code else {
            return Ok(Err(SsoFailure::new(
                SsoLoginError::SsoFailed,
                "No authorization code in the return URL request",
            )));
        };

        // Retrieve the handshake from the SsoRequestStore by the IdP-echoed
        // `state`, bound to this session (see `crate::sso_request_store`) —
        // NOT from the Poem session, which loses it under concurrency and is
        // exactly what caused spurious "Invalid SSO state parameter" failures.
        let session_id = session_id_for_login(req, ctx.0).await?;
        let Some(context) = sso_store.take(state, &session_id).await else {
            return Ok(Err(SsoFailure::new(
                SsoLoginError::SsoFailed,
                "Not in an active SSO process",
            )));
        };

        // Where a failure sends the caller back to. Taken now because
        // `verify_code` consumes the request half of the context.
        let return_to = context
            .next_url
            .clone()
            .map(|next| (context.return_origin.clone(), next));

        // Defence in depth: the store already keyed by `state` and bound to the
        // session, so this holds by construction; keep the explicit CSRF check.
        if !context.request.verify_state(state) {
            return Ok(Err(SsoFailure::at(
                &return_to,
                SsoLoginError::SsoFailed,
                "Invalid SSO state parameter",
            )));
        }

        let response = match context.request.verify_code((*code).clone()).await {
            Ok(response) => response,
            Err(e) => {
                warn!("Failed to verify SSO code: {e:?}");
                // Without a safe `next` to go back to this stays the error it
                // always was.
                if !return_to
                    .as_ref()
                    .is_some_and(|(_, next)| is_safe_redirect_target(next))
                {
                    return Err(e.into());
                }
                return Ok(Err(SsoFailure::at(
                    &return_to,
                    SsoLoginError::SsoFailed,
                    "Failed to verify the SSO authorization code",
                )));
            }
        };

        if !response.email_verified.unwrap_or(true) {
            error!(
                "SSO login attempt with an unverified email: {:?}",
                response.email
            );
            error!(
                "The SSO provider did provide an email_verified claim, and it is false. Since the provider provides this claim, Warpgate requires the email to be verified."
            );
            return Ok(Err(SsoFailure::at(
                &return_to,
                SsoLoginError::SsoFailed,
                "The SSO account's e-mail is not verified",
            )));
        }

        let Some(ref email) = response.email else {
            return Ok(Err(SsoFailure::at(
                &return_to,
                SsoLoginError::SsoFailed,
                "No e-mail information in the SSO response",
            )));
        };

        info!("SSO login as {email}");

        let providers_config = ctx
            .services()
            .config
            .lock()
            .await
            .store
            .sso_providers
            .clone();
        let mut iter = providers_config.iter();
        let Some(provider_config) = iter.find(|x| x.name == context.provider) else {
            return Ok(Err(SsoFailure::at(
                &return_to,
                SsoLoginError::SsoFailed,
                format!("No provider matching {}", context.provider),
            )));
        };

        let cred = AuthCredential::Sso {
            provider: context.provider.clone(),
            email: email.clone(),
        };

        let username = services
            .config_provider
            .username_for_sso_credential(
                &cred,
                response.preferred_username.clone(),
                provider_config.clone(),
            )
            .await?;
        let Some(username) = username else {
            let session_id = session_id_for_login(req, &ctx).await?;
            emit_unknown_authentication_failed_event(
                session_id,
                client_ip,
                email,
                &cred.readable_description(),
                "unknown user",
            );
            return Ok(Err(SsoFailure::at(
                &return_to,
                SsoLoginError::NoMatchingUser,
                format!("No user matching {email}"),
            )));
        };

        let state_arc = match get_or_create_auth_state_for_request(req, &username, &ctx, None).await
        {
            Ok(state) => state,
            Err(e) => {
                if matches!(e, WarpgateError::IpAddrNotAllowed(..)) {
                    let session_id = session_id_for_login(req, &ctx).await?;
                    emit_unknown_authentication_failed_event(
                        session_id,
                        client_ip,
                        &username,
                        &cred.readable_description(),
                        "IP address not allowed",
                    );
                    return Ok(Err(SsoFailure::at(
                        &return_to,
                        SsoLoginError::AccessDenied,
                        "Login denied: your IP address is not in the allowed range for this user",
                    )));
                }
                return Err(e);
            }
        };

        if let Some(failure) = blocked_address_failure(services, client_ip, &return_to).await? {
            return Ok(Err(failure));
        }

        let mut state = state_arc.lock().await;

        let outcome = submit_credential(
            &mut state,
            cred,
            ctx.services().config_provider.as_ref(),
            &ctx.services().login_protection,
        )
        .await?;

        if !outcome.is_valid() {
            return Ok(Err(
                rejected_credential_failure(services, client_ip, &username, &return_to).await,
            ));
        }

        // Stored before any remaining factor so back-channel logout and SLO
        // can find the session even when TOTP or an approval is still pending.
        let login_state = || SsoLoginState {
            provider: context.provider.clone(),
            token: response.id_token.clone(),
            supports_single_logout: context.supports_single_logout,
            subject: Some(response.subject.clone()),
            sid: response.sid.clone(),
        };
        session.set_sso_login_state(login_state());

        if let Ok(user_info) = outcome.into_accepted() {
            authorize_session(req, &ctx, user_info).await?;
            // Stamp the HTTP per-session step-up clock, after
            // `authorize_session` (which can clear the session). Only the SSO
            // return path stamps: password / OTP logins are not SSO handshakes
            // and must not refresh the clock, else a user who only ever logs in
            // via password would never re-SSO and the step-up gate would
            // silently become a no-op.
            session.set_last_sso_at(OffsetDateTime::now_utc());
            state.emit_authenticated_event_once();
            if let Some(ip) = client_ip {
                let _ = services
                    .login_protection
                    .clear_failed_attempts(&ip, &username)
                    .await;
            }
            // `authorize_session` can clear the session, so store it again.
            session.set_sso_login_state(login_state());
        }
        drop(state);

        // Also ends whatever access the role sync took away.
        services
            .resolve_and_map_sso_user(provider_config, &response)
            .await?;

        Ok(Ok(post_login_redirect(
            context.next_url.as_deref(),
            &context.return_origin,
        )))
    }

    #[oai(
        path = "/sso/logout",
        method = "get",
        operation_id = "initiate_sso_logout"
    )]
    async fn api_start_slo(
        &self,
        req: &Request,
        session: &Session,
        ctx: Data<&UnauthenticatedRequestContext>,
        session_middleware: Data<&Arc<Mutex<SessionStore>>>,
    ) -> Result<StartSloResponse, WarpgateError> {
        let Some(state) = session.get_sso_login_state() else {
            warn!("SSO logout requested for a session that did not log in via SSO");
            return Ok(StartSloResponse::NotInSsoSession);
        };

        // Log out of Warpgate first. The IdP's single logout below is
        // best-effort on top of it: a provider no longer configured, an IdP
        // that cannot be reached or one without single logout must not leave
        // the Warpgate login live.
        logout(session, session_middleware.0, &ctx.services().db).await;

        // The configuration lock is not held across the IdP's network calls.
        let (provider, return_url) = {
            let config = ctx.services().config.lock().await;
            let return_url = construct_external_url(Some(req), &config, None).await?;
            let Some(provider_config) = config
                .store
                .sso_providers
                .iter()
                .find(|p| p.name == state.provider)
            else {
                warn!(provider = %state.provider, "SSO logout requested for a provider that is no longer configured");
                return Ok(StartSloResponse::NotFound);
            };
            (provider_config.provider.clone(), return_url)
        };
        debug!("Return URL: {}", &return_url);

        let client = SsoClient::new(provider)?;
        let logout_url = client.logout(state.token, return_url).await?;

        Ok(StartSloResponse::Ok(Json(StartSloResponseParams {
            url: logout_url.to_string(),
        })))
    }

    #[oai(
        path = "/sso/kubernetes-configs",
        method = "get",
        operation_id = "get_sso_kubernetes_configs"
    )]
    async fn api_get_sso_kubernetes_configs(
        &self,
        ctx: AuthedSession,
    ) -> Result<GetSsoKubernetesConfigsResponse, WarpgateError> {
        if ctx.auth.as_full_user().is_none() {
            return Ok(GetSsoKubernetesConfigsResponse::Forbidden);
        }
        let mut providers = ctx
            .services()
            .config
            .lock()
            .await
            .store
            .sso_providers
            .clone();
        providers.sort_by(|a, b| a.label().cmp(b.label()));
        let configs = providers
            .iter()
            .filter_map(|p| {
                let k = p.kubernetes.as_ref()?;
                let issuer_url = p.provider.issuer_url().ok()?;
                Some(SsoKubernetesConfigDescription {
                    name: p.name.clone(),
                    label: p.label().to_string(),
                    issuer_url: issuer_url.to_string(),
                    client_id: k.client_id.clone(),
                    scopes: k.scopes_or_default(),
                    client_secret: k.client_secret.clone(),
                })
            })
            .collect();
        Ok(GetSsoKubernetesConfigsResponse::Ok(Json(configs)))
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::{ActiveModelTrait, IntoActiveModel, Set};
    use uuid::Uuid;
    use warpgate_db_entities::{Parameters, User};

    use super::{
        SsoFailure, SsoLoginError, blocked_address_failure, is_safe_redirect_target,
        make_redirect_url, next_with_login_error, post_login_redirect, rejected_credential_failure,
    };
    use crate::test_db::{memory_db, services};

    #[test]
    fn error_redirect_is_site_relative_and_escaped() {
        assert_eq!(
            make_redirect_url("No user matching a&b@example.com"),
            "/@warpgate?login_error=No+user+matching+a%26b%40example.com"
        );
    }

    #[test]
    fn accepts_relative_paths() {
        assert!(is_safe_redirect_target("/@warpgate#/login"));
        assert!(is_safe_redirect_target("/foo/bar?x=1"));
    }

    #[test]
    fn rejects_anything_carrying_its_own_authority() {
        assert!(!is_safe_redirect_target("javascript:alert(1)"));
        assert!(!is_safe_redirect_target("data:text/html,<script>"));
        assert!(!is_safe_redirect_target("//evil.com"));
        assert!(!is_safe_redirect_target("/\\evil.com"));
        assert!(!is_safe_redirect_target("ftp://example.com"));
        // Absolute http(s) URLs are rejected too: the origin comes from the SSO
        // return URL, never from the caller.
        assert!(!is_safe_redirect_target("https://evil.com/path"));
        assert!(!is_safe_redirect_target("http://evil.com"));
    }

    #[test]
    fn redirect_is_resolved_against_the_return_origin() {
        assert_eq!(
            post_login_redirect(Some("/foo?x=1"), "https://gate.example:8888"),
            "https://gate.example:8888/foo?x=1"
        );
    }

    #[test]
    fn rejected_targets_fall_back_to_the_login_page_on_the_return_origin() {
        for next in [
            Some("https://evil.com/path"),
            Some("//evil.com"),
            Some("javascript:alert(1)"),
            None,
        ] {
            assert_eq!(
                post_login_redirect(next, "https://gate.example"),
                "https://gate.example/@warpgate#/login",
                "{next:?} must not leave the return origin"
            );
        }
    }

    const ORIGIN: &str = "https://gate.example";

    fn failure_url(code: SsoLoginError, next: Option<&str>) -> String {
        let mut failure = SsoFailure::new(code, "reason");
        failure.return_to = next.map(|next| (ORIGIN.to_string(), next.to_string()));
        failure.into_redirect_url()
    }

    #[test]
    fn codes_are_the_stable_wire_strings() {
        assert_eq!(SsoLoginError::IpBlocked.code(), "ip_blocked");
        assert_eq!(SsoLoginError::SsoFailed.code(), "sso_failed");
        assert_eq!(SsoLoginError::NoMatchingUser.code(), "no_matching_user");
        assert_eq!(SsoLoginError::AccessDenied.code(), "access_denied");
    }

    #[test]
    fn each_code_returns_to_a_safe_next_on_the_return_origin() {
        for (code, wire) in [
            (SsoLoginError::SsoFailed, "sso_failed"),
            (SsoLoginError::NoMatchingUser, "no_matching_user"),
            (SsoLoginError::AccessDenied, "access_denied"),
        ] {
            assert_eq!(
                failure_url(code, Some("/cove/login")),
                format!("{ORIGIN}/cove/login?login_error={wire}")
            );
        }
    }

    #[test]
    fn ip_blocked_carries_retry_after() {
        let failure = SsoFailure::new(SsoLoginError::IpBlocked, "blocked").with_retry_after(120);
        let failure = SsoFailure {
            return_to: Some((ORIGIN.to_string(), "/cove/login".to_string())),
            ..failure
        };
        assert_eq!(
            failure.into_redirect_url(),
            format!("{ORIGIN}/cove/login?login_error=ip_blocked&retry_after=120")
        );
    }

    #[test]
    fn retry_after_is_only_ever_sent_for_ip_blocked() {
        for code in [
            SsoLoginError::SsoFailed,
            SsoLoginError::NoMatchingUser,
            SsoLoginError::AccessDenied,
        ] {
            let failure = SsoFailure {
                return_to: Some((ORIGIN.to_string(), "/cove/login".to_string())),
                ..SsoFailure::new(code, "reason").with_retry_after(120)
            };
            assert!(!failure.into_redirect_url().contains("retry_after"));
        }
    }

    /// A database with login protection on, a user `alice`, and the given
    /// per-address and per-username attempt limits.
    async fn protected_services(ip_max: i32, user_max: i32) -> warpgate_core::Services {
        let db = memory_db().await;
        User::ActiveModel {
            id: Set(Uuid::new_v4()),
            username: Set("alice".into()),
            description: Set(String::new()),
            credential_policy: Set(serde_json::json!({})),
            rate_limit_bytes_per_second: Set(None),
            ldap_server_id: Set(None),
            ldap_object_uuid: Set(None),
            allowed_ip_ranges: Set(serde_json::Value::Null),
        }
        .insert(&db)
        .await
        .unwrap();
        let mut params = Parameters::Entity::get(&db)
            .await
            .unwrap()
            .into_active_model();
        params.login_protection_enabled = Set(true);
        params.lp_ip_max_attempts = Set(ip_max);
        params.lp_ip_time_window_seconds = Set(3600);
        params.lp_ip_base_block_duration_seconds = Set(600);
        params.lp_ip_max_block_duration_seconds = Set(3600);
        params.lp_user_max_attempts = Set(user_max);
        params.lp_user_time_window_seconds = Set(3600);
        params.lp_user_auto_unlock = Set(true);
        params.lp_user_lockout_duration_seconds = Set(3600);
        params.lp_user_exempt_admins = Set(false);
        params.update(&db).await.unwrap();
        services(db).await
    }

    async fn rejected_url(
        services: &warpgate_core::Services,
        client_ip: Option<&str>,
        username: &str,
    ) -> String {
        let return_to = Some((ORIGIN.to_string(), "/cove/login".to_string()));
        let client_ip = client_ip.map(|ip| ip.parse().unwrap());
        rejected_credential_failure(services, client_ip, username, &return_to)
            .await
            .into_redirect_url()
    }

    #[tokio::test]
    async fn a_locked_account_reports_sso_failed_not_its_lock() {
        let services = protected_services(100, 2).await;
        for _ in 0..2 {
            rejected_url(&services, Some("192.0.2.10"), "alice").await;
        }
        assert!(
            services
                .login_protection
                .check_user_locked("alice")
                .await
                .unwrap()
                .is_some(),
            "the account is locked"
        );

        let url = rejected_url(&services, Some("192.0.2.10"), "alice").await;

        assert_eq!(url, format!("{ORIGIN}/cove/login?login_error=sso_failed"));
        assert!(!url.contains("lock"));
    }

    #[tokio::test]
    async fn a_blocked_address_reports_ip_blocked_for_that_address_only() {
        let services = protected_services(2, 100).await;
        rejected_url(&services, Some("192.0.2.10"), "alice").await;
        rejected_url(&services, Some("192.0.2.10"), "alice").await;

        let blocked = rejected_url(&services, Some("192.0.2.10"), "alice").await;
        let other = rejected_url(&services, Some("192.0.2.11"), "alice").await;

        assert!(
            blocked.starts_with(&format!(
                "{ORIGIN}/cove/login?login_error=ip_blocked&retry_after="
            )),
            "{blocked}"
        );
        assert_eq!(other, format!("{ORIGIN}/cove/login?login_error=sso_failed"));
    }

    #[tokio::test]
    async fn the_credential_gate_reads_the_request_address_only() {
        let services = protected_services(2, 100).await;
        rejected_url(&services, Some("192.0.2.10"), "alice").await;
        rejected_url(&services, Some("192.0.2.10"), "alice").await;
        let return_to = Some((ORIGIN.to_string(), "/cove/login".to_string()));
        let gate = |ip: Option<&str>| {
            let ip = ip.map(|ip| ip.parse().unwrap());
            let services = &services;
            let return_to = &return_to;
            async move {
                blocked_address_failure(services, ip, return_to)
                    .await
                    .unwrap()
                    .map(SsoFailure::into_redirect_url)
            }
        };

        let blocked = gate(Some("192.0.2.10"))
            .await
            .expect("the blocked address is refused");
        assert!(
            blocked.starts_with(&format!(
                "{ORIGIN}/cove/login?login_error=ip_blocked&retry_after="
            )),
            "{blocked}"
        );
        assert_eq!(gate(Some("192.0.2.11")).await, None);
        assert_eq!(gate(None).await, None);
    }

    #[test]
    fn a_plus_in_a_name_decodes_to_a_space_so_it_is_another_key() {
        // `+` is a space in form encoding: `login_error+` is `login_error `,
        // not `login_error`, so it is kept and the real code is still added once.
        assert_eq!(
            next_with_login_error("/login?login_error+=x", SsoLoginError::SsoFailed, None),
            "/login?login_error+=x&login_error=sso_failed"
        );
    }

    #[test]
    fn appends_with_ampersand_when_next_has_a_query() {
        assert_eq!(
            next_with_login_error("/login?a=1", SsoLoginError::SsoFailed, None),
            "/login?a=1&login_error=sso_failed"
        );
    }

    #[test]
    fn appends_with_question_mark_when_next_has_no_query() {
        assert_eq!(
            next_with_login_error("/login", SsoLoginError::SsoFailed, None),
            "/login?login_error=sso_failed"
        );
    }

    #[test]
    fn strips_a_login_error_and_retry_after_the_caller_already_set() {
        assert_eq!(
            next_with_login_error(
                "/login?login_error=forged&a=1&retry_after=999&b=2",
                SsoLoginError::AccessDenied,
                None
            ),
            "/login?a=1&b=2&login_error=access_denied"
        );
        assert_eq!(
            next_with_login_error(
                "/login?login_error=forged&retry_after=999",
                SsoLoginError::SsoFailed,
                None
            ),
            "/login?login_error=sso_failed"
        );
    }

    #[test]
    fn strips_a_percent_encoded_login_error_and_retry_after() {
        assert_eq!(
            next_with_login_error(
                "/login?login%5Ferror=forged&a=1&%72etry_after=999",
                SsoLoginError::SsoFailed,
                None
            ),
            "/login?a=1&login_error=sso_failed"
        );
    }

    #[test]
    fn the_query_goes_before_a_fragment() {
        assert_eq!(
            next_with_login_error("/login?a=1#top", SsoLoginError::SsoFailed, None),
            "/login?a=1&login_error=sso_failed#top"
        );
    }

    #[test]
    fn unsafe_or_missing_next_falls_back_to_the_warpgate_page() {
        for next in [
            None,
            Some("https://evil.com/path"),
            Some("//evil.com"),
            Some("javascript:alert(1)"),
        ] {
            assert_eq!(
                failure_url(SsoLoginError::NoMatchingUser, next),
                "/@warpgate?login_error=reason",
                "{next:?} must keep today's login page"
            );
        }
    }
}
