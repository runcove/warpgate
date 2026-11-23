use std::borrow::Cow;
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use openidconnect::core::{
    CoreAuthDisplay, CoreAuthPrompt, CoreAuthenticationFlow, CoreClientAuthMethod,
    CoreErrorResponseType, CoreGenderClaim, CoreJsonWebKey, CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm, CoreRevocableToken, CoreRevocationErrorResponse,
    CoreTokenIntrospectionResponse, CoreTokenType,
};
use openidconnect::url::Url;
use openidconnect::{
    AccessTokenHash, AdditionalClaims, Audience, AuthType, AuthorizationCode, Client, ClientSecret,
    CsrfToken, EmptyExtraTokenFields, EndpointMaybeSet, EndpointNotSet, EndpointSet,
    HttpClientError, IdToken, IdTokenClaims, IdTokenFields, LogoutRequest, Nonce,
    OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, PostLogoutRedirectUrl,
    ProviderMetadataWithLogout, RedirectUrl, RequestTokenError, Scope, StandardErrorResponse,
    StandardTokenResponse, TokenResponse, UserInfoClaims, UserInfoError, reqwest,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::config::SsoInternalProviderConfig;
use crate::request::SsoLoginRequest;
use crate::{BackchannelLogout, SsoError, discover_metadata, refresh_metadata};

/// A single entry in a group-style claim: either a bare string, or a
/// SCIM-style object (RFC 7643) from which we take `value` (stable group ID)
/// and `display` (human-readable name).
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum GroupClaimEntry {
    Str(String),
    Obj {
        #[serde(default)]
        value: Option<String>,
        #[serde(default)]
        display: Option<String>,
    },
}

/// A group-style claim value: a single entry, or an array of entries
/// (strings and/or objects, mixed). Some OIDC providers return a single
/// value as a bare scalar rather than a one-element array; both are accepted.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum GroupClaim {
    One(GroupClaimEntry),
    Many(Vec<GroupClaimEntry>),
}

/// Flatten a group claim into a sorted, de-duplicated list of strings.
///
/// For object entries BOTH `value` and `display` are emitted (when present),
/// so role mappings may be keyed on either the stable group ID or its name.
/// (A collision between one group's `display` and another's `value` would map
/// both -- effectively impossible with opaque IDs.)
pub fn flatten_group_claim(claim: GroupClaim) -> Vec<String> {
    let entries = match claim {
        GroupClaim::One(e) => vec![e],
        GroupClaim::Many(v) => v,
    };
    let mut out: Vec<String> = entries
        .into_iter()
        .flat_map(|e| match e {
            GroupClaimEntry::Str(s) => vec![s],
            GroupClaimEntry::Obj { value, display } => {
                [value, display].into_iter().flatten().collect()
            }
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(transparent)]
pub struct WarpgateClaims(
    /// Flat map of claims since role claim names are configurable
    pub HashMap<String, serde_json::Value>,
);

impl AdditionalClaims for WarpgateClaims {}

pub type WarpgateIdToken = IdToken<
    WarpgateClaims,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;

type WarpgateIdTokenClaims = IdTokenClaims<WarpgateClaims, CoreGenderClaim>;

type WarpgateTokenResponse = StandardTokenResponse<
    IdTokenFields<
        WarpgateClaims,
        EmptyExtraTokenFields,
        CoreGenderClaim,
        CoreJweContentEncryptionAlgorithm,
        CoreJwsSigningAlgorithm,
    >,
    CoreTokenType,
>;

type WarpgateClient = Client<
    WarpgateClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    WarpgateTokenResponse,
    CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
    EndpointSet,      // HasAuthUrl
    EndpointNotSet,   // HasDeviceAuthUrl
    EndpointNotSet,   // HasIntrospectionUrl
    EndpointNotSet,   // HasRevocationUrl
    EndpointMaybeSet, // HasTokenUrl
    EndpointMaybeSet, // HasUserInfoUrl
>;

pub struct SsoResult {
    pub token: WarpgateIdToken,
    pub claims: WarpgateIdTokenClaims,
    pub userinfo_claims: Option<UserInfoClaims<WarpgateClaims, CoreGenderClaim>>,
    /// Raw ID token claims as JSON for custom claim extraction.
    /// Only the specific configured claim is read from this — avoids serde(flatten)
    /// which could allow OIDC claim injection into typed fields.
    pub raw_id_token_claims: Option<serde_json::Value>,
}

/// How hard an authorize request asks the provider to re-authenticate the user
/// rather than resume its own SSO session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reauth {
    /// Let the provider decide.
    None,
    /// `max_age=<secs>`: the provider re-authenticates a user whose last login
    /// there is older than this.
    MaxAge(Duration),
    /// `prompt=login` and `max_age=0`: always a fresh login.
    Force,
}

/// The `claims` authorize parameter that asks for `auth_time` in the ID token
/// (OpenID Connect Core, section 5.5).
const AUTH_TIME_CLAIMS_REQUEST: &str = r#"{"id_token":{"auth_time":{"essential":true}}}"#;

/// The current time in unix seconds.
fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i64::try_from(elapsed.as_secs()).ok())
        .unwrap_or_default()
}

pub struct SsoClient {
    config: SsoInternalProviderConfig,
    http_client: reqwest::Client,
}

/// Extract the `iss` claim from a raw JWT **without** verifying its signature.
///
/// Used only as a routing hint to pick which SSO provider should fully verify a
/// bearer token, so we can skip issuer discovery for unrelated providers. The
/// result is never trusted for any security decision.
pub fn unverified_issuer(id_token_str: &str) -> Option<String> {
    #[derive(Deserialize)]
    struct IssuerClaim {
        iss: Option<String>,
    }

    jsonwebtoken::dangerous::insecure_decode::<IssuerClaim>(id_token_str)
        .ok()?
        .claims
        .iss
}

/// `UserInfoError`'s own Display drops the response body and its Debug renders
/// it as a byte array, both of which hide the provider's actual error message.
fn describe_userinfo_error(err: &UserInfoError<HttpClientError<reqwest::Error>>) -> String {
    match err {
        UserInfoError::Response(status, body, _) => {
            format!("HTTP {status}: {}", String::from_utf8_lossy(body))
        }
        e => format!("{e}"),
    }
}

/// Whether HTTP Basic client authentication would transmit this secret intact.
///
/// RFC 6749 section 2.3.1 requires the client secret to be form-urlencoded before it
/// is base64'd into the `Authorization: Basic` credentials, and `oauth2` does
/// exactly that. Providers are supposed to decode it again, but several
/// (Authentik among them) compare the raw header value against the stored
/// secret, so a secret containing `+`, `=` or `/` arrives as its percent-encoded
/// form and is rejected as `invalid_client`.
fn secret_survives_basic_auth(secret: &ClientSecret) -> bool {
    let raw = secret.secret();
    form_urlencoded::byte_serialize(raw.as_bytes()).collect::<String>() == *raw
}

/// A provider that omits `token_endpoint_auth_methods_supported` defaults to
/// `client_secret_basic` alone (OIDC Discovery section 3), so an absent list is a no.
fn advertises_secret_post(metadata: &ProviderMetadataWithLogout) -> bool {
    metadata
        .token_endpoint_auth_methods_supported()
        .is_some_and(|methods| methods.contains(&CoreClientAuthMethod::ClientSecretPost))
}

/// Pick the client authentication method for the token endpoint.
///
/// Basic auth is the RFC's recommendation and stays the default, but it is only
/// unambiguous for secrets that form-urlencoding leaves alone. For the rest,
/// `client_secret_post` carries the secret verbatim and both sides agree on it.
fn resolve_auth_type(
    configured: AuthType,
    secret: &ClientSecret,
    metadata: &ProviderMetadataWithLogout,
) -> AuthType {
    if !matches!(configured, AuthType::BasicAuth) || secret_survives_basic_auth(secret) {
        return configured;
    }
    if advertises_secret_post(metadata) {
        debug!("Client secret needs escaping for basic auth; using client_secret_post instead");
        return AuthType::RequestBody;
    }
    warn!(
        "Client secret contains characters that must be escaped for basic auth, and the provider does not advertise client_secret_post. If authentication fails with invalid_client, rotate the secret to one made up of letters, digits and `-._*`."
    );
    configured
}

fn client_from_metadata(
    config: &SsoInternalProviderConfig,
    metadata: ProviderMetadataWithLogout,
) -> Result<WarpgateClient, SsoError> {
    let secret = config.client_secret()?;
    let auth_type = resolve_auth_type(config.auth_type(), &secret, &metadata);

    let client =
        WarpgateClient::from_provider_metadata(metadata, config.client_id().clone(), Some(secret))
            .set_auth_type(auth_type);

    Ok(client)
}

async fn make_client(
    config: &SsoInternalProviderConfig,
    http_client: &reqwest::Client,
) -> Result<WarpgateClient, SsoError> {
    client_from_metadata(config, discover_metadata(config, http_client).await?)
}

impl SsoClient {
    pub fn new(config: SsoInternalProviderConfig) -> Result<Self, SsoError> {
        Ok(Self {
            config,
            http_client: reqwest::ClientBuilder::new().build()?,
        })
    }

    /// Run `verify` against `metadata` and retry once with refreshed metadata if the token is signed with unknown (rotated) key
    async fn retry_on_unknown_key<T>(
        &self,
        metadata: &ProviderMetadataWithLogout,
        action: impl Fn(&ProviderMetadataWithLogout) -> Result<T, SsoError>,
    ) -> Result<T, SsoError> {
        match action(metadata) {
            Err(error) if error.is_unknown_signing_key() => {
                info!("Token signed with a key missing from the cached JWKS, re-fetching it");
                action(&refresh_metadata(&self.config, &self.http_client).await?)
            }
            result => result,
        }
    }

    pub async fn supports_single_logout(&self) -> Result<bool, SsoError> {
        let metadata = discover_metadata(&self.config, &self.http_client).await?;
        Ok(metadata
            .additional_metadata()
            .end_session_endpoint
            .is_some())
    }

    pub async fn start_login(
        &self,
        redirect_url: String,
        reauth: Reauth,
    ) -> Result<SsoLoginRequest, SsoError> {
        let started_at = unix_now();
        let redirect_url = RedirectUrl::new(redirect_url)?;
        let client: WarpgateClient = make_client(&self.config, &self.http_client).await?;
        let mut auth_req = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .set_redirect_uri(Cow::Owned(redirect_url.clone()));

        match reauth {
            Reauth::None => {}
            Reauth::MaxAge(max_age) => {
                auth_req = auth_req.set_max_age(max_age);
            }
            Reauth::Force => {
                if self.config.supports_prompt_login() {
                    auth_req = auth_req.add_prompt(CoreAuthPrompt::Login);
                }
                auth_req = auth_req.set_max_age(Duration::ZERO);
            }
        }

        // Providers that include `auth_time` only when asked (OpenID Connect
        // Core 5.5) are asked for it. Sent whenever a re-authentication
        // setting is in play; the plain login is left as it was.
        if reauth != Reauth::None {
            auth_req = auth_req.add_extra_param("claims", AUTH_TIME_CLAIMS_REQUEST);
        }

        for (k, v) in self.config.extra_parameters() {
            auth_req = auth_req.add_extra_param(k, v);
        }

        for scope in self.config.scopes() {
            auth_req = auth_req.add_scope(Scope::new(scope.clone()));
        }

        let pkce_verifier = if self.config.needs_pkce_verifier() {
            let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
            auth_req = auth_req.set_pkce_challenge(pkce_challenge);
            Some(pkce_verifier)
        } else {
            None
        };

        let (auth_url, csrf_token, nonce) = auth_req.url();

        Ok(SsoLoginRequest {
            auth_url,
            csrf_token,
            nonce,
            pkce_verifier,
            redirect_url,
            config: self.config.clone(),
            started_at,
            forced: reauth == Reauth::Force,
        })
    }

    pub async fn finish_login(
        &self,
        pkce_verifier: Option<PkceCodeVerifier>,
        redirect_url: RedirectUrl,
        nonce: &Nonce,
        code: String,
    ) -> Result<SsoResult, SsoError> {
        let metadata = discover_metadata(&self.config, &self.http_client).await?;
        let client =
            client_from_metadata(&self.config, metadata.clone())?.set_redirect_uri(redirect_url);

        let mut req = client.exchange_code(AuthorizationCode::new(code))?;
        if let Some(verifier) = pkce_verifier {
            req = req.set_pkce_verifier(verifier);
        }

        let token_response = req.request_async(&self.http_client).await.map_err(
            |e: RequestTokenError<
                HttpClientError<reqwest::Error>,
                StandardErrorResponse<CoreErrorResponseType>,
            >| match e {
                RequestTokenError::ServerResponse(response) => SsoError::Verification(format!(
                    "{}: {:?}",
                    response.error(),
                    response.error_description()
                )),
                RequestTokenError::Parse(err, path) => SsoError::Verification(format!(
                    "Parse error: {:?} / {:?}",
                    err,
                    String::from_utf8_lossy(&path)
                )),
                e => SsoError::Verification(format!("{e}")),
            },
        )?;

        let id_token: &WarpgateIdToken = token_response.id_token().ok_or(SsoError::NotOidc)?;
        let claims = self
            .retry_on_unknown_key(&metadata, |metadata| {
                let client = client_from_metadata(&self.config, metadata.clone())?;
                let mut token_verifier = client.id_token_verifier();

                if let Some(trusted_audiences) = self.config.additional_trusted_audiences() {
                    token_verifier =
                        token_verifier.set_other_audience_verifier_fn(|aud: &Audience| {
                            trusted_audiences.contains(&**aud)
                        });
                }

                if self.config.trust_unknown_audiences() {
                    token_verifier = token_verifier.set_other_audience_verifier_fn(|_aud| true);
                }

                let claims = id_token.claims(&token_verifier, nonce)?;

                if let Some(expected_access_token_hash) = claims.access_token_hash() {
                    let actual_access_token_hash = AccessTokenHash::from_token(
                        token_response.access_token(),
                        id_token.signing_alg()?,
                        id_token.signing_key(&token_verifier)?,
                    )?;
                    if actual_access_token_hash != *expected_access_token_hash {
                        return Err(SsoError::Mitm);
                    }
                }

                Ok(claims.clone())
            })
            .await?;

        let user_info_req = client
            .user_info(token_response.access_token().to_owned(), None)
            .map_err(|err| {
                debug!("Provider has no usable userinfo endpoint: {err}");
                err
            })
            .ok();

        let userinfo_claims: Option<UserInfoClaims<WarpgateClaims, CoreGenderClaim>> =
            if let Some(user_info_req) = user_info_req {
                match user_info_req.request_async(&self.http_client).await {
                    Ok(userinfo) => Some(userinfo),
                    Err(err) => {
                        warn!(
                            "Failed to fetch userinfo: {}",
                            describe_userinfo_error(&err)
                        );
                        None
                    }
                }
            } else {
                None
            };

        // Extract raw ID token claims as JSON for custom claim lookup.
        // This avoids serde(flatten) which could let malicious claims shadow typed fields.
        let raw_id_token_claims = serde_json::to_value(&claims).ok();

        Ok(SsoResult {
            token: id_token.clone(),
            userinfo_claims,
            claims,
            raw_id_token_claims,
        })
    }

    /// Verify a raw OIDC ID token (e.g. from a kubectl exec plugin) without a
    /// code exchange or nonce. Validates signature against the issuer JWKS and
    /// checks `iss`, `exp` and `aud` (honouring the provider's trusted-audience
    /// configuration).
    pub async fn verify_id_token(&self, id_token_str: &str) -> Result<SsoResult, SsoError> {
        // Parse first, so a non-JWT bearer token (e.g. an API token) is rejected
        // before we make any network call to the issuer.
        let id_token: WarpgateIdToken = id_token_str
            .parse()
            .map_err(|e| SsoError::Verification(format!("Malformed ID token: {e}")))?;

        // Capture audience-check configuration before building the verifier.
        let trusted: Vec<String> = self
            .config
            .additional_trusted_audiences()
            .cloned()
            .unwrap_or_default();
        let trust_unknown = self.config.trust_unknown_audiences();
        let client_id = self.config.client_id().as_str().to_owned();

        let metadata = discover_metadata(&self.config, &self.http_client).await?;

        let claims = self
            .retry_on_unknown_key(&metadata, |metadata| {
                let client = client_from_metadata(&self.config, metadata.clone())?;
                // Disable the built-in audience check so we can enforce it ourselves
                // below.  Signature / iss / exp are still fully enforced.
                let token_verifier = client.id_token_verifier().require_audience_match(false);

                // No nonce in a non-interactive flow: accept any (absent) nonce.
                Ok(id_token
                    .claims(&token_verifier, |_: Option<&Nonce>| Ok::<(), String>(()))?
                    .clone())
            })
            .await?;

        // Manual audience enforcement: a token is accepted iff its audience
        // contains Warpgate's own client_id OR any configured trusted audience.
        // When trust_unknown_audiences is true we skip the check entirely
        // (documented semantics), but signature/iss/exp are always enforced.
        if !trust_unknown {
            let auds = claims.audiences();
            let ok = auds.iter().any(|a| {
                let a = a.as_str();
                a == client_id || trusted.iter().any(|t| t == a)
            });
            if !ok {
                return Err(SsoError::Verification(format!(
                    "ID token audience not trusted (audiences: {})",
                    auds.iter()
                        .map(|a| a.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )));
            }
        }

        // Extract raw ID token claims as JSON for custom claim lookup.
        // This avoids serde(flatten) which could let malicious claims shadow typed fields.
        let raw_id_token_claims = serde_json::to_value(&claims).ok();

        Ok(SsoResult {
            token: id_token,
            claims,
            userinfo_claims: None,
            raw_id_token_claims,
        })
    }

    /// Verify a raw ID token and map it to a SsoLoginResponse in one call.
    pub async fn verify_id_token_to_response(
        &self,
        id_token_str: &str,
    ) -> Result<crate::SsoLoginResponse, SsoError> {
        let result = self.verify_id_token(id_token_str).await?;
        Ok(crate::request::map_sso_result(&self.config, result).await)
    }

    pub async fn logout(&self, token: WarpgateIdToken, redirect_url: Url) -> Result<Url, SsoError> {
        let metadata = discover_metadata(&self.config, &self.http_client).await?;
        let Some(ref url) = metadata.additional_metadata().end_session_endpoint else {
            return Err(SsoError::LogoutNotSupported);
        };
        let mut req: LogoutRequest = url.clone().into();
        req = req.set_id_token_hint(&token);
        req = req.set_client_id(self.config.client_id().clone());
        req = req.set_post_logout_redirect_uri(PostLogoutRedirectUrl::from_url(redirect_url));
        Ok(req.http_get_url())
    }

    pub async fn verify_logout_token(&self, token: &str) -> Result<BackchannelLogout, SsoError> {
        let metadata = discover_metadata(&self.config, &self.http_client).await?;
        self.retry_on_unknown_key(&metadata, |metadata| {
            crate::logout_token::verify(&self.config, metadata, token)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use openidconnect::ClientId;
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::{
        AuthType, ClientSecret, GroupClaim, Reauth, SsoClient, advertises_secret_post,
        flatten_group_claim, resolve_auth_type, secret_survives_basic_auth, unix_now,
    };
    use crate::SsoInternalProviderConfig;
    use crate::logout_token::tests::{sign, signing_key};
    use crate::metadata::tests::metadata;

    fn survives(secret: &str) -> bool {
        secret_survives_basic_auth(&ClientSecret::new(secret.to_owned()))
    }

    #[test]
    fn url_safe_secrets_survive_basic_auth() {
        assert!(survives(""));
        assert!(survives("abcXYZ0189"));
        assert!(survives("a-b_c.d*e"));
    }

    #[test]
    fn secrets_needing_escaping_do_not() {
        // The characters from issue #1815, plus the rest of base64's alphabet
        // and a few that form-urlencoding also rewrites.
        for secret in ["a+b", "ab==", "a/b", "a b", "a:b", "a%b", "pä"] {
            assert!(!survives(secret), "{secret} was considered safe");
        }
    }

    #[test]
    fn secret_post_is_taken_from_the_discovery_document() {
        assert!(!advertises_secret_post(&metadata(&json!({}))));
        assert!(!advertises_secret_post(&metadata(&json!({
            "token_endpoint_auth_methods_supported": ["client_secret_basic"],
        }))));
        assert!(advertises_secret_post(&metadata(&json!({
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        }))));
    }

    fn resolved(secret: &str, extra: &serde_json::Value) -> AuthType {
        resolve_auth_type(
            AuthType::BasicAuth,
            &ClientSecret::new(secret.to_owned()),
            &metadata(extra),
        )
    }

    #[test]
    fn only_an_unsafe_secret_switches_to_secret_post() {
        let both = json!({
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        });

        assert!(matches!(resolved("urlsafe", &both), AuthType::BasicAuth));
        assert!(matches!(
            resolved("has+plus=", &both),
            AuthType::RequestBody
        ));
        // Nothing to switch to: basic auth is attempted and the admin is warned.
        assert!(matches!(
            resolved("has+plus=", &json!({})),
            AuthType::BasicAuth
        ));
    }

    fn flat(j: serde_json::Value) -> Vec<String> {
        flatten_group_claim(serde_json::from_value::<GroupClaim>(j).unwrap())
    }

    #[test]
    fn bare_string() {
        assert_eq!(flat(json!("a")), vec!["a".to_string()]);
    }

    #[test]
    fn array_of_strings_sorted() {
        assert_eq!(
            flat(json!(["b", "a"])),
            vec!["a".to_string(), "b".to_string()]
        );
    }

    #[test]
    fn single_object_value_and_display() {
        assert_eq!(
            flat(json!({"value": "id1", "display": "Admins"})),
            vec!["Admins".to_string(), "id1".to_string()]
        );
    }

    #[test]
    fn array_of_objects() {
        assert_eq!(
            flat(json!([
                {"value": "id1", "display": "Admins"},
                {"value": "id2", "display": "Users"}
            ])),
            vec![
                "Admins".to_string(),
                "Users".to_string(),
                "id1".to_string(),
                "id2".to_string()
            ]
        );
    }

    #[test]
    fn mixed_strings_and_partial_objects() {
        assert_eq!(
            flat(json!(["x", {"display": "D"}, {"value": "V"}])),
            vec!["D".to_string(), "V".to_string(), "x".to_string()]
        );
    }

    #[test]
    fn deduplicates() {
        assert_eq!(flat(json!(["a", "a"])), vec!["a".to_string()]);
    }

    #[test]
    fn empty_array() {
        assert!(flat(json!([])).is_empty());
    }

    #[test]
    fn object_without_value_or_display() {
        assert!(flat(json!([{"foo": "bar"}])).is_empty());
    }

    #[test]
    fn complex_mixed_objects_with_cross_dedup_and_spaces() {
        // value/display collisions across entries (e.g. two groups sharing a
        // display, a display equal to another entry's string) must all collapse
        // to a single sorted, de-duplicated set. A value containing a space
        // sorts before non-space characters.
        assert_eq!(
            flat(json!([
                "bla",
                {"value": "val1", "display": "dis1"},
                {"value": "val2", "display": "dis1"},
                {"value": "val1", "display": "dis2"},
                "bla2",
                {"value": "val 3", "display": "bla2"}
            ])),
            vec![
                "bla".to_string(),
                "bla2".to_string(),
                "dis1".to_string(),
                "dis2".to_string(),
                "val 3".to_string(),
                "val1".to_string(),
                "val2".to_string(),
            ]
        );
    }

    /// Answers one HTTP request: discovery, the key set, or the token endpoint
    /// handing back whatever `id_token` currently holds.
    async fn serve(mut socket: TcpStream, doc: &serde_json::Value, id_token: &Mutex<String>) {
        let mut received = Vec::new();
        let mut chunk = [0_u8; 1024];
        let (head, mut body_len) = loop {
            let text = String::from_utf8_lossy(&received).into_owned();
            if let Some((head, body)) = text.split_once("\r\n\r\n") {
                let wanted = head
                    .lines()
                    .filter_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(str::trim)
                            .map(str::to_owned)
                    })
                    .find_map(|value| value.parse::<usize>().ok())
                    .unwrap_or(0);
                break (head.to_owned(), wanted.saturating_sub(body.len()));
            }
            match socket.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => received.extend(chunk.iter().take(n)),
            }
        };
        while body_len > 0 {
            match socket.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => body_len = body_len.saturating_sub(n),
            }
        }
        let path = head
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap_or_default();
        let body = match path {
            "/.well-known/openid-configuration" => doc["discovery"].to_string(),
            "/jwks" => doc["jwks"].to_string(),
            "/token" => serde_json::json!({
                "access_token": "access",
                "token_type": "bearer",
                "id_token": id_token.lock().unwrap().clone(),
            })
            .to_string(),
            _ => String::new(),
        };
        let status = if body.is_empty() {
            "404 Not Found"
        } else {
            "200 OK"
        };
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = socket.write_all(response.as_bytes()).await;
        let _ = socket.shutdown().await;
    }

    /// An identity provider on a loopback port that signs ID tokens with a
    /// fresh P-256 key. The token its token endpoint returns is whatever the
    /// test last put in the returned slot.
    async fn stand_in_idp() -> (
        SsoInternalProviderConfig,
        Arc<Mutex<String>>,
        jsonwebtoken::EncodingKey,
    ) {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        let (jwks, key) = signing_key();
        let doc = serde_json::json!({
            "jwks": jwks,
            "discovery": {
                "issuer": issuer,
                "authorization_endpoint": format!("{issuer}/authorize"),
                "token_endpoint": format!("{issuer}/token"),
                "jwks_uri": format!("{issuer}/jwks"),
                "response_types_supported": ["code"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["ES256"],
            },
        });
        let id_token = Arc::new(Mutex::new(String::new()));
        let slot = id_token.clone();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let doc = doc.clone();
                let id_token = id_token.clone();
                tokio::spawn(async move { serve(socket, &doc, &id_token).await });
            }
        });
        let config = serde_json::from_value(serde_json::json!({
            "type": "custom",
            "client_id": "warpgate",
            "client_secret": "secret",
            "issuer_url": issuer,
            "scopes": [],
        }))
        .unwrap();
        (config, slot, key)
    }

    /// ID token claims for `nonce`, issued by the stand-in provider now.
    fn id_token_claims(
        config: &SsoInternalProviderConfig,
        nonce: &str,
        auth_time: Option<i64>,
    ) -> serde_json::Value {
        let now = unix_now();
        let mut claims = serde_json::json!({
            "iss": config.issuer_url().unwrap().to_string(),
            "sub": "alice",
            "aud": "warpgate",
            "iat": now,
            "exp": now + 300,
            "nonce": nonce,
        });
        if let Some(auth_time) = auth_time {
            claims["auth_time"] = serde_json::json!(auth_time);
        }
        claims
    }

    const RETURN_URL: &str = "http://localhost/sso/return";

    #[tokio::test]
    async fn id_token_auth_time_reaches_login_response() {
        let (config, slot, key) = stand_in_idp().await;
        let client = SsoClient::new(config.clone()).unwrap();
        let auth_time = unix_now() - 3600;

        let request = client
            .start_login(RETURN_URL.into(), Reauth::None)
            .await
            .unwrap();
        let nonce = request.nonce.secret().clone();
        *slot.lock().unwrap() = sign(
            &key,
            "k1",
            &id_token_claims(&config, &nonce, Some(auth_time)),
        );
        let response = request.verify_code("code".into()).await.unwrap();
        assert_eq!(response.auth_time, Some(auth_time));

        // A token that does not say when the user logged in carries none.
        let request = client
            .start_login(RETURN_URL.into(), Reauth::None)
            .await
            .unwrap();
        let nonce = request.nonce.secret().clone();
        *slot.lock().unwrap() = sign(&key, "k1", &id_token_claims(&config, &nonce, None));
        let response = request.verify_code("code".into()).await.unwrap();
        assert_eq!(response.auth_time, None);
    }

    #[tokio::test]
    async fn token_with_another_handshakes_nonce_is_refused() {
        let (config, slot, key) = stand_in_idp().await;
        let client = SsoClient::new(config.clone()).unwrap();

        let ours = client
            .start_login(RETURN_URL.into(), Reauth::None)
            .await
            .unwrap();
        let theirs = client
            .start_login(RETURN_URL.into(), Reauth::None)
            .await
            .unwrap();
        let their_nonce = theirs.nonce.secret().clone();
        *slot.lock().unwrap() = sign(
            &key,
            "k1",
            &id_token_claims(&config, &their_nonce, Some(unix_now())),
        );

        assert!(ours.verify_code("code".into()).await.is_err());
        // The same token is good for the handshake it was issued to.
        assert!(theirs.verify_code("code".into()).await.is_ok());
    }

    #[tokio::test]
    async fn forced_return_refuses_replayed_older_id_token() {
        let (config, slot, key) = stand_in_idp().await;
        let client = SsoClient::new(config.clone()).unwrap();

        // Handshake A completes normally, with a login from an hour ago.
        let an_hour_ago = unix_now() - 3600;
        let a = client
            .start_login(RETURN_URL.into(), Reauth::None)
            .await
            .unwrap();
        let a_token = sign(
            &key,
            "k1",
            &id_token_claims(&config, a.nonce.secret(), Some(an_hour_ago)),
        );
        *slot.lock().unwrap() = a_token.clone();
        assert_eq!(
            a.verify_code("code".into()).await.unwrap().auth_time,
            Some(an_hour_ago)
        );

        // Handshake B is forced. A's valid token, replayed on B's return, is
        // refused and yields no response, so no `auth_time` reaches a caller.
        let b = client
            .start_login(RETURN_URL.into(), Reauth::Force)
            .await
            .unwrap();
        assert!(b.forced());
        *slot.lock().unwrap() = a_token;
        let result = b.verify_code("code".into()).await;
        assert!(result.is_err(), "replayed token must be refused");
    }

    #[tokio::test]
    async fn a_bearer_token_response_never_carries_auth_time() {
        let (config, _, key) = stand_in_idp().await;
        let client = SsoClient::new(config.clone()).unwrap();
        // Signed, audience-correct and carrying an auth_time, but bound to no
        // handshake of ours: it must not be usable as a stamp.
        let token = sign(
            &key,
            "k1",
            &id_token_claims(&config, "unrelated", Some(unix_now())),
        );
        let response = client.verify_id_token_to_response(&token).await.unwrap();
        assert_eq!(response.auth_time, None);
    }

    fn query(request: &crate::SsoLoginRequest) -> Vec<(String, String)> {
        request
            .auth_url()
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect()
    }

    fn has(query: &[(String, String)], key: &str, value: &str) -> bool {
        query.iter().any(|(k, v)| k == key && v == value)
    }

    #[tokio::test]
    async fn force_puts_prompt_login_and_max_age_zero_in_the_authorize_url() {
        let (config, _, _) = stand_in_idp().await;
        let client = SsoClient::new(config).unwrap();
        let before = unix_now();
        let request = client
            .start_login(RETURN_URL.into(), Reauth::Force)
            .await
            .unwrap();
        let query = query(&request);
        assert!(has(&query, "prompt", "login"), "{query:?}");
        assert!(has(&query, "max_age", "0"), "{query:?}");
        assert!(request.forced());
        assert!((before..=unix_now()).contains(&request.started_at()));
    }

    #[tokio::test]
    async fn a_reauth_request_asks_for_auth_time_in_the_id_token() {
        let (config, _, _) = stand_in_idp().await;
        let client = SsoClient::new(config).unwrap();
        for reauth in [Reauth::Force, Reauth::MaxAge(Duration::from_secs(3600))] {
            let request = client
                .start_login(RETURN_URL.into(), reauth)
                .await
                .unwrap();
            let query = query(&request);
            assert!(
                has(
                    &query,
                    "claims",
                    r#"{"id_token":{"auth_time":{"essential":true}}}"#
                ),
                "{query:?}"
            );
        }
        let request = client
            .start_login(RETURN_URL.into(), Reauth::None)
            .await
            .unwrap();
        assert!(!query(&request).iter().any(|(k, _)| k == "claims"));
    }

    #[test]
    fn google_takes_no_prompt_login() {
        let google = SsoInternalProviderConfig::Google {
            client_id: ClientId::new("c".into()),
            client_secret: ClientSecret::new("s".into()),
            service_account_email: None,
            service_account_key: None,
            admin_email: None,
            role_mappings: None,
            admin_role_mappings: None,
        };
        assert!(!google.supports_prompt_login());
    }

    #[tokio::test]
    async fn max_age_puts_max_age_and_no_prompt_in_the_authorize_url() {
        let (config, _, _) = stand_in_idp().await;
        let client = SsoClient::new(config).unwrap();
        let request = client
            .start_login(RETURN_URL.into(), Reauth::MaxAge(Duration::from_secs(3600)))
            .await
            .unwrap();
        let query = query(&request);
        assert!(has(&query, "max_age", "3600"), "{query:?}");
        assert!(!query.iter().any(|(k, _)| k == "prompt"), "{query:?}");
        assert!(!request.forced());
    }

    #[tokio::test]
    async fn no_reauth_leaves_the_authorize_url_as_it_was() {
        let (config, _, _) = stand_in_idp().await;
        let client = SsoClient::new(config).unwrap();
        let request = client
            .start_login(RETURN_URL.into(), Reauth::None)
            .await
            .unwrap();
        let query = query(&request);
        assert!(
            !query.iter().any(|(k, _)| k == "prompt" || k == "max_age"),
            "{query:?}"
        );
        assert!(!request.forced());
    }
}
