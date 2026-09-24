use std::collections::HashSet;
use std::fmt::Write;
use std::future::Future;
use std::net::IpAddr;

use data_encoding::HEXLOWER;
use rand::RngExt;
use sha2::Digest;
use time::OffsetDateTime;
use tokio::sync::broadcast;
use tracing::{debug, info};
use url::Url;
use uuid::Uuid;

use super::{
    ApprovalKind, AuthCredential, CredentialKind, CredentialPolicy, CredentialPolicyResponse,
    StoredCredential, StoredCredentialKind, ValidCredential,
};
use crate::helpers::logging::format_related_ids;
use crate::{Protocol, User, UserSessionId, WarpgateError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthResult {
    Accepted { user_info: AuthStateUserInfo },
    Need(HashSet<CredentialKind>),
    Rejected,
}

/// The outcome of submitting a single credential: whether *that credential*
/// passed validation, alongside the resulting overall verification state.
///
/// The two are independent: a wrong credential leaves the state as it was
/// (typically `Need(..)`, not `Rejected`), and a wrong extra credential on an
/// already-satisfied policy yields `Invalid(Accepted { .. })`. Brute-force
/// accounting must key off credential validity, never off the overall state.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitOutcome {
    /// The credential passed validation and was recorded.
    Valid(AuthResult),
    /// The credential failed validation; the auth state is unchanged.
    Invalid(AuthResult),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedSubmission {
    /// Whether the specific credential failed validation. False when
    /// the cred was ok but the policy requires more
    pub credential_rejected: bool,
    pub state: AuthResult,
}

impl SubmitOutcome {
    pub const fn is_valid(&self) -> bool {
        matches!(self, Self::Valid(_))
    }

    pub const fn result(&self) -> &AuthResult {
        match self {
            Self::Valid(result) | Self::Invalid(result) => result,
        }
    }

    // Protects against an Invalid(Accepted) from authorising a session
    pub fn into_accepted(self) -> Result<AuthStateUserInfo, RejectedSubmission> {
        match self {
            Self::Valid(AuthResult::Accepted { user_info }) => Ok(user_info),
            Self::Valid(state) => Err(RejectedSubmission {
                credential_rejected: false,
                state,
            }),
            Self::Invalid(state) => Err(RejectedSubmission {
                credential_rejected: true,
                state,
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthStateUserInfo {
    pub id: Uuid,
    pub username: String,
}

/// What a login is asking a remembered approval for. Explicit rather than an
/// `Option`, because "no target yet" is a real bucket of its own: an untargeted
/// grant must not stand in for approval of an actual target.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum WebApprovalScopeKey {
    /// The flow isn't target-scoped: an HTTP portal sign-in, or SSH before the
    /// menu selection.
    Untargeted,
    /// Bound to a single target.
    Target(String),
}

/// A sorted, deduplicated, equatable set of the stored credentials an
/// authentication was made with — what a "remember approval" decision is
/// keyed on.
///
/// A web approval cannot appear here by construction: the set is built through
/// [`ValidCredential::stored`], and an approval has no stored row. A login
/// whose only factor is the approval itself therefore keys on the empty set,
/// which leaves the remembered grant scoped by origin, protocol and username —
/// the same scope the approval prompt offers to remember.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StoredCredentials(Vec<StoredCredential>);

impl StoredCredentials {
    #[must_use]
    pub fn new(mut credentials: Vec<StoredCredential>) -> Self {
        credentials.sort_unstable();
        credentials.dedup();
        Self(credentials)
    }

    /// A stable digest for the credential set (for matching)
    #[must_use]
    pub fn digest(&self) -> String {
        // Version 2 keys on stored rows; version 1 keyed on verifier hashes
        // alone. Bump this with any encoding change — every remembered approval
        // in flight stops matching, which is the intended, fail-closed effect.
        let mut bytes = vec![2];

        for credential in &self.0 {
            credential.write_canonical_bytes(&mut bytes);
        }

        let digest = sha2::Sha256::digest(&bytes);
        HEXLOWER.encode(&digest)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RememberApprovalBy {
    /// Approval can be reused if this credential set matches
    Credentials(StoredCredentials),
    /// Never remembered: the connection has no auth state to key on (ticket
    /// logins, gateway web clients).
    Nothing,
}

impl RememberApprovalBy {
    #[must_use]
    pub fn from_credentials(credentials: Vec<StoredCredential>) -> Self {
        Self::Credentials(StoredCredentials::new(credentials))
    }

    #[must_use]
    pub const fn credentials(&self) -> Option<&StoredCredentials> {
        match self {
            Self::Credentials(credentials) => Some(credentials),
            Self::Nothing => None,
        }
    }
}

/// The exact identity half of a remember approval key
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WebApprovalIdentity {
    kind: ApprovalKind,
    remote_ip: IpAddr,
    protocol: Protocol,
    username: String,
    other_credentials: StoredCredentials,
}

impl WebApprovalIdentity {
    #[must_use]
    pub fn digest(&self) -> String {
        let mut bytes = vec![1]; // version tag
        // Length-prefix everything to avoid collisions via string boundaries
        let mut push = |part: &[u8]| {
            bytes.extend_from_slice(&(part.len() as u64).to_le_bytes());
            bytes.extend_from_slice(part);
        };

        push(&[self.kind as u8]);
        push(self.remote_ip.to_string().as_bytes());
        push(self.protocol.to_string().as_bytes());
        push(self.username.as_bytes());
        push(self.other_credentials.digest().as_bytes());

        HEXLOWER.encode(&sha2::Sha256::digest(&bytes))
    }

    pub fn kind(&self) -> ApprovalKind {
        self.kind
    }

    pub fn remote_ip(&self) -> IpAddr {
        self.remote_ip
    }

    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn other_credentials(&self) -> &StoredCredentials {
        &self.other_credentials
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WebApprovalMatchKey {
    // compared by "scope is narrower", so it cannot be a part of the digest
    scope: WebApprovalScopeKey,
    // compared by equality
    identity: WebApprovalIdentity,
}

impl WebApprovalMatchKey {
    #[must_use]
    pub fn build(
        kind: ApprovalKind,
        remote_ip: IpAddr,
        protocol: Protocol,
        username: &str,
        target_name: &str,
        remember_by: &RememberApprovalBy,
    ) -> Option<Self> {
        Some(Self {
            scope: if target_name.is_empty() {
                // currenrly, only the SSH menu can do this
                WebApprovalScopeKey::Untargeted
            } else {
                WebApprovalScopeKey::Target(target_name.to_string())
            },
            identity: WebApprovalIdentity {
                kind,
                remote_ip,
                protocol,
                username: username.to_lowercase(),
                other_credentials: remember_by.credentials()?.clone(),
            },
        })
    }

    pub fn identity(&self) -> &WebApprovalIdentity {
        &self.identity
    }

    pub fn scope(&self) -> &WebApprovalScopeKey {
        &self.scope
    }
}

impl From<&User> for AuthStateUserInfo {
    fn from(user: &User) -> Self {
        Self {
            id: user.id,
            username: user.username.clone(),
        }
    }
}

pub struct AuthState {
    session_id: UserSessionId,
    user_info: AuthStateUserInfo,
    remote_ip: Option<IpAddr>,
    protocol: Protocol,
    target_name: String,
    force_rejected: bool,
    policy: Box<dyn CredentialPolicy + Sync + Send>,
    valid_credentials: Vec<ValidCredential>,
    started: OffsetDateTime,
    identification_string: String,
    last_result: Option<AuthResult>,
    state_change_signal: broadcast::Sender<AuthResult>,
    authenticated_event_emitted: bool,
    /// True when a step-up gate has decided the current credentials are
    /// insufficient and a `WebUserApproval` must arrive before `verify()`
    /// reports `Accepted`. Without this flag the browser's
    /// `/api/auth/state/:id` poll would see `Accepted` (because the pubkey
    /// already validated) and the UI would hide the Authorize button.
    /// Cleared in `add_web_user_approval` when one lands.
    pending_step_up: bool,
    /// True when the `WebUserApproval` in `valid_credentials` was not collected
    /// by this attempt at all, but injected by the grace-period bypass from an
    /// approval remembered for an *earlier* attempt
    /// (`Services::try_web_approval_bypass`). Such an approval proves nothing
    /// about SSO freshness, so the SSH step-up gate must neither treat it as
    /// satisfying the gate nor stamp `last_sso_at` from it - otherwise chained
    /// reconnects inside the grace window slide the step-up window forward
    /// forever with no SSO handshake ever happening.
    /// Cleared again by a real `add_web_user_approval`.
    web_approval_from_grace_bypass: bool,
}

fn generate_identification_string() -> String {
    let mut s = String::new();
    let mut rng = rand::rng();
    for _ in 0..4 {
        let _ = write!(&mut s, "{:X}", rng.random_range(0..16));
    }
    s
}

impl AuthState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: UserSessionId,
        remote_ip: Option<IpAddr>,
        user_info: AuthStateUserInfo,
        protocol: Protocol,
        target_name: String,
        policy: Box<dyn CredentialPolicy + Sync + Send>,
        state_change_signal: broadcast::Sender<AuthResult>,
    ) -> Self {
        let mut this = Self {
            session_id,
            remote_ip,
            user_info,
            protocol,
            target_name,
            force_rejected: false,
            policy,
            valid_credentials: vec![],
            started: OffsetDateTime::now_utc(),
            identification_string: generate_identification_string(),
            last_result: None,
            state_change_signal,
            authenticated_event_emitted: false,
            pending_step_up: false,
            web_approval_from_grace_bypass: false,
        };
        this.maybe_update_verification_state();
        this
    }

    pub const fn session_id(&self) -> &UserSessionId {
        &self.session_id
    }

    pub const fn user_info(&self) -> &AuthStateUserInfo {
        &self.user_info
    }

    pub const fn protocol(&self) -> Protocol {
        self.protocol
    }

    pub const fn remote_ip(&self) -> Option<IpAddr> {
        self.remote_ip
    }

    pub fn target_name(&self) -> &str {
        &self.target_name
    }

    /// Best possible "remember by" key for approving this AuthState
    #[must_use]
    pub fn remembered_by(&self) -> RememberApprovalBy {
        RememberApprovalBy::from_credentials(
            self.valid_credentials
                .iter()
                .filter_map(ValidCredential::stored)
                .copied()
                .collect(),
        )
    }

    /// Builds the key used to match this attempt against a remembered web
    /// approval.
    pub fn web_approval_match_key(&self) -> Option<WebApprovalMatchKey> {
        self.remote_ip.and_then(|ip| {
            WebApprovalMatchKey::build(
                ApprovalKind::User,
                ip,
                self.protocol,
                &self.user_info.username,
                &self.target_name,
                &self.remembered_by(),
            )
        })
    }

    pub const fn started(&self) -> &OffsetDateTime {
        &self.started
    }

    pub fn identification_string(&self) -> &str {
        &self.identification_string
    }

    /// Mark this state as requiring a `WebUserApproval` step-up. The SSH
    /// handler calls this when `step_up_interval.ssh` is set and the matched
    /// pubkey's `last_sso_at` is stale. After this flag is set, `verify()`
    /// reports `Need({WebUserApproval})` until a real one arrives - which is
    /// what the browser approve UI and the pending-request listing both key
    /// off. Fires the state-change signal so listening UIs get the new status.
    pub fn require_step_up(&mut self) {
        if !self.pending_step_up {
            self.pending_step_up = true;
            self.maybe_update_verification_state();
        }
    }

    /// Whether a step-up gate has fired on this state and is still waiting for
    /// its `WebUserApproval`.
    ///
    /// A step-up `Need` means "prove *this* credential just did a fresh SSO
    /// handshake". It is deliberately distinguishable from a policy-raised
    /// `Need(WebUserApproval)` so that the web-approval grace-period bypass
    /// (`Services::try_web_approval_bypass`) can refuse to satisfy it from a
    /// remembered approval on another session - which would defeat the
    /// per-credential freshness guarantee the gate exists to provide.
    #[must_use]
    pub const fn is_step_up_pending(&self) -> bool {
        self.pending_step_up
    }

    /// The row ids of the stored public keys validated so far in this
    /// attempt. The SSH step-up gate reads and stamps `last_sso_at` on the
    /// matched row; more than one id is unexpected and the gate treats it
    /// as stale.
    #[must_use]
    pub fn matched_public_key_ids(&self) -> Vec<Uuid> {
        self.valid_credentials
            .iter()
            .filter_map(ValidCredential::stored)
            .filter(|stored| stored.kind() == StoredCredentialKind::PublicKey)
            .map(StoredCredential::id)
            .collect()
    }

    /// Runs `validate` on the credential and records it only if it passes.
    /// This is the sole path for adding a credential that requires validation,
    /// so a credential in `valid_credentials` is validated by construction.
    ///
    /// validate() should return None for rejected credentials
    pub async fn submit_credential<F, Fut>(
        &mut self,
        credential: AuthCredential,
        validate: F,
    ) -> Result<SubmitOutcome, WarpgateError>
    where
        F: FnOnce(String, AuthCredential) -> Fut,
        Fut: Future<Output = Result<Option<StoredCredential>, WarpgateError>>,
    {
        if let Some(stored) = validate(self.user_info.username.clone(), credential.clone()).await? {
            self.valid_credentials.push(ValidCredential::Stored(stored));
            Ok(SubmitOutcome::Valid(self.maybe_update_verification_state()))
        } else {
            self.emit_authentication_failed_event(Some(&credential), "invalid credential");
            Ok(SubmitOutcome::Invalid(self.current_verification_state()))
        }
    }

    /// Records a web user approval. Unlike other credential kinds, the act of
    /// approval is itself the validation, so there is nothing to check.
    ///
    /// This is the *real* approval path - a human just approved this attempt -
    /// so it also clears the step-up flag and any earlier bypass marking.
    pub fn add_web_user_approval(&mut self) -> AuthResult {
        self.pending_step_up = false;
        self.web_approval_from_grace_bypass = false;
        self.valid_credentials
            .push(ValidCredential::WebUserApproval);
        self.maybe_update_verification_state()
    }

    /// Records a web user approval that came from the grace-period bypass
    /// rather than from a human approving *this* attempt.
    ///
    /// Behaves exactly like [`Self::add_web_user_approval`] for policy
    /// purposes - the credential is present and the policy is satisfied - but
    /// marks the state so the SSH step-up gate can tell the two apart. See
    /// [`Self::web_approval_from_grace_bypass`].
    pub fn add_web_user_approval_via_grace_bypass(&mut self) -> AuthResult {
        self.web_approval_from_grace_bypass = true;
        self.valid_credentials
            .push(ValidCredential::WebUserApproval);
        self.maybe_update_verification_state()
    }

    /// Whether the `WebUserApproval` credential on this state (if any) was
    /// injected by the grace-period bypass instead of being collected by this
    /// attempt.
    ///
    /// The SSH step-up gate reads this to refuse to count a bypassed approval
    /// as a fresh SSO handshake: it neither satisfies the freshness gate nor
    /// stamps `last_sso_at`.
    #[must_use]
    pub const fn web_approval_from_grace_bypass(&self) -> bool {
        self.web_approval_from_grace_bypass
    }

    /// Whether a web approval collected by *this* attempt is present, as
    /// opposed to none or only one injected by the grace-period bypass.
    #[must_use]
    pub fn has_real_web_approval(&self) -> bool {
        !self.web_approval_from_grace_bypass
            && self
                .valid_credentials
                .contains(&ValidCredential::WebUserApproval)
    }

    pub fn reject(&mut self) {
        self.force_rejected = true;
        self.maybe_update_verification_state();
    }

    pub fn verify(&self) -> AuthResult {
        self.current_verification_state()
    }

    /// Receives every verification-state change, including the terminal
    /// `Accepted` / `Rejected`. Sends happen while the state's lock is held,
    /// so subscribing under that lock cannot miss a transition.
    pub fn subscribe(&self) -> broadcast::Receiver<AuthResult> {
        self.state_change_signal.subscribe()
    }

    /// The set of credential kinds that have been validated so far during
    /// this auth attempt.
    #[must_use]
    pub fn valid_credential_kinds(&self) -> HashSet<CredentialKind> {
        self.valid_credentials
            .iter()
            .map(ValidCredential::kind)
            .collect()
    }

    fn valid_credentials_description(&self) -> String {
        self.valid_credentials
            .iter()
            .map(ValidCredential::readable_description)
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn client_ip_for_logging(&self) -> String {
        self.remote_ip
            .map_or_else(|| "<unknown>".to_string(), |x| x.to_string())
    }

    pub fn emit_authenticated_event_once(&mut self) {
        if self.authenticated_event_emitted {
            return;
        }

        let AuthResult::Accepted { .. } = self.current_verification_state() else {
            return;
        };

        info!(
            target: "audit",
            _type = "UserAuthenticated1",
            session = %self.session_id,
            client_ip = %self.client_ip_for_logging(),
            user_id = %self.user_info.id,
            username = %self.user_info.username,
            credentials = %self.valid_credentials_description(),
            related_users = %format_related_ids(&[self.user_info.id]),
            "Authenticated",
        );

        self.authenticated_event_emitted = true;
    }

    pub fn emit_web_approval_bypassed_event(&self) {
        info!(
            target: "audit",
            _type = "WebApprovalBypassed1",
            session = %self.session_id,
            client_ip = %self.client_ip_for_logging(),
            user_id = %self.user_info.id,
            username = %self.user_info.username,
            protocol = %self.protocol,
            target = %self.target_name,
            related_users = %format_related_ids(&[self.user_info.id]),
            "Web approval bypassed within grace period",
        );
    }

    pub fn emit_authentication_failed_event(
        &self,
        credential: Option<&AuthCredential>,
        reason: &str,
    ) {
        let credentials = credential.map_or_else(
            || "<unknown>".to_string(),
            AuthCredential::readable_description,
        );

        info!(
            target: "audit",
            _type = "UserAuthenticationFailed1",
            session = %self.session_id,
            client_ip = %self.client_ip_for_logging(),
            user_id = %self.user_info.id,
            username = %self.user_info.username,
            credentials = %credentials,
            reason = %reason,
            related_users = %format_related_ids(&[self.user_info.id]),
            "Authentication failed",
        );
    }

    fn current_verification_state(&self) -> AuthResult {
        if self.force_rejected {
            return AuthResult::Rejected;
        }
        if self.pending_step_up && !self.has_real_web_approval() {
            // A step-up gate has fired but no real WebUserApproval has landed
            // yet. Short-circuit the policy so the browser's approve page
            // renders the Authorize button and the approval wakes the SSH
            // session.
            return AuthResult::Need(HashSet::from([CredentialKind::WebUserApproval]));
        }
        match self
            .policy
            .is_sufficient(self.protocol, &self.valid_credential_kinds())
        {
            CredentialPolicyResponse::Ok => AuthResult::Accepted {
                user_info: self.user_info.clone(),
            },
            CredentialPolicyResponse::Need(kinds) => AuthResult::Need(kinds),
        }
    }

    fn maybe_update_verification_state(&mut self) -> AuthResult {
        let new_result = self.current_verification_state();
        if self.last_result.as_ref() != Some(&new_result) {
            self.emit_authenticated_event_once();
            debug!(
                "Verification state changed for auth state {}: {:?} -> {:?}",
                self.session_id, self.last_result, &new_result
            );
            let _ = self.state_change_signal.send(new_result.clone());
            self.last_result = Some(new_result.clone());
        }

        new_result
    }

    pub fn construct_web_approval_url(&self, mut external_url: Url) -> url::Url {
        external_url.set_path("@warpgate");
        external_url.set_fragment(Some(&format!("/login/{}", self.session_id())));
        external_url
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Secret;
    use crate::auth::{StoredCredentialFingerprint, StoredCredentialKind};

    fn stored_credential(byte: u8) -> StoredCredential {
        StoredCredential::new(
            StoredCredentialKind::Password,
            Uuid::from_u128(u128::from(byte)),
            StoredCredentialFingerprint::of_stored_verifier([byte; 32].as_slice()),
        )
    }

    fn fingerprints(byte: u8) -> StoredCredentials {
        #[allow(clippy::expect_used)]
        StoredCredentials::new(vec![stored_credential(byte)])
    }

    fn identity() -> WebApprovalIdentity {
        WebApprovalIdentity {
            kind: ApprovalKind::Admin,
            remote_ip: "10.0.0.1".parse().unwrap(),
            protocol: Protocol::Ssh,
            username: "someone".into(),
            other_credentials: fingerprints(1),
        }
    }

    /// The digest is what a remembered approval is matched by, so two sessions
    /// differing in any part of their identity must not share one.
    #[test]
    fn every_part_of_the_identity_reaches_the_digest() {
        let base = identity();
        let differing = [
            WebApprovalIdentity {
                kind: ApprovalKind::User,
                ..identity()
            },
            WebApprovalIdentity {
                remote_ip: "10.0.0.2".parse().unwrap(),
                ..identity()
            },
            WebApprovalIdentity {
                protocol: Protocol::Http,
                ..identity()
            },
            WebApprovalIdentity {
                username: "someone-else".into(),
                ..identity()
            },
            WebApprovalIdentity {
                other_credentials: fingerprints(2),
                ..identity()
            },
        ];

        for altered in differing {
            assert_ne!(
                base.digest(),
                altered.digest(),
                "identities differing in one field must not share a digest: {altered:?}",
            );
        }
    }

    /// A policy whose only factor is the approval itself lands here: the grant
    /// is still rememberable, keyed on the empty set, and that key is its own —
    /// it must not match a login that did present a credential.
    #[test]
    fn an_empty_credential_set_is_remembered_as_its_own_key() {
        let empty = RememberApprovalBy::from_credentials(vec![]);
        assert_eq!(
            empty,
            RememberApprovalBy::Credentials(StoredCredentials::new(vec![]))
        );
        assert_ne!(
            StoredCredentials::new(vec![]).digest(),
            fingerprints(1).digest()
        );
    }

    #[test]
    fn credential_sets_key_the_same_whatever_the_order() {
        let a = stored_credential(1);
        let b = stored_credential(2);
        assert_eq!(
            StoredCredentials::new(vec![a, b, a]),
            StoredCredentials::new(vec![b, a]),
        );
    }

    struct RequireAll(HashSet<CredentialKind>);

    impl CredentialPolicy for RequireAll {
        fn is_sufficient(
            &self,
            _protocol: Protocol,
            valid_credentials: &HashSet<CredentialKind>,
        ) -> CredentialPolicyResponse {
            let needed: HashSet<CredentialKind> =
                self.0.difference(valid_credentials).copied().collect();
            if needed.is_empty() {
                CredentialPolicyResponse::Ok
            } else {
                CredentialPolicyResponse::Need(needed)
            }
        }
    }

    fn make_state(kinds: &[CredentialKind]) -> AuthState {
        AuthState::new(
            UserSessionId(Uuid::new_v4()),
            None,
            AuthStateUserInfo {
                id: Uuid::new_v4(),
                username: "alice".into(),
            },
            Protocol::Ssh,
            "target".into(),
            Box::new(RequireAll(kinds.iter().copied().collect())),
            broadcast::channel(8).0,
        )
    }

    fn password() -> AuthCredential {
        AuthCredential::Password(Secret::new("pw".into()))
    }

    #[tokio::test]
    async fn valid_credential_is_recorded() {
        let mut state = make_state(&[CredentialKind::Password]);
        let outcome = state
            .submit_credential(password(), |_, _| async { Ok(Some(stored_credential(1))) })
            .await
            .unwrap();
        assert!(outcome.is_valid());
        assert!(matches!(outcome.result(), AuthResult::Accepted { .. }));
        assert!(matches!(state.verify(), AuthResult::Accepted { .. }));
    }

    #[tokio::test]
    async fn invalid_credential_leaves_state_unchanged() {
        let mut state = make_state(&[CredentialKind::Password]);
        let outcome = state
            .submit_credential(password(), |_, _| async { Ok(None) })
            .await
            .unwrap();
        assert!(!outcome.is_valid());
        assert!(matches!(
            outcome.result(),
            AuthResult::Need(needed) if needed.contains(&CredentialKind::Password)
        ));
        assert!(matches!(
            state.verify(),
            AuthResult::Need(needed) if needed.contains(&CredentialKind::Password)
        ));
    }

    #[tokio::test]
    async fn invalid_extra_credential_keeps_accepted_state() {
        let mut state = make_state(&[CredentialKind::Password]);
        let _ = state
            .submit_credential(password(), |_, _| async { Ok(Some(stored_credential(1))) })
            .await
            .unwrap();
        let outcome = state
            .submit_credential(password(), |_, _| async { Ok(None) })
            .await
            .unwrap();
        assert!(!outcome.is_valid());
        assert!(matches!(outcome.result(), AuthResult::Accepted { .. }));

        // ...and `into_accepted` refuses to hand back the user for it, so an
        // invalid extra credential can never (re-)authorize the session.
        let rejection = outcome.into_accepted().unwrap_err();
        assert!(rejection.credential_rejected);
        assert!(matches!(rejection.state, AuthResult::Accepted { .. }));
    }

    #[tokio::test]
    async fn into_accepted_yields_user_only_on_valid_success() {
        let mut state = make_state(&[CredentialKind::Password]);
        let outcome = state
            .submit_credential(password(), |_, _| async { Ok(Some(stored_credential(1))) })
            .await
            .unwrap();
        assert!(outcome.into_accepted().is_ok());
    }

    #[tokio::test]
    async fn validator_error_records_nothing() {
        let mut state = make_state(&[CredentialKind::Password]);
        let result = state
            .submit_credential(password(), |_, _| async {
                Err(WarpgateError::UserNotFound("alice".into()))
            })
            .await;
        assert!(result.is_err());
        assert!(matches!(state.verify(), AuthResult::Need(_)));
    }

    #[tokio::test]
    async fn reject_broadcasts_and_is_sticky() {
        let mut state = make_state(&[CredentialKind::WebUserApproval]);
        let mut rx = state.subscribe();
        state.reject();
        assert!(matches!(rx.recv().await.unwrap(), AuthResult::Rejected));
        let _ = state.add_web_user_approval();
        assert!(matches!(state.verify(), AuthResult::Rejected));
    }

    #[tokio::test]
    async fn web_approval_accepts_and_broadcasts() {
        let mut state = make_state(&[CredentialKind::WebUserApproval]);
        let mut rx = state.subscribe();
        assert!(matches!(
            state.add_web_user_approval(),
            AuthResult::Accepted { .. }
        ));
        assert!(matches!(
            rx.recv().await.unwrap(),
            AuthResult::Accepted { .. }
        ));
    }

    #[test]
    fn unit_require_step_up_overrides_accepted_verdict() {
        // Without the override, a policy-satisfied state verifies as Accepted
        // and the browser approve page hides the Authorize button. With
        // require_step_up() the verdict flips to Need(WebUserApproval) until
        // one lands, which is the contract the approve flow relies on.
        let mut state = make_state(&[CredentialKind::WebUserApproval]);
        let _ = state.add_web_user_approval();
        assert!(matches!(state.verify(), AuthResult::Accepted { .. }));

        // A fresh state on the same policy, gated by a step-up.
        let mut state = make_state(&[CredentialKind::WebUserApproval]);
        state.require_step_up();
        assert!(state.is_step_up_pending());
        let AuthResult::Need(needed) = state.verify() else {
            panic!("expected Need");
        };
        assert!(needed.contains(&CredentialKind::WebUserApproval));

        let _ = state.add_web_user_approval();
        assert!(!state.is_step_up_pending());
        assert!(
            matches!(state.verify(), AuthResult::Accepted { .. }),
            "WebUserApproval must clear the step-up flag"
        );
    }

    /// An approval injected by the grace-period bypass is not a fresh SSO: it
    /// cannot satisfy a pending step-up, and it is reported as bypassed so the
    /// gate neither passes on it nor stamps from it.
    #[test]
    fn unit_bypassed_approval_does_not_satisfy_a_pending_step_up() {
        let mut state = make_state(&[CredentialKind::WebUserApproval]);
        let _ = state.add_web_user_approval_via_grace_bypass();
        assert!(state.web_approval_from_grace_bypass());
        assert!(!state.has_real_web_approval());
        // For the policy alone, a bypassed approval still counts.
        assert!(matches!(state.verify(), AuthResult::Accepted { .. }));

        state.require_step_up();
        assert!(matches!(state.verify(), AuthResult::Need(_)));

        let _ = state.add_web_user_approval();
        assert!(!state.web_approval_from_grace_bypass());
        assert!(state.has_real_web_approval());
        assert!(matches!(state.verify(), AuthResult::Accepted { .. }));
    }

    /// The gate addresses the exact public-key row that matched, which now
    /// comes from upstream's `StoredCredential` rather than a copy of ours.
    #[tokio::test]
    async fn unit_matched_public_key_ids_lists_only_public_key_rows() {
        let mut state = make_state(&[CredentialKind::Password, CredentialKind::PublicKey]);
        let key_row = Uuid::new_v4();
        let _ = state
            .submit_credential(password(), |_, _| async { Ok(Some(stored_credential(1))) })
            .await
            .unwrap();
        assert!(state.matched_public_key_ids().is_empty());

        let _ = state
            .submit_credential(password(), move |_, _| async move {
                Ok(Some(StoredCredential::new(
                    StoredCredentialKind::PublicKey,
                    key_row,
                    StoredCredentialFingerprint::of_stored_verifier([2; 32].as_slice()),
                )))
            })
            .await
            .unwrap();
        assert_eq!(state.matched_public_key_ids(), vec![key_row]);
    }
}
