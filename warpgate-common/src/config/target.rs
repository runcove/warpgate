use std::collections::HashMap;

use poem_openapi::types::{ParseFromJSON, ParseResult};
use poem_openapi::{Enum, Object, Union};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use warpgate_tls::TlsMode;

use super::defaults::{
    _default_empty_string, _default_empty_vec, _default_mysql_port,
    _default_postgres_idle_timeout_str, _default_postgres_port, _default_rdp_port,
    _default_ssh_port, _default_username, _default_vnc_port,
};
use crate::encryption::EncryptionError;
use crate::{Protocol, Secret, StoredSecret};

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object)]
pub struct KubernetesTargetCertificateAuth {
    pub certificate: Secret<String>,
    pub private_key: StoredSecret,
}

impl Default for KubernetesTargetCertificateAuth {
    fn default() -> Self {
        Self {
            certificate: Secret::new(String::new()),
            private_key: StoredSecret::default(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object)]
pub struct TargetSSHOptions {
    pub host: String,
    #[serde(default = "_default_ssh_port")]
    pub port: u16,
    #[serde(default = "_default_username")]
    pub username: String,
    // It was an `Option<bool>` before 0.29.1, so clients send it as null or
    // not at all, and rows and config files written then may hold a null;
    // both mean false, as they did then. The admin API parses with
    // poem-openapi, everything else with serde, so each gets the rule.
    // Parsing only: the schema still lists the field as required, which is
    // what every response carries (an `#[oai(default)]` would make it
    // optional in responses too).
    #[serde(default, deserialize_with = "deserialize_absent_or_null_as_false")]
    #[oai(deserialize_with = "parse_absent_or_null_as_false")]
    pub allow_insecure_algos: bool,
    #[serde(default)]
    pub auth: SSHTargetAuth,
    #[serde(default)]
    pub jump_host: Option<Uuid>,

    /// Custom environment variables to inject into downstream SSH sessions
    #[serde(default)]
    pub env: Option<HashMap<String, String>>,
}

/// An absent or null boolean parses as false (poem-openapi).
fn parse_absent_or_null_as_false(value: Option<serde_json::Value>) -> ParseResult<bool> {
    match value {
        None | Some(serde_json::Value::Null) => Ok(false),
        value => bool::parse_from_json(value),
    }
}

/// A null boolean deserializes as false (serde; an absent one takes the
/// field's `#[serde(default)]`).
fn deserialize_absent_or_null_as_false<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<bool, D::Error> {
    Ok(Option::<bool>::deserialize(deserializer)?.unwrap_or(false))
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Union)]
#[serde(tag = "kind")]
#[oai(discriminator_name = "kind", one_of)]
pub enum SSHTargetAuth {
    #[serde(rename = "password")]
    Password(SshTargetPasswordAuth),
    #[serde(rename = "publickey")]
    PublicKey(SshTargetPublicKeyAuth),
    #[serde(rename = "iam_role")]
    IamRole(SshTargetIamRoleAuth),
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object)]
pub struct SshTargetPasswordAuth {
    pub password: StoredSecret,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object, Default)]
pub struct SshTargetPublicKeyAuth {
    /// Specific stored client key to authenticate with; `None` uses the keys
    /// marked default.
    #[serde(default)]
    pub key_id: Option<Uuid>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object, Default)]
pub struct SshTargetIamRoleAuth {}

impl Default for SSHTargetAuth {
    fn default() -> Self {
        Self::PublicKey(SshTargetPublicKeyAuth::default())
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object)]
pub struct TargetHTTPOptions {
    #[serde(default = "_default_empty_string")]
    pub url: String,

    #[serde(default)]
    pub tls: Tls,

    #[serde(default)]
    pub headers: HashMap<String, String>,

    #[serde(default)]
    pub external_host: Option<String>,

    /// When `true`, the catchall HTTP proxy serves this target without
    /// requiring a Warpgate login. Anonymous and session-authed clients pass
    /// through on a throwaway session that is never stored; admin, user and
    /// cluster tokens hit a public target -> 401 (tokens are not proxy-scoped).
    /// A target that requires admin approval is never bypassed. Default
    /// `false` preserves existing behaviour; serde-default backfills existing
    /// JSON-column rows so no DB migration is required.
    ///
    /// `#[oai(default)]` is NOT a duplicate of `#[serde(default)]`. serde's
    /// governs JSON deserialisation; poem-openapi's `Object` derive is a
    /// separate generator and marks every non-`Option` field REQUIRED in the
    /// emitted schema unless it carries its own default. Without it the admin
    /// API's OpenAPI document would tell clients they must send `public` on
    /// POST /targets and PUT /targets/{id}.
    #[serde(default)]
    #[oai(default)]
    pub public: bool,

    /// Absolute path of a Unix socket to reach the target through, in place
    /// of a TCP connection to the host in `url`, which still gives the `Host`
    /// header and the scheme. Only served when `http.plain_http_on_loopback`
    /// is on. At each connection the socket and its directory must be owned
    /// by the account Warpgate runs as, the directory must not be accessible
    /// to group or others (mode 0700), and neither may be a symlink. Every
    /// directory above it must be a real directory (the path may not go
    /// through a symlink) owned by root or that account, and writable by
    /// group or others only when root-owned and sticky, as `/tmp` is. For
    /// WebSocket requests the process serving the socket must also run as
    /// that account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unix_socket: Option<String>,
}

impl TargetHTTPOptions {
    /// Refuses a `unix_socket` that cannot be served: when the HTTP listener
    /// is not in loopback mode, or when the path is not absolute or has `..`
    /// in it. The socket file itself is checked at each connection.
    pub fn check_unix_socket(&self, plain_http_on_loopback: bool) -> Result<(), String> {
        let Some(path) = &self.unix_socket else {
            return Ok(());
        };
        if !plain_http_on_loopback {
            return Err(
                "`unix_socket` is only served when `http.plain_http_on_loopback` is on".into(),
            );
        }
        check_unix_socket_path(path)
    }
}

/// The longest Unix socket path the platform can connect to, in bytes:
/// `sockaddr_un.sun_path` (104 on macOS and the BSDs, 108 on Linux) less its
/// terminating NUL.
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
pub const UNIX_SOCKET_PATH_MAX: usize = 103;
#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
)))]
pub const UNIX_SOCKET_PATH_MAX: usize = 107;

/// A Unix socket path must be absolute and free of `..`, so the directory
/// that is checked is the one the socket is reached through, and short
/// enough to connect to ([`UNIX_SOCKET_PATH_MAX`]), so an over-long path is
/// refused when the target is saved rather than at each connection.
pub fn check_unix_socket_path(path: &str) -> Result<(), String> {
    if path.len() > UNIX_SOCKET_PATH_MAX {
        return Err(format!(
            "`unix_socket` is {} bytes; socket paths here may be at most {UNIX_SOCKET_PATH_MAX}",
            path.len()
        ));
    }
    let path = std::path::Path::new(path);
    if !path.is_absolute() {
        return Err("`unix_socket` must be an absolute path".into());
    }
    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err("`unix_socket` must not contain `..`".into());
    }
    if path.file_name().is_none() {
        return Err("`unix_socket` must name a socket file".into());
    }
    Ok(())
}

#[cfg(test)]
mod unix_socket_tests {
    use super::*;

    fn options(unix_socket: Option<&str>) -> TargetHTTPOptions {
        let mut json = serde_json::json!({"url": "http://app.local"});
        if let Some(path) = unix_socket {
            json["unix_socket"] = path.into();
        }
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn unix_socket_defaults_to_none_and_round_trips() {
        assert_eq!(options(None).unix_socket, None);
        let serialized = serde_json::to_value(options(None)).unwrap();
        assert!(serialized.get("unix_socket").is_none());

        let with_socket = options(Some("/run/app/app.sock"));
        let round_tripped: TargetHTTPOptions =
            serde_json::from_value(serde_json::to_value(&with_socket).unwrap()).unwrap();
        assert_eq!(round_tripped, with_socket);
        assert_eq!(
            round_tripped.unix_socket.as_deref(),
            Some("/run/app/app.sock")
        );
    }

    #[test]
    fn unix_socket_is_refused_outside_loopback_mode() {
        let with_socket = options(Some("/run/app/app.sock"));
        assert!(with_socket.check_unix_socket(true).is_ok());
        let error = with_socket.check_unix_socket(false).unwrap_err();
        assert!(error.contains("plain_http_on_loopback"), "{error}");
        // Without a socket, nothing to refuse.
        assert!(options(None).check_unix_socket(false).is_ok());
    }

    #[test]
    fn unix_socket_path_must_be_absolute_without_parent_components() {
        for path in ["/run/app/app.sock", "/tmp/a b/x.sock"] {
            assert!(check_unix_socket_path(path).is_ok(), "{path}");
        }
        for path in [
            "",
            "app.sock",
            "./app.sock",
            "run/app.sock",
            "/run/../tmp/app.sock",
            "/",
        ] {
            assert!(check_unix_socket_path(path).is_err(), "{path:?}");
        }
    }

    #[test]
    fn unix_socket_path_must_fit_the_platform_socket_address() {
        let longest = format!("/{}", "a".repeat(UNIX_SOCKET_PATH_MAX - 1));
        assert_eq!(longest.len(), UNIX_SOCKET_PATH_MAX);
        assert!(check_unix_socket_path(&longest).is_ok());
        let error = check_unix_socket_path(&format!("{longest}a")).unwrap_err();
        assert!(error.contains("at most"), "{error}");
    }
}

#[cfg(test)]
mod public_flag_tests {
    //! `public: bool` on `TargetHTTPOptions`. Default `false` (private;
    //! existing behaviour) unless explicitly opted in.
    use super::*;

    #[test]
    fn deserializes_public_default_false() {
        let json = r#"{"url": "http://x:80"}"#;
        let opts: TargetHTTPOptions = serde_json::from_str(json).unwrap();
        assert!(!opts.public);
    }

    #[test]
    fn deserializes_public_explicit_true() {
        let json = r#"{"url": "http://x:80", "public": true}"#;
        let opts: TargetHTTPOptions = serde_json::from_str(json).unwrap();
        assert!(opts.public);
    }
}

// `#[serde(default)]` sits on the container, not on each field, so that
// `Default` is the single source for both an absent `tls` block and an absent
// key inside a present one. Spelling the two separately is how `verify` came to
// mean `false` for an omitted block and `true` for an empty one. Kept as a plain
// comment: a doc comment here would surface in the OpenAPI schema.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object)]
#[serde(default)]
pub struct Tls {
    pub mode: TlsMode,
    pub verify: bool,
}

impl Default for Tls {
    fn default() -> Self {
        Self {
            mode: TlsMode::default(),
            // A target that says nothing about certificate checking is not
            // asking for it to be off.
            verify: true,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Union)]
#[serde(tag = "kind")]
#[oai(discriminator_name = "kind", one_of)]
pub enum DatabaseTargetAuth {
    #[serde(rename = "password")]
    Password(DatabaseTargetPasswordAuth),
    #[serde(rename = "iam_role")]
    IamRole(DatabaseTargetIamRoleAuth),
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object, Default)]
pub struct DatabaseTargetPasswordAuth {
    #[serde(default)]
    pub password: StoredSecret,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object, Default)]
pub struct DatabaseTargetIamRoleAuth {}

impl Default for DatabaseTargetAuth {
    fn default() -> Self {
        Self::Password(DatabaseTargetPasswordAuth::default())
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object)]
pub struct TargetMySqlOptions {
    #[serde(default = "_default_empty_string")]
    pub host: String,

    #[serde(default = "_default_mysql_port")]
    pub port: u16,

    #[serde(default = "_default_username")]
    pub username: String,

    #[serde(default)]
    pub auth: DatabaseTargetAuth,

    #[serde(default)]
    pub tls: Tls,

    #[serde(default)]
    pub default_database_name: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq, Default, Enum)]
pub enum PostgresProtocolVersion {
    #[serde(rename = "3.0")]
    #[oai(rename = "3.0")]
    V3_0,
    #[default]
    #[serde(rename = "3.2")]
    #[oai(rename = "3.2")]
    V3_2,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object)]
pub struct TargetPostgresOptions {
    #[serde(default = "_default_empty_string")]
    pub host: String,

    #[serde(default = "_default_postgres_port")]
    pub port: u16,

    #[serde(default = "_default_username")]
    pub username: String,

    #[serde(default)]
    pub auth: DatabaseTargetAuth,

    #[serde(default)]
    pub tls: Tls,

    #[serde(default = "_default_postgres_idle_timeout_str")]
    pub idle_timeout: Option<String>,

    #[serde(default)]
    pub default_database_name: Option<String>,

    #[serde(default)]
    pub protocol_version: PostgresProtocolVersion,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object)]
pub struct TargetVncOptions {
    #[serde(default = "_default_empty_string")]
    pub host: String,

    #[serde(default = "_default_vnc_port")]
    pub port: u16,

    #[serde(default)]
    pub auth: VncTargetAuth,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Union)]
#[serde(tag = "kind")]
#[oai(discriminator_name = "kind", one_of)]
pub enum VncTargetAuth {
    #[serde(rename = "none")]
    None(VncTargetNoneAuth),
    #[serde(rename = "password")]
    Password(VncTargetPasswordAuth),
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object, Default)]
pub struct VncTargetNoneAuth {}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object)]
pub struct VncTargetPasswordAuth {
    pub password: StoredSecret,
}

impl Default for VncTargetAuth {
    fn default() -> Self {
        Self::None(VncTargetNoneAuth::default())
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq, Enum, Default)]
pub enum RdpTargetCompression {
    #[default]
    #[serde(rename = "remotefx")]
    #[oai(rename = "remotefx")]
    RemoteFX,
    #[serde(rename = "lossless")]
    #[oai(rename = "lossless")]
    Lossless,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object)]
pub struct TargetRdpOptions {
    #[serde(default = "_default_empty_string")]
    pub host: String,

    #[serde(default = "_default_rdp_port")]
    pub port: u16,

    #[serde(default = "_default_username")]
    pub username: String,

    #[serde(default)]
    pub domain: Option<String>,

    #[serde(default)]
    pub auth: RdpTargetAuth,

    /// Verify the RDP server's TLS certificate against the system root store.
    /// RDP servers commonly use self-signed certificates, so this is off by default.
    #[serde(default)]
    pub verify_tls: bool,

    #[serde(default)]
    pub compression: RdpTargetCompression,

    /// Show the target's own sign-in screen instead of logging on automatically.
    /// The stored credentials still pass network-level authentication (CredSSP).
    #[serde(default)]
    pub interactive_logon: bool,

    // TLS compatibility/security profile used for the target-facing RDP connection.
    // Kept as a plain comment so OpenAPI emits a direct enum reference. A field
    // description wraps the enum in allOf, which typescript-fetch misgenerates.
    #[serde(default)]
    pub tls_security: RdpTlsSecurity,
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq, Default, Enum)]
pub enum RdpTlsSecurity {
    /// ~ Windows 2016/10
    #[serde(rename = "tls_1_2")]
    #[default]
    Tls12,
    /// ~ Windows 2012/8
    #[serde(rename = "tls_1_2_with_legacy_ciphers")]
    Tls12WithLegacyCiphers,
    /// ~ Windows 2008/Vista
    #[serde(rename = "tls_1_0_unsafe")]
    Tls10Unsafe,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Union)]
#[serde(tag = "kind")]
#[oai(discriminator_name = "kind", one_of)]
pub enum RdpTargetAuth {
    #[serde(rename = "password")]
    Password(RdpTargetPasswordAuth),
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object)]
pub struct RdpTargetPasswordAuth {
    pub password: StoredSecret,
}

impl Default for RdpTargetAuth {
    fn default() -> Self {
        Self::Password(RdpTargetPasswordAuth {
            password: StoredSecret::default(),
        })
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object)]
pub struct TargetKubernetesOptions {
    #[serde(default = "_default_empty_string")]
    pub cluster_url: String,

    #[serde(default)]
    pub tls: Tls,

    #[serde(default)]
    pub auth: KubernetesTargetAuth,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Union)]
#[serde(tag = "kind")]
#[oai(discriminator_name = "kind", one_of)]
pub enum KubernetesTargetAuth {
    #[serde(rename = "token")]
    Token(KubernetesTargetTokenAuth),
    #[serde(rename = "certificate")]
    Certificate(KubernetesTargetCertificateAuth),
    #[serde(rename = "iam_role")]
    IamRole(KubernetesTargetIamRoleAuth),
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object)]
pub struct KubernetesTargetTokenAuth {
    pub token: StoredSecret,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object, Default)]
pub struct KubernetesTargetIamRoleAuth {}

impl Default for KubernetesTargetAuth {
    fn default() -> Self {
        Self::Certificate(KubernetesTargetCertificateAuth::default())
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object)]
pub struct Target {
    #[serde(default)]
    pub id: Uuid,
    pub name: String,
    pub description: String,
    #[serde(default = "_default_empty_vec")]
    pub allow_roles: Vec<String>,
    #[serde(flatten)]
    pub options: TargetOptions,
    pub rate_limit_bytes_per_second: Option<u32>,
    pub group_id: Option<Uuid>,
    pub ticket_max_duration_seconds: Option<i64>,
    pub ticket_requests_disabled: bool,
    pub ticket_require_approval: bool,
    pub require_approval: bool,
    pub ticket_max_uses: Option<i16>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Union)]
#[oai(discriminator_name = "kind", one_of)]
pub enum TargetOptions {
    #[serde(rename = "ssh")]
    Ssh(TargetSSHOptions),
    #[serde(rename = "http")]
    Http(TargetHTTPOptions),
    #[serde(rename = "kubernetes")]
    Kubernetes(TargetKubernetesOptions),
    #[serde(rename = "mysql")]
    MySql(TargetMySqlOptions),
    #[serde(rename = "postgres")]
    Postgres(TargetPostgresOptions),
    #[serde(rename = "vnc")]
    Vnc(TargetVncOptions),
    #[serde(rename = "rdp")]
    Rdp(TargetRdpOptions),
}

impl TargetOptions {
    pub fn protocol(&self) -> Protocol {
        match self {
            TargetOptions::Ssh(_) => Protocol::Ssh,
            TargetOptions::Http(_) => Protocol::Http,
            TargetOptions::Kubernetes(_) => Protocol::Kubernetes,
            TargetOptions::MySql(_) => Protocol::MySql,
            TargetOptions::Postgres(_) => Protocol::Postgres,
            TargetOptions::Vnc(_) => Protocol::Vnc,
            TargetOptions::Rdp(_) => Protocol::Rdp,
        }
    }

    // both used for connection instructions

    pub fn external_host(&self) -> Option<&str> {
        match self {
            Self::Http(options) => options.external_host.as_deref(),
            _ => None,
        }
    }

    pub fn default_database_name(&self) -> Option<&str> {
        match self {
            Self::MySql(options) => options.default_database_name.as_deref(),
            Self::Postgres(options) => options.default_database_name.as_deref(),
            _ => None,
        }
    }
}

/// JSON path towards every possible credential within *serialized* TargetOptions
/// Update for new protocols
const SECRET_PATHS: &[&[&str]] = &[
    &["ssh", "auth", "password"],
    &["mysql", "auth", "password"],
    &["postgres", "auth", "password"],
    &["vnc", "auth", "password"],
    &["rdp", "auth", "password"],
    &["kubernetes", "auth", "token"],
    &["kubernetes", "auth", "private_key"],
];

/// Rewrite every secret in a serialized TargetOptions
pub fn map_target_secrets(
    options: &mut serde_json::Value,
    f: &mut dyn FnMut(&str) -> Result<String, EncryptionError>,
) -> Result<(), EncryptionError> {
    fn resolve<'a>(
        node: &'a mut serde_json::Value,
        path: &[&str],
    ) -> Option<&'a mut serde_json::Value> {
        path.iter().try_fold(node, |node, step| node.get_mut(step))
    }

    for path in SECRET_PATHS {
        // Only a string is a credential - a missing path, a `null` auth block or an
        // unexpected shape is left exactly as it was found.
        if let Some(serde_json::Value::String(value)) = resolve(options, path) {
            let replacement = f(value)?;
            *value = replacement;
        }
    }
    Ok(())
}

/// Blanks out every secret in a serialized TargetOptions or Target (same JSON paths as options are serde(flatten))
pub fn redact_target_secrets(value: &mut serde_json::Value) {
    // The closure is infallible, so the walk is too.
    let _ = map_target_secrets(value, &mut |_| Ok(String::new()));
}

#[cfg(test)]
mod tests {
    use super::{
        DatabaseTargetAuth, DatabaseTargetPasswordAuth, PostgresProtocolVersion,
        RdpTargetCompression, RdpTlsSecurity, TargetHTTPOptions, TargetKubernetesOptions,
        TargetMySqlOptions, TargetPostgresOptions, TargetRdpOptions, TargetSSHOptions, Tls,
    };

    /// The two ways of saying "nothing specified" — an absent `tls` block and an
    /// empty one — must both resolve to verifying.
    #[test]
    fn omitted_and_empty_tls_agree_on_verifying() {
        let absent: TargetHTTPOptions = serde_json::from_str(r#"{"url":"http://t"}"#).unwrap();
        let empty: TargetHTTPOptions =
            serde_json::from_str(r#"{"url":"http://t","tls":{}}"#).unwrap();

        assert!(absent.tls.verify);
        assert_eq!(absent.tls, empty.tls);
        assert_eq!(absent.tls, Tls::default());
    }

    /// These fields stopped being `Option`, and m00087 drops the explicit nulls
    /// left behind rather than translating them. Their defaults therefore have to
    /// keep producing what the old `unwrap_or` did.
    #[test]
    fn an_omitted_field_defaults_to_what_the_option_fell_back_to() {
        let ssh: TargetSSHOptions = serde_json::from_str(r#"{"host":"h"}"#).unwrap();
        let http: TargetHTTPOptions = serde_json::from_str(r#"{"url":"http://t"}"#).unwrap();
        let mysql: TargetMySqlOptions = serde_json::from_str("{}").unwrap();
        let postgres: TargetPostgresOptions = serde_json::from_str("{}").unwrap();
        let rdp: TargetRdpOptions = serde_json::from_str("{}").unwrap();

        assert!(!ssh.allow_insecure_algos);
        assert!(http.headers.is_empty());
        assert_eq!(postgres.protocol_version, PostgresProtocolVersion::V3_2);
        assert_eq!(rdp.compression, RdpTargetCompression::RemoteFX);
        assert_eq!(rdp.tls_security, RdpTlsSecurity::Tls12);
        let empty_password = DatabaseTargetAuth::Password(DatabaseTargetPasswordAuth::default());
        assert_eq!(mysql.auth, empty_password);
        assert_eq!(postgres.auth, empty_password);
    }

    /// Registering an SSH target through the admin API: `allow_insecure_algos`
    /// absent or null is accepted and stored as false (it was an
    /// `Option<bool>` before 0.29.1), and true is still stored as true.
    #[test]
    fn ssh_allow_insecure_algos_absent_or_null_registers_as_false() {
        use poem_openapi::types::ParseFromJSON;

        use super::TargetOptions;

        let register = |allow_insecure_algos: Option<serde_json::Value>| {
            let mut body = serde_json::json!({
                "kind": "Ssh",
                "host": "h",
                "port": 22,
                "username": "u",
                "auth": {"kind": "PublicKey"},
            });
            if let Some(value) = allow_insecure_algos {
                body["allow_insecure_algos"] = value;
            }
            let parsed = TargetOptions::parse_from_json(Some(body))
                .unwrap_or_else(|error| panic!("refused: {}", error.message()));
            let TargetOptions::Ssh(ref ssh) = parsed else {
                panic!("not an SSH target: {parsed:?}");
            };
            // What the admin API writes to the options column: the options
            // under their kind.
            let stored = serde_json::to_value(&parsed).unwrap();
            assert_eq!(
                stored["ssh"]["allow_insecure_algos"],
                serde_json::Value::Bool(ssh.allow_insecure_algos),
                "{stored}"
            );
            ssh.allow_insecure_algos
        };

        assert!(!register(None));
        assert!(!register(Some(serde_json::Value::Null)));
        assert!(!register(Some(serde_json::Value::Bool(false))));
        assert!(register(Some(serde_json::Value::Bool(true))));
    }

    /// The same rule through serde, which reads the options column and the
    /// config file: absent or null is false, true stays true.
    #[test]
    fn ssh_allow_insecure_algos_absent_or_null_deserializes_as_false() {
        use super::TargetOptions;

        for (options, expected) in [
            (serde_json::json!({"host": "h"}), false),
            (
                serde_json::json!({"host": "h", "allow_insecure_algos": null}),
                false,
            ),
            (
                serde_json::json!({"host": "h", "allow_insecure_algos": false}),
                false,
            ),
            (
                serde_json::json!({"host": "h", "allow_insecure_algos": true}),
                true,
            ),
        ] {
            let ssh: TargetSSHOptions = serde_json::from_value(options.clone())
                .unwrap_or_else(|error| panic!("{options} refused: {error}"));
            assert_eq!(ssh.allow_insecure_algos, expected, "{options}");

            // A stored row: the options under their kind.
            let row = serde_json::json!({ "ssh": options });
            let stored: TargetOptions = serde_json::from_value(row.clone())
                .unwrap_or_else(|error| panic!("{row} refused: {error}"));
            let TargetOptions::Ssh(ref ssh) = stored else {
                panic!("not an SSH target: {stored:?}");
            };
            assert_eq!(ssh.allow_insecure_algos, expected, "{row}");
        }
    }

    #[test]
    fn every_target_kind_defaults_to_verifying() {
        let mysql: TargetMySqlOptions = serde_json::from_str(r#"{"host":"t"}"#).unwrap();
        let kubernetes: TargetKubernetesOptions = serde_json::from_str("{}").unwrap();

        assert!(mysql.tls.verify);
        assert!(kubernetes.tls.verify);
    }

    /// Turning verification off has to stay possible — it just has to be said.
    #[test]
    fn verification_can_still_be_opted_out_of() {
        let off: TargetHTTPOptions =
            serde_json::from_str(r#"{"url":"http://t","tls":{"verify":false}}"#).unwrap();

        assert!(!off.tls.verify);
    }

    fn wrap(v: &mut serde_json::Value, prefix: &str) {
        super::map_target_secrets(v, &mut |s| Ok(format!("{prefix}{s}"))).unwrap();
    }

    /// The reason encryption walks the JSON instead of `TargetOptions`: a
    /// `from_value`/`to_value` round trip drops anything a newer Warpgate wrote.
    /// Encrypting must not be able to lose a credential, so everything outside the
    /// mapped paths has to survive byte for byte.
    #[test]
    fn nothing_outside_the_mapped_paths_is_disturbed() {
        let original = serde_json::json!({
            "mysql": {
                "host": "db",
                "port": 3306,
                "auth": { "kind": "password", "password": "current" },
                "tls": { "mode": "preferred", "verify": true },
                "future_field": 1,
            }
        });

        let mut mapped = original.clone();
        wrap(&mut mapped, "X");
        assert_eq!(mapped["mysql"]["auth"]["password"], "Xcurrent");

        super::map_target_secrets(&mut mapped, &mut |s| {
            Ok(s.strip_prefix('X').unwrap_or(s).to_owned())
        })
        .unwrap();
        assert_eq!(mapped, original);
    }

    /// Fails when a protocol gains a credential field but not a `SECRET_PATHS` entry.
    #[test]
    fn every_credential_path_is_covered() {
        let cases = [
            (
                serde_json::json!({"ssh": {"auth": {"kind": "password", "password": "p"}}}),
                serde_json::json!({"ssh": {"auth": {"kind": "password", "password": "Xp"}}}),
            ),
            (
                serde_json::json!({"mysql": {"auth": {"kind": "password", "password": "p"}}}),
                serde_json::json!({"mysql": {"auth": {"kind": "password", "password": "Xp"}}}),
            ),
            (
                serde_json::json!({"postgres": {"auth": {"kind": "password", "password": "p"}}}),
                serde_json::json!({"postgres": {"auth": {"kind": "password", "password": "Xp"}}}),
            ),
            (
                serde_json::json!({"vnc": {"auth": {"kind": "password", "password": "p"}}}),
                serde_json::json!({"vnc": {"auth": {"kind": "password", "password": "Xp"}}}),
            ),
            (
                serde_json::json!({"rdp": {"auth": {"kind": "password", "password": "p"}}}),
                serde_json::json!({"rdp": {"auth": {"kind": "password", "password": "Xp"}}}),
            ),
            (
                serde_json::json!({"kubernetes": {"auth": {"kind": "token", "token": "t"}}}),
                serde_json::json!({"kubernetes": {"auth": {"kind": "token", "token": "Xt"}}}),
            ),
            (
                serde_json::json!({"kubernetes": {"auth": {
                    "kind": "certificate", "certificate": "pub", "private_key": "k"
                }}}),
                serde_json::json!({"kubernetes": {"auth": {
                    "kind": "certificate", "certificate": "pub", "private_key": "Xk"
                }}}),
            ),
            // HTTP carries no credential of its own, and `external_host` must stay
            // readable: `get_target_by_hostname` extracts it with raw SQL.
            (
                serde_json::json!({"http": {"url": "http://t", "external_host": "h"}}),
                serde_json::json!({"http": {"url": "http://t", "external_host": "h"}}),
            ),
        ];

        for (mut input, expected) in cases {
            wrap(&mut input, "X");
            assert_eq!(input, expected);
        }
    }

    /// A missing `auth` block must not make the walk fall through to a same-named
    /// field one level up.
    #[test]
    fn an_absent_auth_block_is_skipped_not_confused_with_its_parent() {
        let mut absent = serde_json::json!({"mysql": {"host": "db", "auth": null}});
        wrap(&mut absent, "X");
        assert_eq!(
            absent,
            serde_json::json!({"mysql": {"host": "db", "auth": null}})
        );
    }

    /// Session snapshots are stored redacted; everything else about the target has
    /// to survive, since the snapshot is what the session list displays.
    #[test]
    fn redaction_blanks_credentials_and_keeps_the_rest() {
        let mut snapshot = serde_json::json!({
            "id": "7c1c0e1e-0000-0000-0000-000000000000",
            "name": "prod-db",
            "mysql": {
                "host": "db",
                "port": 3306,
                "username": "root",
                "auth": {"kind": "password", "password": "hunter2"},
            }
        });

        super::redact_target_secrets(&mut snapshot);

        assert_eq!(snapshot["mysql"]["auth"]["password"], "");
        assert_eq!(snapshot["mysql"]["host"], "db");
        assert_eq!(snapshot["mysql"]["username"], "root");
        assert_eq!(snapshot["name"], "prod-db");
    }
}
