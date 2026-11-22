//! The signed session statement Warpgate adds to requests it proxies to an
//! HTTP target with `signed_statement` on (header
//! [`STATEMENT_HEADER`]). It tells the target who the cookie session behind the
//! request is, how it signed in, and when it last did single sign-on, bound to
//! the target, the method and the upstream path, for [`STATEMENT_TTL_SECS`].
//!
//! Wire form: `v1.<kid>.<payload>.<sig>`
//!
//! - `payload` is base64url (no padding) of the JSON [`StatementClaims`];
//! - `sig` is base64url (no padding) of the 64-byte Ed25519 signature over
//!   [`signed_message`]: the tag [`STATEMENT_TAG`], the `kid` and the
//!   `payload` text exactly as sent, each preceded by its length as a 4-byte
//!   big-endian integer.
//!
//! A verifier checks the version, looks the `kid` up among the keys it pinned,
//! verifies the signature over the bytes it received, and only then decodes
//! the payload. The statement is a bearer token for its lifetime: it is never
//! logged, and nothing here implements `Debug` over a signed value.

use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// The header the statement travels in. Inside the `x-warpgate-` prefix that
/// is dropped from every client request, so a client cannot supply one.
pub const STATEMENT_HEADER: &str = "x-warpgate-session-freshness";
/// The version label that starts every statement.
pub const STATEMENT_VERSION: &str = "v1";
/// Domain tag of the signed message.
pub const STATEMENT_TAG: &[u8] = b"cove-session-freshness-v1";
/// Domain tag of the session hash `sh`.
pub const SESSION_HASH_TAG: &[u8] = b"cove-session-hash-v1";
/// `exp - iat`, fixed.
pub const STATEMENT_TTL_SECS: i64 = 30;

/// How the cookie session behind the request signed in.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum StatementAuth {
    User,
    Ticket,
}

/// What a statement says. Serialized in this field order.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct StatementClaims {
    /// Id of the target the request is for
    pub aud: String,
    /// Id of the session's user, stable across a rename
    pub sub: String,
    /// The session's username, exactly as Warpgate holds it
    pub name: String,
    /// From the cookie session, never from a request's made-up authorization
    pub auth: StatementAuth,
    /// The session's last SSO return, Unix seconds; `null` when it never did SSO
    pub last_sso_at: Option<i64>,
    /// The session's last sign-in of any kind, Unix seconds; `null` for a
    /// session with no recorded sign-in. Audit only.
    pub auth_time: Option<i64>,
    pub iat: i64,
    pub exp: i64,
    /// Request method
    pub m: String,
    /// Upstream path and query, as forwarded
    pub p: String,
    /// The ticket's id. Reserved: no statement is made for a ticket session,
    /// so Warpgate never sets it
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tid: Option<String>,
    /// [`session_hash`] of Warpgate's session id; `null` when the browser
    /// session has none
    pub sh: Option<String>,
}

/// Each part preceded by its length as a 4-byte big-endian integer.
fn length_prefixed(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(parts.iter().map(|p| p.len() + 4).sum());
    for part in parts {
        #[allow(clippy::cast_possible_truncation)] // a header is far below 4 GiB
        out.extend_from_slice(&(part.len() as u32).to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

/// The bytes the signature covers: [`STATEMENT_TAG`], `kid`, then the
/// base64url `payload` text exactly as sent, each length-prefixed.
pub fn signed_message(kid: &str, payload: &str) -> Vec<u8> {
    length_prefixed(&[STATEMENT_TAG, kid.as_bytes(), payload.as_bytes()])
}

/// `sh`: SHA-256 over the length-prefixed [`SESSION_HASH_TAG`] and the
/// session id in its hyphenated lowercase form, base64url without padding.
/// For correlating audit records only; it is never the cookie value.
pub fn session_hash(session_id: Uuid) -> String {
    let id = session_id.hyphenated().to_string();
    BASE64URL_NOPAD.encode(&Sha256::digest(length_prefixed(&[
        SESSION_HASH_TAG,
        id.as_bytes(),
    ])))
}

/// The header value for `claims`, signed with `key` under `kid`.
pub fn sign_statement(
    kid: &str,
    key: &SigningKey,
    claims: &StatementClaims,
) -> Result<String, serde_json::Error> {
    let payload = BASE64URL_NOPAD.encode(&serde_json::to_vec(claims)?);
    let signature = key.sign(&signed_message(kid, &payload));
    Ok(format!(
        "{STATEMENT_VERSION}.{kid}.{payload}.{}",
        BASE64URL_NOPAD.encode(&signature.to_bytes())
    ))
}

#[cfg(test)]
pub(crate) mod tests {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    use super::*;
    use crate::statement_keys::kid_for;

    /// The shared test vector's key: the seed is the bytes 0, 1, ..., 31.
    pub(crate) fn vector_key() -> SigningKey {
        let mut seed = [0u8; 32];
        for (i, b) in seed.iter_mut().enumerate() {
            #[allow(clippy::cast_possible_truncation)]
            {
                *b = i as u8;
            }
        }
        SigningKey::from_bytes(&seed)
    }

    pub(crate) const VECTOR_SESSION_ID: Uuid =
        Uuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef);

    /// A fresh user statement, as a password-then-SSO session would carry.
    pub(crate) fn vector_claims() -> StatementClaims {
        StatementClaims {
            aud: "6f1b0c3e-0000-4000-8000-000000000001".into(),
            sub: "9a7e5b2c-0000-4000-8000-000000000002".into(),
            name: "alice".into(),
            auth: StatementAuth::User,
            last_sso_at: Some(1_795_000_000),
            auth_time: Some(1_795_000_000),
            iat: 1_795_000_100,
            exp: 1_795_000_130,
            m: "POST".into(),
            p: "/vms/dev/delete?confirm=1".into(),
            tid: None,
            sh: Some(session_hash(VECTOR_SESSION_ID)),
        }
    }

    /// Parses and verifies a header value the way a verifier must: the
    /// signature first, over the bytes as received, then the payload.
    pub(crate) fn verify(value: &str, key: &VerifyingKey) -> Option<StatementClaims> {
        let mut parts = value.split('.');
        let (Some(version), Some(kid), Some(payload), Some(sig), None) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            return None;
        };
        if version != STATEMENT_VERSION || kid != kid_for(key) {
            return None;
        }
        let sig: [u8; 64] = BASE64URL_NOPAD
            .decode(sig.as_bytes())
            .ok()?
            .try_into()
            .ok()?;
        key.verify(&signed_message(kid, payload), &Signature::from_bytes(&sig))
            .ok()?;
        serde_json::from_slice(&BASE64URL_NOPAD.decode(payload.as_bytes()).ok()?).ok()
    }

    /// The shared vector, fixed byte for byte. cove's verifier must accept
    /// exactly this value for this key. The signature was cross-checked with
    /// OpenSSL's Ed25519 over [`signed_message`].
    #[test]
    fn the_shared_vector() {
        let key = vector_key();
        let public = key.verifying_key();
        assert_eq!(
            BASE64URL_NOPAD.encode(public.as_bytes()),
            VECTOR_PUBLIC_KEY,
            "public key"
        );
        assert_eq!(kid_for(&public), VECTOR_KID, "kid");
        assert_eq!(session_hash(VECTOR_SESSION_ID), VECTOR_SH, "sh");
        let value = sign_statement(VECTOR_KID, &key, &vector_claims()).unwrap();
        assert_eq!(value, VECTOR_STATEMENT);
        assert!(verify(&value, &public) == Some(vector_claims()));
    }

    pub(crate) const VECTOR_PUBLIC_KEY: &str = "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg";
    pub(crate) const VECTOR_KID: &str = "Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw";
    pub(crate) const VECTOR_SH: &str = "csYevRtBmdkph9kYTknQH15jWwvnGD8dkDC7ixc-y2I";
    pub(crate) const VECTOR_STATEMENT: &str = concat!(
        "v1.Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw.",
        "eyJhdWQiOiI2ZjFiMGMzZS0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDEiLCJzdWIiOiI5YTdlNWIy",
        "Yy0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDIiLCJuYW1lIjoiYWxpY2UiLCJhdXRoIjoidXNlciIs",
        "Imxhc3Rfc3NvX2F0IjoxNzk1MDAwMDAwLCJhdXRoX3RpbWUiOjE3OTUwMDAwMDAsImlhdCI6MTc5NTAw",
        "MDEwMCwiZXhwIjoxNzk1MDAwMTMwLCJtIjoiUE9TVCIsInAiOiIvdm1zL2Rldi9kZWxldGU_Y29uZmly",
        "bT0xIiwic2giOiJjc1lldlJ0Qm1ka3BoOWtZVGtuUUgxNWpXd3ZuR0Q4ZGtEQzdpeGMteTJJIn0",
        ".",
        "r0FhJpXpIu0dSPz7gEfBeLe88WDNwQ-uONJhskmSmg7kOuBtod3JiptM-K7ueulsWyJTFuurTQrx2MnafZQ1Ag"
    );

    #[test]
    fn the_payload_keeps_its_field_order_and_nulls() {
        let mut claims = vector_claims();
        claims.last_sso_at = None;
        claims.sh = None;
        let json = serde_json::to_string(&claims).unwrap();
        assert_eq!(
            json,
            r#"{"aud":"6f1b0c3e-0000-4000-8000-000000000001","sub":"9a7e5b2c-0000-4000-8000-000000000002","name":"alice","auth":"user","last_sso_at":null,"auth_time":1795000000,"iat":1795000100,"exp":1795000130,"m":"POST","p":"/vms/dev/delete?confirm=1","sh":null}"#
        );
        claims.auth = StatementAuth::Ticket;
        claims.tid = Some("t-1".into());
        claims.auth_time = None;
        let json = serde_json::to_string(&claims).unwrap();
        assert!(json.contains(r#""auth":"ticket""#), "{json}");
        assert!(json.contains(r#""auth_time":null"#), "{json}");
        assert!(json.contains(r#""tid":"t-1","sh":null}"#), "{json}");
    }

    #[test]
    fn the_signed_message_is_length_prefixed() {
        let message = signed_message("k", "p.q");
        let mut expected = vec![0, 0, 0, 25];
        expected.extend_from_slice(STATEMENT_TAG);
        expected.extend_from_slice(&[0, 0, 0, 1, b'k', 0, 0, 0, 3, b'p', b'.', b'q']);
        assert_eq!(message, expected);
    }

    #[test]
    fn a_changed_byte_or_another_key_fails_verification() {
        let key = vector_key();
        let value = sign_statement(VECTOR_KID, &key, &vector_claims()).unwrap();
        let other = SigningKey::from_bytes(&[9u8; 32]);
        assert!(verify(&value, &other.verifying_key()).is_none());

        let mut tampered = vector_claims();
        tampered.p = "/vms/prod/delete?confirm=1".into();
        let forged_payload = BASE64URL_NOPAD.encode(&serde_json::to_vec(&tampered).unwrap());
        let parts: Vec<&str> = value.split('.').collect();
        let forged = format!("{}.{}.{forged_payload}.{}", parts[0], parts[1], parts[3]);
        assert!(verify(&forged, &key.verifying_key()).is_none());
    }

    #[test]
    fn the_session_hash_is_domain_separated() {
        let plain = BASE64URL_NOPAD.encode(&Sha256::digest(
            VECTOR_SESSION_ID.hyphenated().to_string().as_bytes(),
        ));
        assert_ne!(session_hash(VECTOR_SESSION_ID), plain);
        assert_eq!(session_hash(VECTOR_SESSION_ID).len(), 43);
    }
}
