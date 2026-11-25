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
use rand::TryRng;
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

/// How the cookie session behind the request signed in. Only a user session
/// gets a statement, so there is one value.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum StatementAuth {
    User,
}

/// Bytes of the random `jti`.
pub const JTI_BYTES: usize = 16;

/// What a statement says. Serialized in this field order, and exactly these 11
/// keys, each once; only `last_sso_at` and `sh` may be `null`.
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
    /// When the identity provider says the user last signed in (the ID token's
    /// `auth_time` at the session's last SSO return), Unix seconds; `null` when
    /// the session never did SSO
    pub last_sso_at: Option<i64>,
    pub iat: i64,
    pub exp: i64,
    /// Unique id of this statement: 16 random bytes from the OS RNG, base64url
    /// without padding. A receiver keeps a replay cache keyed on `(kid, jti)`.
    pub jti: String,
    /// Request method
    pub m: String,
    /// Upstream path and query, as forwarded
    pub p: String,
    /// [`session_hash`] of Warpgate's session id; `null` when the browser
    /// session has none
    pub sh: Option<String>,
}

/// A fresh `jti`: 16 bytes straight from the OS RNG, base64url without
/// padding. `None` if the OS RNG fails: no statement is better than a weak one.
pub fn new_jti() -> Option<String> {
    let mut bytes = [0u8; JTI_BYTES];
    rand::rngs::SysRng.try_fill_bytes(&mut bytes).ok()?;
    Some(BASE64URL_NOPAD.encode(&bytes))
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
            iat: 1_795_000_100,
            exp: 1_795_000_130,
            jti: BASE64URL_NOPAD.encode(&[0xA5; JTI_BYTES]),
            m: "POST".into(),
            p: "/vms/dev/delete?confirm=1".into(),
            sh: Some(session_hash(VECTOR_SESSION_ID)),
        }
    }

    /// The payload keys, as a verifier must find them: each exactly once.
    pub(crate) const PAYLOAD_KEYS: [&str; 11] = [
        "aud",
        "sub",
        "name",
        "auth",
        "last_sso_at",
        "iat",
        "exp",
        "jti",
        "m",
        "p",
        "sh",
    ];

    /// Reads every `(key, value)` pair of a JSON object in order, keeping a
    /// repeated key instead of dropping it the way a map would.
    fn object_pairs(json: &[u8]) -> Option<Vec<(String, serde_json::Value)>> {
        struct Pairs(Vec<(String, serde_json::Value)>);
        impl<'de> Deserialize<'de> for Pairs {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                struct V;
                impl<'de> serde::de::Visitor<'de> for V {
                    type Value = Pairs;
                    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                        f.write_str("a JSON object")
                    }
                    fn visit_map<A: serde::de::MapAccess<'de>>(
                        self,
                        mut map: A,
                    ) -> Result<Pairs, A::Error> {
                        let mut out = Vec::new();
                        while let Some(pair) = map.next_entry()? {
                            out.push(pair);
                        }
                        Ok(Pairs(out))
                    }
                }
                d.deserialize_map(V)
            }
        }
        serde_json::from_slice::<Pairs>(json)
            .ok()
            .map(|pairs| pairs.0)
    }

    /// The payload rule: exactly the 11 keys, each once and no other; only
    /// `last_sso_at` and `sh` may be `null`; `jti` decodes to 16 bytes.
    pub(crate) fn decode_payload(json: &[u8]) -> Option<StatementClaims> {
        let pairs = object_pairs(json)?;
        if pairs.len() != PAYLOAD_KEYS.len() {
            return None;
        }
        for key in PAYLOAD_KEYS {
            if pairs.iter().filter(|(name, _)| name == key).count() != 1 {
                return None;
            }
        }
        for (name, value) in &pairs {
            if value.is_null() && !matches!(name.as_str(), "last_sso_at" | "sh") {
                return None;
            }
        }
        let claims: StatementClaims = serde_json::from_slice(json).ok()?;
        (BASE64URL_NOPAD.decode(claims.jti.as_bytes()).ok()?.len() == JTI_BYTES).then_some(claims)
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
        decode_payload(&BASE64URL_NOPAD.decode(payload.as_bytes()).ok()?)
    }

    /// Signs `json` as a payload verbatim, for payloads `sign_statement`
    /// would never make.
    fn sign_raw(key: &SigningKey, json: &str) -> String {
        let payload = BASE64URL_NOPAD.encode(json.as_bytes());
        let signature = key.sign(&signed_message(VECTOR_KID, &payload));
        format!(
            "{STATEMENT_VERSION}.{VECTOR_KID}.{payload}.{}",
            BASE64URL_NOPAD.encode(&signature.to_bytes())
        )
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
        "Imxhc3Rfc3NvX2F0IjoxNzk1MDAwMDAwLCJpYXQiOjE3OTUwMDAxMDAsImV4cCI6MTc5NTAwMDEzMCwi",
        "anRpIjoicGFXbHBhV2xwYVdscGFXbHBhV2xwUSIsIm0iOiJQT1NUIiwicCI6Ii92bXMvZGV2L2RlbGV0",
        "ZT9jb25maXJtPTEiLCJzaCI6ImNzWWV2UnRCbWRrcGg5a1lUa25RSDE1ald3dm5HRDhka0RDN2l4Yy15",
        "MkkifQ",
        ".",
        "uMiCuNaQvmp4o1EhcG1nAlRZSMB9KWAsVLOf0raV4Ac4rH7g6QCMPxDu84VkRz5SMMAya77y09S5S52ZQZygDw"
    );

    /// The vector for a session with no session id: `sh` is `null`, and
    /// `last_sso_at` too (a password sign-in).
    #[test]
    fn the_shared_vector_without_a_session_id() {
        let key = vector_key();
        let mut claims = vector_claims();
        claims.sh = None;
        claims.last_sso_at = None;
        let value = sign_statement(VECTOR_KID, &key, &claims).unwrap();
        assert_eq!(value, VECTOR_STATEMENT_NO_SESSION);
        assert!(verify(&value, &key.verifying_key()) == Some(claims));
    }

    /// The vector's payload as JSON text.
    fn vector_json() -> String {
        serde_json::to_string(&vector_claims()).unwrap()
    }

    /// Payloads signed correctly under the vector key that a verifier must
    /// still refuse: a key missing, a key twice, a key twice in place of a
    /// missing one (the count is right, the set is not), an extra key, and a
    /// `null` where none is allowed.
    fn rejected_payloads() -> Vec<(&'static str, String)> {
        let good = vector_json();
        let jti = vector_claims().jti;
        let sh_tail = format!(r#","sh":"{VECTOR_SH}"}}"#);
        let without_sh = good.replace(&sh_tail, "}");
        assert_ne!(without_sh, good);
        vec![
            (
                "missing_jti",
                good.replace(&format!(r#""jti":"{jti}","#), ""),
            ),
            (
                "duplicate_m",
                good.replace(&sh_tail, &format!(r#","m":"GET"{sh_tail}"#)),
            ),
            (
                "duplicate_m_for_missing_sh",
                without_sh.replace('}', r#","m":"GET"}"#),
            ),
            (
                "extra_tid",
                good.replace(&sh_tail, &format!(r#","tid":"t"{sh_tail}"#)),
            ),
            (
                "null_name",
                good.replace(r#""name":"alice""#, r#""name":null"#),
            ),
            (
                "short_jti",
                good.replace(&jti, &BASE64URL_NOPAD.encode(&[0xA5; JTI_BYTES - 1])),
            ),
        ]
    }

    #[test]
    fn the_rejection_vectors() {
        let key = vector_key();
        let public = key.verifying_key();
        let cases = rejected_payloads();
        // The unmodified payload passes the same checks the cases fail.
        assert!(verify(&sign_raw(&key, &vector_json()), &public).is_some());
        assert_eq!(cases.len(), REJECTED.len());
        for ((name, json), (expected_name, expected)) in cases.iter().zip(REJECTED) {
            let value = sign_raw(&key, json);
            assert_eq!(name, expected_name);
            assert_eq!(&value, expected, "{name}");
            // The signature is good: it is the payload that is refused.
            let [_, kid, payload, sig] = value.split('.').collect::<Vec<_>>()[..] else {
                panic!("four parts");
            };
            let sig: [u8; 64] = BASE64URL_NOPAD
                .decode(sig.as_bytes())
                .unwrap()
                .try_into()
                .unwrap();
            public
                .verify(&signed_message(kid, payload), &Signature::from_bytes(&sig))
                .unwrap();
            assert!(verify(&value, &public).is_none(), "{name}");
        }
    }

    pub(crate) const VECTOR_STATEMENT_NO_SESSION: &str = concat!(
        "v1.Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw.",
        "eyJhdWQiOiI2ZjFiMGMzZS0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDEiLCJzdWIiOiI5YTdlNWIy",
        "Yy0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDIiLCJuYW1lIjoiYWxpY2UiLCJhdXRoIjoidXNlciIs",
        "Imxhc3Rfc3NvX2F0IjpudWxsLCJpYXQiOjE3OTUwMDAxMDAsImV4cCI6MTc5NTAwMDEzMCwianRpIjoi",
        "cGFXbHBhV2xwYVdscGFXbHBhV2xwUSIsIm0iOiJQT1NUIiwicCI6Ii92bXMvZGV2L2RlbGV0ZT9jb25m",
        "aXJtPTEiLCJzaCI6bnVsbH0",
        ".",
        "6quPIPTzEvC7xdK8SXvc4vUo1xjOWYShKvJDMs7FyJCOpv4Sttou5oMDodRPqZZ79auxivVlzs8o7FU6ynJuBw"
    );
    pub(crate) const REJECTED: &[(&str, &str)] = &[
        (
            "missing_jti",
            concat!(
                "v1.Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw.",
                "eyJhdWQiOiI2ZjFiMGMzZS0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDEiLCJzdWIiOiI5YTdlNWIy",
                "Yy0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDIiLCJuYW1lIjoiYWxpY2UiLCJhdXRoIjoidXNlciIs",
                "Imxhc3Rfc3NvX2F0IjoxNzk1MDAwMDAwLCJpYXQiOjE3OTUwMDAxMDAsImV4cCI6MTc5NTAwMDEzMCwi",
                "bSI6IlBPU1QiLCJwIjoiL3Ztcy9kZXYvZGVsZXRlP2NvbmZpcm09MSIsInNoIjoiY3NZZXZSdEJtZGtw",
                "aDlrWVRrblFIMTVqV3d2bkdEOGRrREM3aXhjLXkySSJ9",
                ".",
                "LlWIYgZU1-DrGdhAGyH2qpBo9KK-TYJLNPiVtLAMlMrL8ilgWVJBHRqZM2bLxwbHzFbzdRCIzpy_EU08NkmrDA"
            ),
        ),
        (
            "duplicate_m",
            concat!(
                "v1.Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw.",
                "eyJhdWQiOiI2ZjFiMGMzZS0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDEiLCJzdWIiOiI5YTdlNWIy",
                "Yy0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDIiLCJuYW1lIjoiYWxpY2UiLCJhdXRoIjoidXNlciIs",
                "Imxhc3Rfc3NvX2F0IjoxNzk1MDAwMDAwLCJpYXQiOjE3OTUwMDAxMDAsImV4cCI6MTc5NTAwMDEzMCwi",
                "anRpIjoicGFXbHBhV2xwYVdscGFXbHBhV2xwUSIsIm0iOiJQT1NUIiwicCI6Ii92bXMvZGV2L2RlbGV0",
                "ZT9jb25maXJtPTEiLCJtIjoiR0VUIiwic2giOiJjc1lldlJ0Qm1ka3BoOWtZVGtuUUgxNWpXd3ZuR0Q4",
                "ZGtEQzdpeGMteTJJIn0",
                ".",
                "FTUDKcyMFenG1CGdLFDKDVuIfNSE8c36qmLwzdFDlU5u7QVVrqTNMW-Xcny_15F_Ewny1VQOh40pya40T8qeDA"
            ),
        ),
        (
            "duplicate_m_for_missing_sh",
            concat!(
                "v1.Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw.",
                "eyJhdWQiOiI2ZjFiMGMzZS0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDEiLCJzdWIiOiI5YTdlNWIy",
                "Yy0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDIiLCJuYW1lIjoiYWxpY2UiLCJhdXRoIjoidXNlciIs",
                "Imxhc3Rfc3NvX2F0IjoxNzk1MDAwMDAwLCJpYXQiOjE3OTUwMDAxMDAsImV4cCI6MTc5NTAwMDEzMCwi",
                "anRpIjoicGFXbHBhV2xwYVdscGFXbHBhV2xwUSIsIm0iOiJQT1NUIiwicCI6Ii92bXMvZGV2L2RlbGV0",
                "ZT9jb25maXJtPTEiLCJtIjoiR0VUIn0",
                ".",
                "T9VZ1vDmIVsJGhs-JzUIIuv7irHuHt0iEoXyPXGbZ_fZu7m3RPmbwCQbK851TaMZ2-QHh2qyeMDKuvLkhQpoAw"
            ),
        ),
        (
            "extra_tid",
            concat!(
                "v1.Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw.",
                "eyJhdWQiOiI2ZjFiMGMzZS0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDEiLCJzdWIiOiI5YTdlNWIy",
                "Yy0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDIiLCJuYW1lIjoiYWxpY2UiLCJhdXRoIjoidXNlciIs",
                "Imxhc3Rfc3NvX2F0IjoxNzk1MDAwMDAwLCJpYXQiOjE3OTUwMDAxMDAsImV4cCI6MTc5NTAwMDEzMCwi",
                "anRpIjoicGFXbHBhV2xwYVdscGFXbHBhV2xwUSIsIm0iOiJQT1NUIiwicCI6Ii92bXMvZGV2L2RlbGV0",
                "ZT9jb25maXJtPTEiLCJ0aWQiOiJ0Iiwic2giOiJjc1lldlJ0Qm1ka3BoOWtZVGtuUUgxNWpXd3ZuR0Q4",
                "ZGtEQzdpeGMteTJJIn0",
                ".",
                "mp4oOH_lLO2uil8-pbN3uSK5Et-SDDk2WnnelimGXv4cY_NjR8B5ZExQp6Fv8hWB8C0xKuPk9ySviLEzfln3Bg"
            ),
        ),
        (
            "null_name",
            concat!(
                "v1.Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw.",
                "eyJhdWQiOiI2ZjFiMGMzZS0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDEiLCJzdWIiOiI5YTdlNWIy",
                "Yy0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDIiLCJuYW1lIjpudWxsLCJhdXRoIjoidXNlciIsImxh",
                "c3Rfc3NvX2F0IjoxNzk1MDAwMDAwLCJpYXQiOjE3OTUwMDAxMDAsImV4cCI6MTc5NTAwMDEzMCwianRp",
                "IjoicGFXbHBhV2xwYVdscGFXbHBhV2xwUSIsIm0iOiJQT1NUIiwicCI6Ii92bXMvZGV2L2RlbGV0ZT9j",
                "b25maXJtPTEiLCJzaCI6ImNzWWV2UnRCbWRrcGg5a1lUa25RSDE1ald3dm5HRDhka0RDN2l4Yy15Mkki",
                "fQ",
                ".",
                "3SToDp5y6Uu_vKJeul7Wj6p9NEuJRCUqSlb_YFIvUNLA_DrcGntx6J-2NdlurPh2RZ-sdjqTqn8NsUHL6LkSBA"
            ),
        ),
        (
            "short_jti",
            concat!(
                "v1.Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw.",
                "eyJhdWQiOiI2ZjFiMGMzZS0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDEiLCJzdWIiOiI5YTdlNWIy",
                "Yy0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDIiLCJuYW1lIjoiYWxpY2UiLCJhdXRoIjoidXNlciIs",
                "Imxhc3Rfc3NvX2F0IjoxNzk1MDAwMDAwLCJpYXQiOjE3OTUwMDAxMDAsImV4cCI6MTc5NTAwMDEzMCwi",
                "anRpIjoicGFXbHBhV2xwYVdscGFXbHBhV2wiLCJtIjoiUE9TVCIsInAiOiIvdm1zL2Rldi9kZWxldGU_",
                "Y29uZmlybT0xIiwic2giOiJjc1lldlJ0Qm1ka3BoOWtZVGtuUUgxNWpXd3ZuR0Q4ZGtEQzdpeGMteTJJ",
                "In0",
                ".",
                "0pdcx6NyS6DRj4xlvmmsydOnPfm0uWHlCZUHdXH6Bl--3SfRixQy9j840ui9nhBgZzDaXeZnO-O-kKFBDRxACg"
            ),
        ),
    ];

    #[test]
    fn the_payload_keeps_its_field_order_and_nulls() {
        let mut claims = vector_claims();
        claims.last_sso_at = None;
        claims.sh = None;
        let json = serde_json::to_string(&claims).unwrap();
        assert_eq!(
            json,
            r#"{"aud":"6f1b0c3e-0000-4000-8000-000000000001","sub":"9a7e5b2c-0000-4000-8000-000000000002","name":"alice","auth":"user","last_sso_at":null,"iat":1795000100,"exp":1795000130,"jti":"paWlpaWlpaWlpaWlpaWlpQ","m":"POST","p":"/vms/dev/delete?confirm=1","sh":null}"#
        );
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
        let [version, kid, _, sig] = value.split('.').collect::<Vec<_>>()[..] else {
            panic!("four parts");
        };
        let forged = format!("{version}.{kid}.{forged_payload}.{sig}");
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
