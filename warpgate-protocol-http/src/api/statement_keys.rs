//! `GET /@warpgate/api/statement-keys`: the public halves of the keys that
//! sign session statements, for a verifier to pin. Unauthenticated: it serves
//! public keys only. Never the private half. A host bound to an HTTP target
//! answers 404 (`ManagementScopeMiddleware`). Deliberately not JWKS: a
//! verifier pins this set and never fetches a key for an id it does not know.

use poem::web::Data;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use warpgate_common::WarpgateError;
use warpgate_common_http::auth::UnauthenticatedRequestContext;
use warpgate_core::statement_keys::{
    PublishedStatementKey, STATEMENT_KEY_ALG, published_statement_keys,
};

pub struct Api;

#[derive(Object, Debug, PartialEq, Eq)]
pub struct StatementKeyDescription {
    /// base64url (no padding) of the SHA-256 of the raw public key
    pub kid: String,
    /// Always `Ed25519`
    pub alg: String,
    /// base64url (no padding) of the raw 32-byte public key
    pub public_key: String,
    /// Whether this key signs; true for exactly one key when any exists
    pub signing: bool,
}

impl From<PublishedStatementKey> for StatementKeyDescription {
    fn from(key: PublishedStatementKey) -> Self {
        Self {
            signing: key.signing(),
            kid: key.kid,
            alg: STATEMENT_KEY_ALG.into(),
            public_key: key.public_key,
        }
    }
}

#[derive(ApiResponse)]
enum GetStatementKeysResponse {
    /// The published keys; empty when Warpgate has no statement key
    #[oai(status = 200)]
    Ok(Json<Vec<StatementKeyDescription>>),
}

#[OpenApi]
impl Api {
    #[oai(
        path = "/statement-keys",
        method = "get",
        operation_id = "get_statement_keys"
    )]
    async fn api_get_statement_keys(
        &self,
        ctx: Data<&UnauthenticatedRequestContext>,
    ) -> Result<GetStatementKeysResponse, WarpgateError> {
        let keys = published_statement_keys(&ctx.services().db).await?;
        Ok(GetStatementKeysResponse::Ok(Json(
            keys.into_iter().map(Into::into).collect(),
        )))
    }
}

#[cfg(test)]
mod tests {
    use poem::http::Method;
    use time::OffsetDateTime;
    use warpgate_db_entities::StatementKey::StatementKeySlot;

    use super::*;
    use crate::middleware::is_served_on_bound_host;

    #[test]
    fn a_bound_host_does_not_serve_the_key_list() {
        assert!(!is_served_on_bound_host(
            &Method::GET,
            "/@warpgate/api/statement-keys"
        ));
    }

    #[test]
    fn the_description_carries_the_public_half_only() {
        let description = StatementKeyDescription::from(PublishedStatementKey {
            kid: "kid".into(),
            public_key: "pub".into(),
            slot: StatementKeySlot::Next,
            created_at: OffsetDateTime::UNIX_EPOCH,
        });
        assert_eq!(
            description,
            StatementKeyDescription {
                kid: "kid".into(),
                alg: "Ed25519".into(),
                public_key: "pub".into(),
                signing: false,
            }
        );
        let json = poem_openapi::types::ToJSON::to_json(&description).unwrap();
        let mut fields: Vec<_> = json.as_object().unwrap().keys().cloned().collect();
        fields.sort_unstable();
        assert_eq!(fields, ["alg", "kid", "public_key", "signing"]);
    }
}
