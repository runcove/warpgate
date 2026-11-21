use sea_orm::entity::prelude::*;
use time::OffsetDateTime;
use warpgate_common::StoredSecret;

/// Which part a statement key plays in a rotation. At most one key holds
/// each slot (a unique index). Only the `Active` key signs; `Next` and
/// `Retiring` are published so that a verifier can pin them ahead of and
/// after a promotion.
#[derive(Debug, PartialEq, Eq, Clone, Copy, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(16))")]
pub enum StatementKeySlot {
    #[sea_orm(string_value = "active")]
    Active,
    #[sea_orm(string_value = "next")]
    Next,
    #[sea_orm(string_value = "retiring")]
    Retiring,
}

impl StatementKeySlot {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Next => "next",
            Self::Retiring => "retiring",
        }
    }
}

/// An Ed25519 key that signs session statements on HTTP targets with
/// `signed_statement` on. The private half never leaves Warpgate: the model
/// is not serializable, and `StoredSecret` prints as `<secret>`.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "cove_statement_keys")]
pub struct Model {
    /// base64url (no padding) of the SHA-256 of the raw 32-byte public key
    #[sea_orm(primary_key, auto_increment = false)]
    pub kid: String,
    /// base64url (no padding) of the raw 32-byte public key
    #[sea_orm(column_type = "Text")]
    pub public_key: String,
    /// base64url (no padding) of the 32-byte seed, encrypted at rest with
    /// the keyring like every other stored credential
    #[sea_orm(column_type = "Text")]
    pub secret_key: StoredSecret,
    #[sea_orm(unique)]
    pub slot: StatementKeySlot,
    pub created_at: OffsetDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
