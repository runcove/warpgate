use sea_orm::entity::prelude::*;
use sea_orm::{PaginatorTrait, QueryFilter, Set, TransactionTrait};
use time::OffsetDateTime;
use warpgate_common::WarpgateError;

/// A one-time handoff of a sign-in from the control-plane host to a host
/// bound to an HTTP target, in three single-use steps:
///
/// 1. [`open`]: the bound host, asked for a page by a browser without a
///    session there, records which host and target the browser wants, the
///    page to return to, and the hash of a nonce it gives that browser in a
///    cookie. The browser carries the challenge (hashed here) to the control
///    plane.
/// 2. [`mint`]: the control plane, once the browser is signed in there,
///    fills in the user and the user session, and the hash of a token it
///    sends the browser back to the bound host with.
/// 3. [`take`]: the bound host deletes the row by the token's hash before it
///    checks anything else, so a token is used at most once whatever the
///    outcome.
///
/// Only hashes of the challenge, nonce and token are stored.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "cove_http_handoffs")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub challenge_hash: String,
    pub token_hash: Option<String>,
    pub nonce_hash: String,
    pub hostname: String,
    pub target_id: Uuid,
    pub next: String,
    pub user_id: Option<Uuid>,
    pub user_session_id: Option<Uuid>,
    /// When the control-plane session that minted this handoff last did an
    /// SSO handshake, for the bound host's step-up gate.
    pub last_sso_at: Option<OffsetDateTime>,
    pub expires: OffsetDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

/// The opened handoff a bound host records ([`open`]).
pub struct Opening {
    pub challenge_hash: String,
    pub nonce_hash: String,
    pub hostname: String,
    pub target_id: Uuid,
    pub next: String,
    pub expires: OffsetDateTime,
}

/// Records an opened handoff.
pub async fn open<C: ConnectionTrait>(db: &C, opening: Opening) -> Result<(), WarpgateError> {
    Entity::insert(ActiveModel {
        challenge_hash: Set(opening.challenge_hash),
        token_hash: Set(None),
        nonce_hash: Set(opening.nonce_hash),
        hostname: Set(opening.hostname),
        target_id: Set(opening.target_id),
        next: Set(opening.next),
        user_id: Set(None),
        user_session_id: Set(None),
        last_sso_at: Set(None),
        expires: Set(opening.expires),
    })
    .exec_without_returning(db)
    .await?;
    Ok(())
}

/// The opened handoff with this challenge hash, if it is unexpired and not yet
/// minted. Reading it changes nothing.
pub async fn opened<C: ConnectionTrait>(
    db: &C,
    challenge_hash: &str,
    now: OffsetDateTime,
) -> Result<Option<Model>, WarpgateError> {
    Ok(Entity::find_by_id(challenge_hash.to_owned())
        .filter(Column::TokenHash.is_null())
        .filter(Column::Expires.gt(now))
        .one(db)
        .await?)
}

/// What the control plane fills in when it mints a handoff ([`mint`]).
pub struct Minting {
    pub token_hash: String,
    pub user_id: Uuid,
    pub user_session_id: Uuid,
    pub last_sso_at: Option<OffsetDateTime>,
    pub expires: OffsetDateTime,
}

/// Fills in the user and token of the opened handoff with this challenge hash.
/// Returns whether it did: `false` when the challenge is unknown, expired or
/// was already minted, so a challenge mints at most one token.
pub async fn mint<C: ConnectionTrait>(
    db: &C,
    challenge_hash: &str,
    minting: Minting,
    now: OffsetDateTime,
) -> Result<bool, WarpgateError> {
    let result = Entity::update_many()
        .set(ActiveModel {
            token_hash: Set(Some(minting.token_hash)),
            user_id: Set(Some(minting.user_id)),
            user_session_id: Set(Some(minting.user_session_id)),
            last_sso_at: Set(minting.last_sso_at),
            expires: Set(minting.expires),
            ..Default::default()
        })
        .filter(Column::ChallengeHash.eq(challenge_hash))
        .filter(Column::TokenHash.is_null())
        .filter(Column::Expires.gt(now))
        .exec(db)
        .await?;
    Ok(result.rows_affected == 1)
}

/// Deletes the minted handoff with this token hash and returns it if this call
/// deleted it and it had not expired. The row is gone afterwards in every
/// case, so a token is never accepted twice, even by two nodes at once: only
/// the call whose delete removed the row gets it.
pub async fn take<C: ConnectionTrait + TransactionTrait>(
    db: &C,
    token_hash: &str,
    now: OffsetDateTime,
) -> Result<Option<Model>, WarpgateError> {
    let tx = db.begin().await?;
    let Some(row) = Entity::find()
        .filter(Column::TokenHash.eq(token_hash))
        .one(&tx)
        .await?
    else {
        tx.commit().await?;
        return Ok(None);
    };
    let deleted = Entity::delete_many()
        .filter(Column::ChallengeHash.eq(row.challenge_hash.clone()))
        .exec(&tx)
        .await?;
    tx.commit().await?;
    Ok((deleted.rows_affected == 1 && row.expires > now).then_some(row))
}

/// How many handoffs are stored, expired or not: what [`open`] is refused
/// past (`warpgate_protocol_http::handoff`'s ceiling).
pub async fn count<C: ConnectionTrait>(db: &C) -> Result<u64, WarpgateError> {
    Ok(Entity::find().count(db).await?)
}

/// Deletes every expired handoff.
pub async fn purge_expired<C: ConnectionTrait>(
    db: &C,
    now: OffsetDateTime,
) -> Result<u64, WarpgateError> {
    Ok(Entity::delete_many()
        .filter(Column::Expires.lte(now))
        .exec(db)
        .await?
        .rows_affected)
}
