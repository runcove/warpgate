//! `warpgate statement-keys`: the host-only rotation of the keys that sign
//! session statements. Publish first, then sign: `add-next`, re-pin on every
//! verifier, `promote`, then `retire` the old key. Prints key ids and public
//! halves only; the private half never leaves the database.

use anyhow::{Result, bail};
use warpgate_common::GlobalParams;
use warpgate_core::db::connect_to_db_and_migrate;
use warpgate_core::statement_keys::{
    STATEMENT_KEY_ALG, add_next_statement_key, list_statement_keys, promote_statement_key,
    retire_statement_key, statement_keys_enabled,
};

use crate::config::load_config;

#[derive(clap::Subcommand)]
pub(crate) enum StatementKeysCommand {
    /// List the keys: id, slot, algorithm, public key, created
    List,
    /// Generate a new key and publish it without signing with it
    AddNext,
    /// Make the next key sign; the signing key becomes the retiring one
    Promote { kid: String },
    /// Remove a next or retiring key
    Retire { kid: String },
}

pub(crate) async fn command(params: &GlobalParams, action: &StatementKeysCommand) -> Result<()> {
    let config = load_config(params, true)?;
    let db = connect_to_db_and_migrate(&config, params).await?;

    match action {
        StatementKeysCommand::List => {
            if !statement_keys_enabled() {
                println!(
                    "WARPGATE_ENCRYPTION_KEY is not set: no key is published and nothing is signed."
                );
            }
            for key in list_statement_keys(&db).await? {
                println!(
                    "{}\t{}\t{STATEMENT_KEY_ALG}\t{}\t{}",
                    key.kid,
                    key.slot.name(),
                    key.public_key,
                    key.created_at
                );
            }
        }
        StatementKeysCommand::AddNext => match add_next_statement_key(&db).await {
            Ok(kid) => println!("Added next key {kid}. It is published and does not sign."),
            Err(error) => bail!("{error}"),
        },
        StatementKeysCommand::Promote { kid } => match promote_statement_key(&db, kid).await {
            Ok(()) => println!("Key {kid} now signs; the previous key is retiring."),
            Err(error) => bail!("{error}"),
        },
        StatementKeysCommand::Retire { kid } => match retire_statement_key(&db, kid).await {
            Ok(()) => println!("Key {kid} removed."),
            Err(error) => bail!("{error}"),
        },
    }
    Ok(())
}
