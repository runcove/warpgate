use sea_orm_migration::prelude::*;

/// The keys that sign session statements: at most one per slot (`active`,
/// `next`, `retiring`), the private half encrypted with the keyring. The
/// table starts empty; `ensure_statement_key` fills the active slot at
/// startup when an encryption key is configured.
#[derive(DeriveMigrationName)]
pub struct Migration;

const TABLE: &str = "cove_statement_keys";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Alias::new(TABLE))
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Alias::new("kid"))
                            .string_len(64)
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Alias::new("public_key")).text().not_null())
                    .col(ColumnDef::new(Alias::new("secret_key")).text().not_null())
                    .col(
                        ColumnDef::new(Alias::new("slot"))
                            .string_len(16)
                            .not_null()
                            .unique_key(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("created_at"))
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(Alias::new(TABLE))
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}
