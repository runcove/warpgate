use sea_orm_migration::prelude::*;

/// One-time handoffs that give a browser a session on a host bound to an HTTP
/// target, issued by the control-plane host. Rows live for seconds and are
/// deleted when used or expired.
#[derive(DeriveMigrationName)]
pub struct Migration;

const TABLE: &str = "cove_http_handoffs";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Alias::new(TABLE))
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Alias::new("challenge_hash"))
                            .string_len(64)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("token_hash"))
                            .string_len(64)
                            .null()
                            .unique_key(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("nonce_hash"))
                            .string_len(64)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("hostname"))
                            .string_len(255)
                            .not_null(),
                    )
                    .col(ColumnDef::new(Alias::new("target_id")).uuid().not_null())
                    .col(ColumnDef::new(Alias::new("next")).text().not_null())
                    .col(ColumnDef::new(Alias::new("user_id")).uuid().null())
                    .col(ColumnDef::new(Alias::new("user_session_id")).uuid().null())
                    .col(
                        ColumnDef::new(Alias::new("expires"))
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
