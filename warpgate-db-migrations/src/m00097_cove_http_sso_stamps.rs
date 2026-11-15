use sea_orm_migration::prelude::*;

/// The latest SSO sign-in of each HTTP user session, against which a
/// target-host session's own copy is checked: one older than a later sign-in
/// (a step-up) is refused.
#[derive(DeriveMigrationName)]
pub struct Migration;

const TABLE: &str = "cove_http_sso_stamps";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Alias::new(TABLE))
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Alias::new("user_session_id"))
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("last_sso_at"))
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        crate::helpers::refuse_down_while_http_sessions_remain(manager, &self.name()).await?;
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
