use sea_orm_migration::prelude::*;

use crate::helpers::string_default_value;
use crate::m00010_parameters::parameters;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();
        manager
            .alter_table(
                Table::alter()
                    .table(parameters::Entity)
                    .add_column(
                        // A JSON list of CIDR strings; empty keeps upstream behaviour.
                        ColumnDef::new(Alias::new("lp_ip_exempt_cidrs"))
                            .text()
                            .not_null()
                            .default(string_default_value(backend, "[]")),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(parameters::Entity)
                    .drop_column(Alias::new("lp_ip_exempt_cidrs"))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
