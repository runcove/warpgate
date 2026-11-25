use poem_openapi::param::{Path, Query};
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, OpenApi};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};
use tracing::warn;
use uuid::Uuid;
use warpgate_common::{
    AdminPermission, Role as RoleConfig, StoredSecrets, Target as TargetConfig, TargetOptions,
    TargetSSHOptions, WarpgateError, host_binding_conflict,
};
use warpgate_common_http::errors::invalid_field;
use warpgate_core::AccessChange;
use warpgate_core::resources::ResourceError;
use warpgate_core::resources::targets::{self as store, TargetDataRequest};
use warpgate_db_entities::Target::fuzzy_filter_targets;
use warpgate_db_entities::{KnownHost, Role, Target, TargetGroup};

use super::AdminContext;

/// Why an HTTP target's `unix_socket` cannot be served by this Warpgate, if
/// it cannot.
async fn unix_socket_refusal(admin: &AdminContext, options: &TargetOptions) -> Option<String> {
    let TargetOptions::Http(options) = options else {
        return None;
    };
    options.unix_socket.as_ref()?;
    let loopback = admin
        .services()
        .config
        .lock()
        .await
        .store
        .http
        .plain_http_on_loopback;
    options.check_unix_socket(loopback).err()
}

/// Why an HTTP target's configured headers are refused, if they are: a name
/// in the `x-warpgate-` family is Warpgate's own (identity headers, the
/// session statement), compared ASCII case-insensitively.
fn reserved_header_refusal(options: &TargetOptions) -> Option<String> {
    let TargetOptions::Http(options) = options else {
        return None;
    };
    options
        .headers
        .keys()
        .any(|name| name.trim().to_ascii_lowercase().starts_with("x-warpgate-"))
        .then(|| "header names starting with `x-warpgate-` are reserved".to_owned())
}

/// Why an HTTP target's `external_host` binding is refused, if it is: it is
/// on the control-plane host (at any port), or another target's binding
/// shares its hostname (at any port), compared ASCII case-insensitively
/// ([`host_binding_conflict`]). `id` is the target being updated, left out of
/// the comparison; `None` on create.
async fn host_binding_refusal(
    admin: &AdminContext,
    options: &TargetOptions,
    id: Option<Uuid>,
) -> Result<Option<String>, WarpgateError> {
    let services = admin.services();
    let control_plane = services.config.lock().await.control_plane_host();
    binding_refusal_in(&services.db, control_plane.as_deref(), options, id).await
}

/// [`host_binding_refusal`] against the targets stored in `db` and the
/// control-plane host `control_plane`.
async fn binding_refusal_in(
    db: &sea_orm::DatabaseConnection,
    control_plane: Option<&str>,
    options: &TargetOptions,
    id: Option<Uuid>,
) -> Result<Option<String>, WarpgateError> {
    let Some(binding) = options.external_host().filter(|host| !host.is_empty()) else {
        return Ok(None);
    };
    let others: Vec<(String, String)> = Target::Entity::find()
        .all(db)
        .await?
        .into_iter()
        .filter(|other| Some(other.id) != id)
        .filter_map(|other| {
            let host = other
                .options
                .pointer("/http/external_host")
                .and_then(|value| value.as_str())
                .filter(|value| !value.is_empty())?
                .to_owned();
            Some((other.name, host))
        })
        .collect();
    Ok(host_binding_conflict(
        binding,
        control_plane,
        others
            .iter()
            .map(|(name, host)| (name.as_str(), host.as_str())),
    )
    .map(|conflict| conflict.to_string()))
}

pub(crate) fn maybe_redacted_target(
    admin: &AdminContext,
    model: Target::Model,
) -> Result<TargetConfig, WarpgateError> {
    let mut target: TargetConfig = model.try_into()?;
    if !admin.has_permission(AdminPermission::TargetsEdit) {
        target.redact();
    }
    Ok(target)
}

#[derive(ApiResponse)]
enum GetTargetsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<TargetConfig>>),
}

#[allow(clippy::large_enum_variant)]
#[derive(ApiResponse)]
enum CreateTargetResponse {
    #[oai(status = 201)]
    Created(Json<TargetConfig>),

    #[oai(status = 409)]
    Conflict(Json<String>),

    #[oai(status = 400)]
    BadRequest(Json<String>),
}

pub struct ListApi;

#[OpenApi]
impl ListApi {
    #[oai(path = "/targets", method = "get", operation_id = "get_targets")]
    async fn api_get_all_targets(
        &self,
        admin: AdminContext,
        search: Query<Option<String>>,
        group_id: Query<Option<Uuid>>,
    ) -> Result<GetTargetsResponse, WarpgateError> {
        let db = &admin.services().db;

        let groups: Vec<TargetGroup::Model> = TargetGroup::Entity::find().all(db).await?;

        let mut targets = Target::Entity::find().order_by_asc(Target::Column::Name);
        if let Some(group_id) = *group_id {
            targets = targets.filter(Target::Column::GroupId.eq(group_id));
        }

        let all_targets = targets.all(db).await.map_err(WarpgateError::from)?;

        let targets =
            fuzzy_filter_targets(&all_targets, &groups, search.as_deref().unwrap_or_default());

        let targets = targets
            .into_iter()
            .map(|t| maybe_redacted_target(&admin, t.clone()))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(GetTargetsResponse::Ok(Json(targets)))
    }

    #[oai(path = "/targets", method = "post", operation_id = "create_target")]
    async fn api_create_target(
        &self,
        admin: AdminContext,
        body: Json<TargetDataRequest>,
    ) -> Result<CreateTargetResponse, WarpgateError> {
        admin.require(AdminPermission::TargetsCreate)?;

        if let Some(reason) = unix_socket_refusal(&admin, &body.options).await {
            return Ok(CreateTargetResponse::BadRequest(invalid_field(
                "unix_socket",
                &reason,
            )));
        }
        if let Some(reason) = reserved_header_refusal(&body.options) {
            return Ok(CreateTargetResponse::BadRequest(invalid_field(
                "headers", &reason,
            )));
        }
        if let Some(reason) = host_binding_refusal(&admin, &body.options, None).await? {
            warn!("Rejecting request: {reason}");
            return Ok(CreateTargetResponse::Conflict(Json(reason)));
        }

        match store::create(&admin.services().db, &body).await {
            Ok(target) => Ok(CreateTargetResponse::Created(Json(maybe_redacted_target(
                &admin, target,
            )?))),
            Err(ResourceError::EmptyName) => Ok(CreateTargetResponse::BadRequest(invalid_field(
                "name",
                "target name is empty",
            ))),
            Err(ResourceError::NameTaken) => Ok(CreateTargetResponse::Conflict(Json(
                "Name already exists".into(),
            ))),
            Err(err) => Err(err.into()),
        }
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(ApiResponse)]
enum GetTargetResponse {
    #[oai(status = 200)]
    Ok(Json<TargetConfig>),
    #[oai(status = 404)]
    NotFound,
}

#[allow(clippy::large_enum_variant)]
#[derive(ApiResponse)]
enum UpdateTargetResponse {
    #[oai(status = 200)]
    Ok(Json<TargetConfig>),
    #[oai(status = 400)]
    BadRequest(Json<String>),
    #[oai(status = 409)]
    Conflict(Json<String>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum DeleteTargetResponse {
    #[oai(status = 204)]
    Deleted,

    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum TargetKnownSshHostKeysResponse {
    #[oai(status = 200)]
    Found(Json<Vec<KnownHost::Model>>),

    #[oai(status = 400)]
    InvalidType,

    #[oai(status = 404)]
    NotFound,
}

pub struct DetailApi;

#[OpenApi]
impl DetailApi {
    #[oai(path = "/targets/:id", method = "get", operation_id = "get_target")]
    async fn api_get_target(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<GetTargetResponse, WarpgateError> {
        let db = &admin.services().db;

        let Some(target) = Target::Entity::find_by_id(id.0).one(db).await? else {
            return Ok(GetTargetResponse::NotFound);
        };

        Ok(GetTargetResponse::Ok(Json(maybe_redacted_target(
            &admin, target,
        )?)))
    }

    #[oai(path = "/targets/:id", method = "put", operation_id = "update_target")]
    async fn api_update_target(
        &self,
        admin: AdminContext,
        body: Json<TargetDataRequest>,
        id: Path<Uuid>,
    ) -> Result<UpdateTargetResponse, WarpgateError> {
        admin.require(AdminPermission::TargetsEdit)?;

        if let Some(reason) = unix_socket_refusal(&admin, &body.options).await {
            warn!("Rejecting request: {reason}");
            return Ok(UpdateTargetResponse::BadRequest(invalid_field(
                "unix_socket",
                &reason,
            )));
        }
        if let Some(reason) = reserved_header_refusal(&body.options) {
            warn!("Rejecting request: {reason}");
            return Ok(UpdateTargetResponse::BadRequest(invalid_field(
                "headers", &reason,
            )));
        }
        if let Some(reason) = host_binding_refusal(&admin, &body.options, Some(id.0)).await? {
            warn!("Rejecting request: {reason}");
            return Ok(UpdateTargetResponse::Conflict(Json(reason)));
        }

        let services = admin.services();
        let target = match store::update(&services.db, id.0, &body).await {
            Ok(target) => target,
            Err(ResourceError::EmptyName) => {
                warn!("Rejecting request: target name is empty");
                return Ok(UpdateTargetResponse::BadRequest(invalid_field(
                    "name",
                    "target name is empty",
                )));
            }
            Err(ResourceError::ProtocolChange) => {
                warn!("Rejecting request: a target's protocol cannot be changed after creation");
                return Ok(UpdateTargetResponse::BadRequest(invalid_field(
                    "options",
                    "a target's protocol cannot be changed after creation",
                )));
            }
            Err(ResourceError::NameTaken) => {
                return Ok(UpdateTargetResponse::Conflict(Json(
                    "Name already exists".into(),
                )));
            }
            Err(ResourceError::NotFound) => return Ok(UpdateTargetResponse::NotFound),
            Err(err) => return Err(err.into()),
        };

        // Unsharing a public target must end the websockets and streams already
        // open through the public bypass, on every node. First, straight after
        // the commit: nothing that can fail may come between the two, or the
        // unshare would never reach the streams (this call queues its own
        // failures for retry).
        services
            .close_sessions_no_longer_authorised(AccessChange::Targets(vec![id.0]))
            .await?;

        warpgate_core::rate_limiting::apply_new_rate_limits(
            &services.rate_limiter_registry,
            &services.state,
        )
        .await?;

        Ok(UpdateTargetResponse::Ok(Json(
            target.try_into().map_err(WarpgateError::from)?,
        )))
    }

    #[oai(
        path = "/targets/:id",
        method = "delete",
        operation_id = "delete_target"
    )]
    async fn api_delete_target(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<DeleteTargetResponse, WarpgateError> {
        admin.require(AdminPermission::TargetsDelete)?;

        let services = admin.services();
        match store::delete(&services.db, id.0).await {
            Ok(admitted) => {
                // Any live session or stream to the target ends now that no one
                // may reach it. First, straight after the commit, so a failure
                // below cannot keep it from every node (this call queues its own
                // failures for retry).
                services
                    .close_sessions_no_longer_authorised(AccessChange::Targets(vec![id.0]))
                    .await?;
                // The sessions a ticket opened, which the re-check above leaves
                // alone, went with their ticket.
                services.close_admitted_sessions(admitted).await?;
                Ok(DeleteTargetResponse::Deleted)
            }
            Err(ResourceError::NotFound) => Ok(DeleteTargetResponse::NotFound),
            Err(err) => Err(err.into()),
        }
    }

    #[oai(
        path = "/targets/:id/known-ssh-host-keys",
        method = "get",
        operation_id = "get_ssh_target_known_ssh_host_keys"
    )]
    async fn get_ssh_target_known_ssh_host_keys(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<TargetKnownSshHostKeysResponse, WarpgateError> {
        admin.require(AdminPermission::TargetsEdit)?;

        let db = &admin.services().db;

        let Some(target) = Target::Entity::find_by_id(id.0).one(db).await? else {
            return Ok(TargetKnownSshHostKeysResponse::NotFound);
        };

        let target: TargetConfig = target.try_into()?;

        let options: TargetSSHOptions = match target.options {
            TargetOptions::Ssh(x) => x,
            _ => {
                warn!("Rejecting request: known SSH host keys are only kept for SSH targets");
                return Ok(TargetKnownSshHostKeysResponse::InvalidType);
            }
        };

        let known_hosts = KnownHost::Entity::find()
            .filter(
                KnownHost::Column::Host
                    .eq(&options.host)
                    .and(KnownHost::Column::Port.eq(options.port)),
            )
            .all(db)
            .await?;

        Ok(TargetKnownSshHostKeysResponse::Found(Json(known_hosts)))
    }
}

#[derive(ApiResponse)]
enum GetTargetRolesResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<RoleConfig>>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum AddTargetRoleResponse {
    #[oai(status = 201)]
    Created,
    #[oai(status = 409)]
    AlreadyExists,
}

#[derive(ApiResponse)]
enum DeleteTargetRoleResponse {
    #[oai(status = 204)]
    Deleted,
    #[oai(status = 404)]
    NotFound,
}

pub struct RolesApi;

#[OpenApi]
impl RolesApi {
    #[oai(
        path = "/targets/:id/roles",
        method = "get",
        operation_id = "get_target_roles"
    )]
    async fn api_get_target_roles(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<GetTargetRolesResponse, WarpgateError> {
        let db = &admin.services().db;

        let Some((_, roles)) = Target::Entity::find_by_id(*id)
            .find_with_related(Role::Entity)
            .all(db)
            .await
            .map(|x| x.into_iter().next())
            .map_err(WarpgateError::from)?
        else {
            return Ok(GetTargetRolesResponse::NotFound);
        };

        Ok(GetTargetRolesResponse::Ok(Json(
            roles.into_iter().map(Into::into).collect(),
        )))
    }

    #[oai(
        path = "/targets/:id/roles/:role_id",
        method = "post",
        operation_id = "add_target_role"
    )]
    async fn api_add_target_role(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
        role_id: Path<Uuid>,
    ) -> Result<AddTargetRoleResponse, WarpgateError> {
        admin.require(AdminPermission::AccessRolesAssign)?;

        match store::add_role(&admin.services().db, id.0, role_id.0).await {
            Ok(()) => Ok(AddTargetRoleResponse::Created),
            Err(ResourceError::RoleAlreadyAssigned) => Ok(AddTargetRoleResponse::AlreadyExists),
            Err(err) => Err(err.into()),
        }
    }

    #[oai(
        path = "/targets/:id/roles/:role_id",
        method = "delete",
        operation_id = "delete_target_role"
    )]
    async fn api_delete_target_role(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
        role_id: Path<Uuid>,
    ) -> Result<DeleteTargetRoleResponse, WarpgateError> {
        admin.require(AdminPermission::AccessRolesAssign)?;

        match store::remove_role(&admin.services().db, id.0, role_id.0).await {
            Ok(()) => {
                admin
                    .services()
                    .close_sessions_no_longer_authorised(AccessChange::Targets(vec![id.0]))
                    .await?;
                Ok(DeleteTargetRoleResponse::Deleted)
            }
            Err(ResourceError::NotFound) => Ok(DeleteTargetRoleResponse::NotFound),
            Err(err) => Err(err.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::ActiveValue::Set;
    use sea_orm::{ActiveModelTrait, Database, DatabaseConnection};
    use warpgate_db_entities::Parameters::{ConfigMigrationValues, set_config_migration_values};
    use warpgate_db_entities::Target::TargetKind;

    use super::*;

    const CONTROL_PLANE: Option<&str> = Some("warp.example.com");

    async fn memory_db() -> DatabaseConnection {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        warpgate_db_migrations::migrate_database(&db).await.unwrap();
        db
    }

    async fn bound_target(db: &DatabaseConnection, name: &str, external_host: &str) -> Uuid {
        let id = Uuid::new_v4();
        Target::ActiveModel {
            id: Set(id),
            name: Set(name.into()),
            description: Set(String::new()),
            kind: Set(TargetKind::Http),
            options: Set(serde_json::to_value(http_options(external_host)).unwrap()),
            rate_limit_bytes_per_second: Set(None),
            group_id: Set(None),
            ticket_max_duration_seconds: Set(None),
            ticket_requests_disabled: Set(false),
            ticket_require_approval: Set(false),
            ticket_max_uses: Set(None),
            require_approval: Set(false),
        }
        .insert(db)
        .await
        .unwrap();
        id
    }

    fn http_options(external_host: &str) -> TargetOptions {
        serde_json::from_value(serde_json::json!({
            "http": {"url": "http://h", "external_host": external_host}
        }))
        .unwrap()
    }

    /// A configured header in Warpgate's own `x-warpgate-` family is refused
    /// in any letter case; other names, and other target kinds, pass.
    #[test]
    fn x_warpgate_header_names_are_refused() {
        let with_header = |name: &str| -> TargetOptions {
            serde_json::from_value(serde_json::json!({
                "http": {"url": "http://h", "headers": {name: "v", "X-Other": "v"}}
            }))
            .unwrap()
        };
        for name in [
            "x-warpgate-session-freshness",
            "X-Warpgate-Session-Freshness",
            "X-WARPGATE-USERNAME",
            "x-warpgate-anything",
        ] {
            assert!(
                reserved_header_refusal(&with_header(name)).is_some(),
                "{name}"
            );
        }
        for name in ["x-warpgated", "authorization", "x-backend-token"] {
            assert!(
                reserved_header_refusal(&with_header(name)).is_none(),
                "{name}"
            );
        }
        let no_headers: TargetOptions =
            serde_json::from_value(serde_json::json!({"http": {"url": "http://h"}})).unwrap();
        assert!(reserved_header_refusal(&no_headers).is_none());
    }

    /// An update is checked against every OTHER target: a target keeping
    /// (or re-casing, or changing the port of) its own hostname passes.
    #[tokio::test]
    async fn an_update_keeping_its_own_hostname_passes() {
        let db = memory_db().await;
        let own = bound_target(&db, "own", "vm.example.com:3000").await;
        bound_target(&db, "other", "other.example.com").await;
        for binding in [
            "vm.example.com:3000",
            "VM.example.com:8080",
            "vm.example.com",
        ] {
            assert_eq!(
                binding_refusal_in(&db, CONTROL_PLANE, &http_options(binding), Some(own))
                    .await
                    .unwrap(),
                None,
                "{binding}"
            );
        }
        // The same binding on create is another target's: refused.
        assert!(
            binding_refusal_in(
                &db,
                CONTROL_PLANE,
                &http_options("vm.example.com:3000"),
                None
            )
            .await
            .unwrap()
            .is_some()
        );
    }

    #[tokio::test]
    async fn an_update_to_the_control_plane_host_is_refused() {
        let db = memory_db().await;
        let own = bound_target(&db, "own", "vm.example.com:3000").await;
        for binding in ["warp.example.com", "WARP.example.com:8443"] {
            let refusal = binding_refusal_in(&db, CONTROL_PLANE, &http_options(binding), Some(own))
                .await
                .unwrap();
            assert!(
                refusal
                    .as_deref()
                    .is_some_and(|r| r.contains("Warpgate's own host")),
                "{binding}: {refusal:?}"
            );
        }
    }

    #[tokio::test]
    async fn an_update_to_another_targets_hostname_is_refused() {
        let db = memory_db().await;
        let own = bound_target(&db, "own", "vm.example.com:3000").await;
        bound_target(&db, "other", "other.example.com:3000").await;
        for binding in ["other.example.com:3000", "OTHER.example.com:8080"] {
            let refusal = binding_refusal_in(&db, CONTROL_PLANE, &http_options(binding), Some(own))
                .await
                .unwrap();
            assert!(
                refusal.as_deref().is_some_and(|r| r.contains("`other`")),
                "{binding}: {refusal:?}"
            );
        }
    }
}
