use poem::Request;
use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, DatabaseConnection, EntityTrait, ModelTrait,
    QueryFilter, QueryOrder, QuerySelect, QueryTrait, Set, TransactionTrait,
};
use time::OffsetDateTime;
use tracing::warn;
use uuid::Uuid;
use warpgate_common::{
    AdminPermission, AdminRole as AdminRoleConfig, User as UserConfig,
    UserRequireCredentialsPolicy, WarpgateError,
};
use warpgate_common_http::errors::{bad_request, invalid_field};
use warpgate_common_http::logging::get_client_ip_addr;
use warpgate_core::logging::{AuditEvent, format_related_ids};
use warpgate_core::resources::AdmittedSessions;
use warpgate_core::{AccessChange, SessionsFilter};
use warpgate_db_entities::{
    AdminRole, PendingSessionClose, PendingUserClose, Role, TargetSession, Ticket, TicketRequest,
    User, UserAdminRoleAssignment, UserRoleAssignment,
};

use super::{AdminContext, guard_user_mutation};
use crate::api::common::case_insensitive_search;

#[derive(Object)]
struct CreateUserRequest {
    username: String,
    description: Option<String>,
}

#[derive(Object)]
struct UserDataRequest {
    username: String,
    credential_policy: Option<UserRequireCredentialsPolicy>,
    description: Option<String>,
    rate_limit_bytes_per_second: Option<u32>,
    allowed_ip_ranges: Option<Vec<String>>,
}

#[derive(ApiResponse)]
enum GetUsersResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<UserConfig>>),
}

#[derive(ApiResponse)]
#[allow(clippy::large_enum_variant)]
enum CreateUserResponse {
    #[oai(status = 201)]
    Created(Json<UserConfig>),

    #[oai(status = 400)]
    BadRequest(Json<String>),
}

pub struct ListApi;

#[OpenApi]
impl ListApi {
    #[oai(path = "/users", method = "get", operation_id = "get_users")]
    async fn api_get_all_users(
        &self,
        admin: AdminContext,
        search: poem_openapi::param::Query<Option<String>>,
    ) -> Result<GetUsersResponse, WarpgateError> {
        let db = &admin.services().db;

        let mut users = User::Entity::find().order_by_asc(User::Column::Username);

        if let Some(ref search) = *search {
            users = users.filter(case_insensitive_search(search, [User::Column::Username]));
        }

        let users = users.all(db).await.map_err(WarpgateError::from)?;

        let users: Vec<UserConfig> = users
            .into_iter()
            .map(UserConfig::try_from)
            .collect::<Result<Vec<UserConfig>, _>>()?;

        Ok(GetUsersResponse::Ok(Json(users)))
    }

    #[oai(path = "/users", method = "post", operation_id = "create_user")]
    async fn api_create_user(
        &self,
        admin: AdminContext,
        body: Json<CreateUserRequest>,
    ) -> Result<CreateUserResponse, WarpgateError> {
        admin.require(AdminPermission::UsersCreate)?;

        if body.username.is_empty() {
            return Ok(CreateUserResponse::BadRequest(invalid_field(
                "name",
                "username is empty",
            )));
        }

        if is_reserved_username(&body.username) {
            return Ok(CreateUserResponse::BadRequest(invalid_field(
                "username",
                RESERVED_USERNAME_MESSAGE,
            )));
        }

        let db = &admin.services().db;

        // Usernames are matched case-insensitively, so a name differing from an
        // existing one only by case is the same account. Rejected here to give a
        // field-level error rather than a bare unique-constraint failure.
        if username_taken(db, &body.username, None).await? {
            return Ok(CreateUserResponse::BadRequest(invalid_field(
                "username",
                "a user with this username already exists",
            )));
        }

        let values = User::ActiveModel {
            id: Set(Uuid::new_v4()),
            username: Set(body.username.clone()),
            credential_policy: Set(serde_json::to_value(
                admin.parameters().await?.default_credential_policy()?,
            )?),
            description: Set(body.description.clone().unwrap_or_default()),
            rate_limit_bytes_per_second: Set(None),
            ldap_server_id: Set(None),
            ldap_object_uuid: Set(None),
            allowed_ip_ranges: Set(serde_json::Value::Null),
        };

        let user = values.insert(db).await.map_err(WarpgateError::from)?;
        on_user_created(db, &user, admin.auth.user_id()).await?;

        Ok(CreateUserResponse::Created(Json(user.try_into()?)))
    }
}

pub(crate) async fn on_user_created(
    db: &sea_orm::DatabaseConnection,
    user: &User::Model,
    actor_user_id: Uuid,
) -> Result<(), WarpgateError> {
    let default_roles = Role::Entity::grant_default_roles(db, user.id).await?;

    AuditEvent::UserCreated {
        user_id: user.id,
        username: user.username.clone(),
        actor_user_id,
    }
    .emit();

    for role in default_roles {
        AuditEvent::AccessRoleGranted {
            grantee_id: user.id,
            grantee_username: user.username.clone(),
            role_id: role.id,
            role_name: role.name,
            actor_user_id,
            related_access_roles: format_related_ids(&[role.id]),
        }
        .emit();
    }
    Ok(())
}

#[derive(ApiResponse)]
#[allow(clippy::large_enum_variant)]
enum GetUserResponse {
    #[oai(status = 200)]
    Ok(Json<UserConfig>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
#[allow(clippy::large_enum_variant)]
enum UpdateUserResponse {
    #[oai(status = 200)]
    Ok(Json<UserConfig>),
    #[oai(status = 400)]
    BadRequest(Json<String>),
    #[oai(status = 404)]
    NotFound,
}

/// True when saving `new_ranges` as the calling admin's own allowed ranges
/// would no longer admit `client_ip`. `None` or an empty list means no
/// restriction, and an unknown client address cannot be judged.
fn edit_locks_out_caller(
    new_ranges: Option<&[ipnet::IpNet]>,
    client_ip: Option<std::net::IpAddr>,
) -> bool {
    let ranges: Option<Vec<warpgate_common::helpers::ipnet::WarpgateIpNet>> =
        new_ranges.map(|r| r.iter().copied().map(Into::into).collect());
    !warpgate_core::ip_allowed(ranges.as_ref(), client_ip)
}

/// Whether saving `new_ranges` would change the user's allowed ranges from
/// the `stored` column value. An unset list and an empty one both mean no
/// restriction, so they are the same; order, repeats and host bits are not
/// significant. A stored value that cannot be read counts as changed.
fn allowed_ranges_changed(stored: &serde_json::Value, new_ranges: Option<&[ipnet::IpNet]>) -> bool {
    fn canonical(ranges: impl IntoIterator<Item = ipnet::IpNet>) -> Vec<ipnet::IpNet> {
        let mut ranges: Vec<_> = ranges.into_iter().map(|range| range.trunc()).collect();
        ranges.sort();
        ranges.dedup();
        ranges
    }

    let stored = if stored.is_null() {
        Ok(vec![])
    } else {
        serde_json::from_value::<Vec<String>>(stored.clone())
            .map_err(WarpgateError::from)
            .and_then(User::parse_allowed_ip_ranges)
            .map(canonical)
    };
    match stored {
        Ok(stored) => stored != canonical(new_ranges.unwrap_or_default().iter().copied()),
        Err(_) => true,
    }
}

/// Which of the two session closes around the write of a user edit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CloseStage {
    BeforeWrite,
    AfterWrite,
}

/// Writes an admin's edit of `user`. When the edit changes the allowed IP
/// ranges, the user's open sessions are closed, as deleting the user does:
/// once before the write, so a failure to close leaves the edit unsaved and
/// retryable, and again once it is committed, so a login admitted under the
/// old ranges in between is closed too.
///
/// The user's pending-close row is written in the transaction of the edit, so
/// it exists exactly when the edit committed: a failure to write it fails the
/// edit, with nothing saved, and a node that stops after the commit leaves the
/// row for the next process's sweep. The second close then runs, and removes
/// the row when it succeeds. A failure of the second close cannot be retried
/// by the admin (the edit is saved), so the row stays for the expiry sweep and
/// the update succeeds.
///
/// `close` runs the close for a stage; it is a parameter so tests can make a
/// chosen stage fail.
async fn save_user_update<F, Fut>(
    services: &warpgate_core::Services,
    user: User::Model,
    body: &UserDataRequest,
    parsed_ranges: Option<Vec<ipnet::IpNet>>,
    close: F,
) -> Result<User::Model, WarpgateError>
where
    F: Fn(CloseStage) -> Fut,
    Fut: std::future::Future<Output = Result<(), WarpgateError>>,
{
    let user_id = user.id;
    // A repeat of an edit whose follow-up close is still queued (in memory or
    // recorded, or whose record cannot be read) closes now, whether or not
    // the stored ranges already match.
    let close_needed = allowed_ranges_changed(&user.allowed_ip_ranges, parsed_ranges.as_deref())
        || services.user_close_pending(user_id).await;

    let allowed_ip_ranges = match parsed_ranges {
        Some(ranges) => {
            serde_json::to_value(ranges.iter().map(ToString::to_string).collect::<Vec<_>>())
                .map_err(WarpgateError::from)?
        }
        None => serde_json::Value::Null,
    };

    if close_needed {
        close(CloseStage::BeforeWrite).await?;
    }

    let mut model: User::ActiveModel = user.into();

    model.username = Set(body.username.clone());
    model.description = Set(body.description.clone().unwrap_or_default());
    model.credential_policy =
        Set(serde_json::to_value(body.credential_policy.clone()).map_err(WarpgateError::from)?);
    model.rate_limit_bytes_per_second = Set(body.rate_limit_bytes_per_second.map(i64::from));
    model.allowed_ip_ranges = Set(allowed_ip_ranges);

    let txn = services.db.begin().await?;
    let queued = if close_needed {
        Some(PendingUserClose::mark(&txn, user_id).await?)
    } else {
        None
    };
    let user = model.update(&txn).await?;
    txn.commit().await?;

    if let Some(queued) = queued {
        services
            .settle_user_session_close(user_id, queued, close(CloseStage::AfterWrite).await)
            .await;
    }

    Ok(user)
}

/// Deletes the user's records, then closes the sessions. `close` closes the
/// user's own sessions and runs before and after the commit; it is a parameter
/// so tests can make the second run fail.
///
/// The user's pending-close row is written in the transaction of the delete,
/// as for an edit (see [`save_user_update`]). The `UserDeleted` audit event is
/// emitted as soon as the delete has committed, before any session is closed,
/// so a close that fails (or a node that stops during it) cannot lose it.
async fn delete_user_and_close<F, Fut>(
    services: &warpgate_core::Services,
    user: User::Model,
    actor_user_id: Uuid,
    close: F,
) -> Result<(), WarpgateError>
where
    F: Fn(CloseStage) -> Fut,
    Fut: std::future::Future<Output = Result<(), WarpgateError>>,
{
    close(CloseStage::BeforeWrite).await?;

    let (user_id, username) = (user.id, user.username.clone());
    let (admitted, queued) = delete_user_records(&services.db, user).await?;
    AuditEvent::UserDeleted {
        user_id,
        username,
        actor_user_id,
    }
    .emit();
    // A login can land between the close above and the commit; the user's
    // own sessions are closed again now that the delete is final. The user's
    // own close cannot be retried by the admin (the user is gone), so its
    // failure leaves the row for the expiry sweep rather than failing the
    // request. Closing the admitted sessions never fails either: a failure is
    // queued the same way.
    let admitted_result = services.close_admitted_sessions(admitted).await;
    services
        .settle_user_session_close(user_id, queued, close(CloseStage::AfterWrite).await)
        .await;
    admitted_result
}

/// Whether another account already uses this username, compared case-insensitively.
/// `excluding` skips one account so a rename can keep — or re-case — its own name.
async fn username_taken(
    db: &sea_orm::DatabaseConnection,
    username: &str,
    excluding: Option<Uuid>,
) -> Result<bool, WarpgateError> {
    let mut query = User::Entity::find().filter(User::Entity::username_eq_ci(username));
    if let Some(id) = excluding {
        query = query.filter(User::Column::Id.ne(id));
    }
    Ok(query.one(db).await?.is_some())
}

/// Deletes `user` and every row that references it through a foreign key
/// without `ON DELETE CASCADE`, in one transaction, so the delete either
/// succeeds whole or leaves the user untouched.
///
/// Tickets and ticket requests are among those rows: with ticket self-service
/// in use, a user who ever requested a ticket could otherwise never be
/// deleted. The target delete handler clears the same two tables for a target.
/// A ticket request is removed both by its own `user_id` and by the ticket it
/// produced, since `ticket_requests.ticket_id` also references `tickets`.
///
/// The user's tickets are locked before the first read, as a target delete
/// does, and the open sessions they admitted are returned (and recorded for
/// the close sweep) for the caller to close once this has committed. The
/// user's own pending-close row is written in the same transaction; its time is
/// returned with them, for the caller to remove the row once the close
/// succeeded ([`warpgate_core::Services::settle_user_session_close`]).
async fn delete_user_records(
    db: &DatabaseConnection,
    user: User::Model,
) -> Result<(AdmittedSessions, OffsetDateTime), WarpgateError> {
    let txn = db.begin().await?;
    let queued = PendingUserClose::mark(&txn, user.id).await?;
    Ticket::lock_all_for_user(&txn, user.id).await?;

    UserRoleAssignment::Entity::delete_many()
        .filter(UserRoleAssignment::Column::UserId.eq(user.id))
        .exec(&txn)
        .await?;

    UserAdminRoleAssignment::Entity::delete_many()
        .filter(UserAdminRoleAssignment::Column::UserId.eq(user.id))
        .exec(&txn)
        .await?;

    TicketRequest::Entity::delete_many()
        .filter(
            Condition::any()
                .add(TicketRequest::Column::UserId.eq(user.id))
                .add(
                    TicketRequest::Column::TicketId.in_subquery(
                        Ticket::Entity::find()
                            .select_only()
                            .column(Ticket::Column::Id)
                            .filter(Ticket::Column::UserId.eq(user.id))
                            .into_query(),
                    ),
                ),
        )
        .exec(&txn)
        .await?;

    let admitted = TargetSession::open_user_sessions_admitted_by_tickets(
        &txn,
        Ticket::Column::UserId.eq(user.id),
    )
    .await?;
    PendingSessionClose::mark(&txn, &admitted).await?;
    Ticket::Entity::delete_many()
        .filter(Ticket::Column::UserId.eq(user.id))
        .exec(&txn)
        .await?;

    user.delete(&txn).await?;
    txn.commit().await?;
    Ok((AdmittedSessions(admitted), queued))
}

#[derive(ApiResponse)]
enum DeleteUserResponse {
    #[oai(status = 204)]
    Deleted,

    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
#[allow(clippy::large_enum_variant)]
enum UnlinkUserFromLdapResponse {
    #[oai(status = 200)]
    Ok(Json<UserConfig>),

    #[oai(status = 404)]
    NotFound,

    #[oai(status = 400)]
    BadRequest(Json<String>),
}

#[derive(ApiResponse)]
#[allow(clippy::large_enum_variant)]
enum AutoLinkUserToLdapResponse {
    #[oai(status = 200)]
    Ok(Json<UserConfig>),

    #[oai(status = 404)]
    NotFound,

    #[oai(status = 400)]
    BadRequest(Json<String>),
}

pub struct DetailApi;

#[OpenApi]
impl DetailApi {
    #[oai(path = "/users/:id", method = "get", operation_id = "get_user")]
    async fn api_get_user(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<GetUserResponse, WarpgateError> {
        let db = &admin.services().db;

        let Some(user) = User::Entity::find_by_id(id.0).one(db).await? else {
            return Ok(GetUserResponse::NotFound);
        };

        Ok(GetUserResponse::Ok(Json(user.try_into()?)))
    }

    #[oai(
        path = "/users/:id",
        method = "put",
        operation_id = "update_user",
        transform = "guard_user_mutation"
    )]
    async fn api_update_user(
        &self,
        admin: AdminContext,
        req: &Request,
        body: Json<UserDataRequest>,
        id: Path<Uuid>,
    ) -> Result<UpdateUserResponse, WarpgateError> {
        admin.require(AdminPermission::UsersEdit)?;

        let db = &admin.services().db;

        let Some(user) = User::Entity::find_by_id(id.0).one(db).await? else {
            return Ok(UpdateUserResponse::NotFound);
        };

        if body.username.is_empty() {
            return Ok(UpdateUserResponse::BadRequest(invalid_field(
                "username",
                "username is empty",
            )));
        }

        // An account that already has the name may keep it.
        if body.username != user.username && is_reserved_username(&body.username) {
            return Ok(UpdateUserResponse::BadRequest(invalid_field(
                "username",
                RESERVED_USERNAME_MESSAGE,
            )));
        }

        // Excludes this account, so re-casing or keeping one's own name is fine.
        if username_taken(db, &body.username, Some(user.id)).await? {
            return Ok(UpdateUserResponse::BadRequest(invalid_field(
                "username",
                "another user already has this username",
            )));
        }

        let parsed_ranges = match body.allowed_ip_ranges.clone() {
            Some(ranges) => match User::parse_allowed_ip_ranges(ranges) {
                Ok(ranges) => Some(ranges),
                Err(WarpgateError::InvalidNetworkAddress(range)) => {
                    return Ok(UpdateUserResponse::BadRequest(invalid_field(
                        "allowed_ip_ranges",
                        &format!("not a valid IP network: {range}"),
                    )));
                }
                Err(error) => return Err(error),
            },
            None => None,
        };

        // An admin's own session and tokens are re-checked against their
        // ranges on every request, so a change that excludes the address
        // they are using would end their access with this very edit.
        if user.id == admin.auth.user_id()
            && edit_locks_out_caller(
                parsed_ranges.as_deref(),
                get_client_ip_addr(req, admin.services()).await,
            )
        {
            return Ok(UpdateUserResponse::BadRequest(invalid_field(
                "allowed_ip_ranges",
                "these ranges do not include the address this request comes from, \
                 so you would be signed out of your own account; \
                 add your current address or edit the ranges from another account",
            )));
        }

        let services = admin.services();
        let user_id = user.id;
        let user = save_user_update(services, user, &body, parsed_ranges, |_| {
            services.close_sessions(SessionsFilter::User { user_id })
        })
        .await?;

        warpgate_core::rate_limiting::apply_new_rate_limits(
            &admin.services().rate_limiter_registry,
            &admin.services().state,
        )
        .await?;

        Ok(UpdateUserResponse::Ok(Json(user.try_into()?)))
    }

    #[oai(
        path = "/users/:id",
        method = "delete",
        operation_id = "delete_user",
        transform = "guard_user_mutation"
    )]
    async fn api_delete_user(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<DeleteUserResponse, WarpgateError> {
        admin.require(AdminPermission::UsersDelete)?;

        let db = &admin.services().db;

        let Some(user) = User::Entity::find_by_id(id.0).one(db).await? else {
            return Ok(DeleteUserResponse::NotFound);
        };

        let services = admin.services();
        let user_id = user.id;
        delete_user_and_close(services, user, admin.auth.user_id(), |_| {
            services.close_sessions(SessionsFilter::User { user_id })
        })
        .await?;

        Ok(DeleteUserResponse::Deleted)
    }

    #[oai(
        path = "/users/:id/ldap-link/unlink",
        method = "post",
        operation_id = "unlink_user_from_ldap",
        transform = "guard_user_mutation"
    )]
    async fn api_unlink_user_from_ldap(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<UnlinkUserFromLdapResponse, WarpgateError> {
        admin.require(AdminPermission::UsersEdit)?;

        let db = &admin.services().db;

        let Some(user) = User::Entity::find_by_id(id.0).one(db).await? else {
            return Ok(UnlinkUserFromLdapResponse::NotFound);
        };

        if user.ldap_server_id.is_none() {
            return Ok(UnlinkUserFromLdapResponse::BadRequest(bad_request(
                "User is not linked to LDAP",
            )));
        }

        let mut model: User::ActiveModel = user.into();
        model.ldap_server_id = Set(None);
        model.ldap_object_uuid = Set(None);
        let user = model.update(db).await?;

        Ok(UnlinkUserFromLdapResponse::Ok(Json(user.try_into()?)))
    }

    #[oai(
        path = "/users/:id/ldap-link/auto-link",
        method = "post",
        operation_id = "auto_link_user_to_ldap",
        transform = "guard_user_mutation"
    )]
    async fn api_auto_link_user_to_ldap(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<AutoLinkUserToLdapResponse, WarpgateError> {
        use warpgate_db_entities::LdapServer;

        admin.require(AdminPermission::UsersEdit)?;

        let db = &admin.services().db;

        let Some(user) = User::Entity::find_by_id(id.0).one(db).await? else {
            return Ok(AutoLinkUserToLdapResponse::NotFound);
        };

        if user.ldap_server_id.is_some() {
            return Ok(AutoLinkUserToLdapResponse::BadRequest(bad_request(
                "User is already linked to LDAP",
            )));
        }

        let ldap_servers: Vec<LdapServer::Model> = LdapServer::Entity::find()
            .filter(LdapServer::Column::Enabled.eq(true))
            .all(db)
            .await?;

        if ldap_servers.is_empty() {
            return Ok(AutoLinkUserToLdapResponse::BadRequest(bad_request(
                "No enabled LDAP servers configured",
            )));
        }

        let username = &user.username;
        let mut ldap_server_id = None;
        let mut ldap_object_uuid = None;

        for ldap_server in ldap_servers {
            let ldap_config = warpgate_ldap::LdapConfig::try_from(&ldap_server)?;

            match warpgate_ldap::find_user_by_username(&ldap_config, username).await {
                Ok(Some(ldap_user)) => {
                    ldap_server_id = Some(ldap_server.id);
                    ldap_object_uuid = Some(ldap_user.object_uuid);
                    break;
                }
                Ok(None) => (),
                Err(e) => {
                    warn!("Error searching for LDAP user in {}: {e}", ldap_server.name);
                }
            }
        }

        if ldap_server_id.is_none() {
            return Ok(AutoLinkUserToLdapResponse::BadRequest(bad_request(
                format!("No LDAP user found with username: {username}",),
            )));
        }

        let mut model: User::ActiveModel = user.into();
        model.ldap_server_id = Set(ldap_server_id);
        model.ldap_object_uuid = Set(ldap_object_uuid);
        let user = model.update(db).await?;

        Ok(AutoLinkUserToLdapResponse::Ok(Json(user.try_into()?)))
    }
}

// ========== User Role Assignment DTOs ==========

/// Response containing user role assignment with expiry info.
#[derive(Object, Clone, Debug)]
struct UserRoleAssignmentResponse {
    /// Role ID
    id: Uuid,
    /// Role name
    name: String,
    /// Role description
    description: String,
    /// When the role was granted
    granted_at: Option<OffsetDateTime>,
    /// When this role assignment expires (null = permanent)
    expires_at: Option<OffsetDateTime>,
    /// Whether this assignment has expired
    is_expired: bool,
    /// Whether this assignment is currently active (not expired, not revoked)
    is_active: bool,
}

/// Request to add a user role with optional expiry
#[derive(Object, Clone, Debug)]
struct AddUserRoleRequest {
    #[oai(default)]
    expires_at: Option<OffsetDateTime>,
}

/// Request to update user role expiry
#[derive(Object, Clone, Debug)]
struct UpdateUserRoleRequest {
    /// The new expiry timestamp, or null to remove expiry (make permanent)
    expires_at: Option<OffsetDateTime>,
}

#[derive(ApiResponse)]
enum GetUserRolesResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<UserRoleAssignmentResponse>>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum GetUserRoleResponse {
    #[oai(status = 200)]
    Ok(Json<UserRoleAssignmentResponse>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum AddUserRoleResponse {
    #[oai(status = 201)]
    Created(Json<UserRoleAssignmentResponse>),
    #[oai(status = 409)]
    AlreadyExists,
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum DeleteUserRoleResponse {
    #[oai(status = 204)]
    Deleted,
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum UpdateUserRoleResponse {
    #[oai(status = 200)]
    Ok(Json<UserRoleAssignmentResponse>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum GetUserAdminRolesResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<AdminRoleConfig>>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum AddUserAdminRoleResponse {
    #[oai(status = 201)]
    Created,
    #[oai(status = 409)]
    AlreadyExists,
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum DeleteUserAdminRoleResponse {
    #[oai(status = 204)]
    Deleted,
    #[oai(status = 404)]
    NotFound,
}

pub struct RolesApi;

fn build_assignment_response(
    assignment: &UserRoleAssignment::Model,
    role: &Role::Model,
) -> UserRoleAssignmentResponse {
    UserRoleAssignmentResponse {
        id: role.id,
        name: role.name.clone(),
        description: role.description.clone(),
        granted_at: assignment.granted_at,
        expires_at: assignment.expires_at,
        is_expired: assignment.expired(),
        is_active: assignment.active(),
    }
}

#[OpenApi]
impl RolesApi {
    /// Get all role assignments for a user with expiry information
    #[oai(
        path = "/users/:id/roles",
        method = "get",
        operation_id = "get_user_roles"
    )]
    async fn api_get_user_roles(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<GetUserRolesResponse, WarpgateError> {
        let db = &admin.services().db;

        let Some(_user) = User::Entity::find_by_id(*id).one(db).await? else {
            return Ok(GetUserRolesResponse::NotFound);
        };

        let assignments = UserRoleAssignment::Entity::find()
            .filter(UserRoleAssignment::Column::UserId.eq(*id))
            .all(db)
            .await?;

        let mut results = Vec::new();
        for assignment in assignments {
            let Some(role) = Role::Entity::find_by_id(assignment.role_id).one(db).await? else {
                continue;
            };
            results.push(build_assignment_response(&assignment, &role));
        }

        Ok(GetUserRolesResponse::Ok(Json(results)))
    }

    /// Get a single user role assignment with details
    #[oai(
        path = "/users/:id/roles/:role_id",
        method = "get",
        operation_id = "get_user_role"
    )]
    async fn api_get_user_role(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
        role_id: Path<Uuid>,
    ) -> Result<GetUserRoleResponse, WarpgateError> {
        let db = &admin.services().db;

        let Some(assignment) = UserRoleAssignment::Entity::find()
            .filter(UserRoleAssignment::Column::UserId.eq(id.0))
            .filter(UserRoleAssignment::Column::RoleId.eq(role_id.0))
            .one(db)
            .await?
        else {
            return Ok(GetUserRoleResponse::NotFound);
        };

        let Some(role) = Role::Entity::find_by_id(role_id.0).one(db).await? else {
            return Ok(GetUserRoleResponse::NotFound);
        };

        Ok(GetUserRoleResponse::Ok(Json(build_assignment_response(
            &assignment,
            &role,
        ))))
    }

    /// Add a role to a user with optional expiry
    #[oai(
        path = "/users/:id/roles/:role_id",
        method = "post",
        operation_id = "add_user_role",
        transform = "guard_user_mutation"
    )]
    async fn api_add_user_role(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
        role_id: Path<Uuid>,
        body: Json<Option<AddUserRoleRequest>>,
    ) -> Result<AddUserRoleResponse, WarpgateError> {
        admin.require(AdminPermission::AccessRolesAssign)?;

        let db = &admin.services().db;
        let expires_at = body.0.and_then(|b| b.expires_at);

        let Some(grantee) = User::Entity::find_by_id(id.0).one(db).await? else {
            return Ok(AddUserRoleResponse::NotFound);
        };

        let Some(role) = Role::Entity::find_by_id(role_id.0).one(db).await? else {
            return Ok(AddUserRoleResponse::AlreadyExists);
        };

        let assignment =
            UserRoleAssignment::Entity::idempotent_grant(db, id.0, role_id.0, expires_at).await?;

        AuditEvent::AccessRoleGranted {
            grantee_id: grantee.id,
            grantee_username: grantee.username.clone(),
            role_id: role.id,
            role_name: role.name.clone(),
            actor_user_id: admin.auth.user_id(),
            related_access_roles: format_related_ids(&[role.id]),
        }
        .emit();

        Ok(AddUserRoleResponse::Created(Json(
            build_assignment_response(&assignment, &role),
        )))
    }

    /// Remove a role from a user (soft delete - sets revoked_at)
    #[oai(
        path = "/users/:id/roles/:role_id",
        method = "delete",
        operation_id = "delete_user_role",
        transform = "guard_user_mutation"
    )]
    async fn api_delete_user_role(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
        role_id: Path<Uuid>,
    ) -> Result<DeleteUserRoleResponse, WarpgateError> {
        admin.require(AdminPermission::AccessRolesAssign)?;

        let db = &admin.services().db;

        let Some(grantee) = User::Entity::find_by_id(id.0).one(db).await? else {
            return Ok(DeleteUserRoleResponse::NotFound);
        };

        let Some(role) = Role::Entity::find_by_id(role_id.0).one(db).await? else {
            return Ok(DeleteUserRoleResponse::NotFound);
        };

        let Some(model) = UserRoleAssignment::Entity::find()
            .filter(UserRoleAssignment::Column::UserId.eq(id.0))
            .filter(UserRoleAssignment::Column::RoleId.eq(role_id.0))
            .one(db)
            .await?
        else {
            return Ok(DeleteUserRoleResponse::NotFound);
        };

        // Soft delete - set revoked_at
        let now = OffsetDateTime::now_utc();
        let mut model: UserRoleAssignment::ActiveModel = model.into();
        model.revoked_at = Set(Some(now));
        model.update(db).await?;

        AuditEvent::AccessRoleRevoked {
            grantee_id: grantee.id,
            grantee_username: grantee.username.clone(),
            role_id: role.id,
            role_name: role.name.clone(),
            actor_user_id: admin.auth.user_id(),
            related_access_roles: format_related_ids(&[role.id]),
        }
        .emit();

        admin
            .services()
            .close_sessions_no_longer_authorised(AccessChange::Users(vec![grantee.id]))
            .await?;

        Ok(DeleteUserRoleResponse::Deleted)
    }

    #[oai(
        path = "/users/:id/roles/:role_id",
        method = "put",
        operation_id = "update_user_role",
        transform = "guard_user_mutation"
    )]
    async fn api_update_user_role(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
        role_id: Path<Uuid>,
        body: Json<UpdateUserRoleRequest>,
    ) -> Result<UpdateUserRoleResponse, WarpgateError> {
        admin.require(AdminPermission::AccessRolesAssign)?;

        let db = &admin.services().db;

        let Some(role) = Role::Entity::find_by_id(role_id.0).one(db).await? else {
            return Ok(UpdateUserRoleResponse::NotFound);
        };

        let Some(assignment) = UserRoleAssignment::Entity::find()
            .filter(UserRoleAssignment::Column::UserId.eq(id.0))
            .filter(UserRoleAssignment::Column::RoleId.eq(role_id.0))
            .one(db)
            .await?
        else {
            return Ok(UpdateUserRoleResponse::NotFound);
        };

        let mut model: UserRoleAssignment::ActiveModel = assignment.into();
        model.expires_at = Set(body.expires_at);
        // If renewing an expired role, clear revoked_at
        model.revoked_at = Set(None);
        let updated = model.update(db).await?;

        // A new expiry may already have passed.
        admin
            .services()
            .close_sessions_no_longer_authorised(AccessChange::Users(vec![id.0]))
            .await?;

        Ok(UpdateUserRoleResponse::Ok(Json(build_assignment_response(
            &updated, &role,
        ))))
    }

    #[oai(
        path = "/users/:id/admin-roles",
        method = "get",
        operation_id = "get_user_admin_roles"
    )]
    async fn api_get_user_admin_roles(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<GetUserAdminRolesResponse, WarpgateError> {
        let db = &admin.services().db;

        let Some((_, roles)) = User::Entity::find_by_id(*id)
            .find_with_related(AdminRole::Entity)
            .all(db)
            .await
            .map(|x| x.into_iter().next())
            .map_err(WarpgateError::from)?
        else {
            return Ok(GetUserAdminRolesResponse::NotFound);
        };

        Ok(GetUserAdminRolesResponse::Ok(Json(
            roles.into_iter().map(Into::into).collect(),
        )))
    }

    #[oai(
        path = "/users/:id/admin-roles/:role_id",
        method = "post",
        operation_id = "add_user_admin_role",
        transform = "guard_user_mutation"
    )]
    async fn api_add_user_admin_role(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
        role_id: Path<Uuid>,
    ) -> Result<AddUserAdminRoleResponse, WarpgateError> {
        admin.require(AdminPermission::AdminRolesManage)?;

        let db = &admin.services().db;

        let Some(grantee) = User::Entity::find_by_id(id.0).one(db).await? else {
            return Ok(AddUserAdminRoleResponse::NotFound);
        };

        let Some(role) = AdminRole::Entity::find_by_id(role_id.0).one(db).await? else {
            return Ok(AddUserAdminRoleResponse::NotFound);
        };

        if !warpgate_db_entities::UserAdminRoleAssignment::Entity::find()
            .filter(warpgate_db_entities::UserAdminRoleAssignment::Column::UserId.eq(id.0))
            .filter(
                warpgate_db_entities::UserAdminRoleAssignment::Column::AdminRoleId.eq(role_id.0),
            )
            .all(db)
            .await
            .map_err(WarpgateError::from)?
            .is_empty()
        {
            return Ok(AddUserAdminRoleResponse::AlreadyExists);
        }

        let values = warpgate_db_entities::UserAdminRoleAssignment::ActiveModel {
            user_id: Set(id.0),
            admin_role_id: Set(role_id.0),
        };

        values.insert(db).await.map_err(WarpgateError::from)?;

        AuditEvent::AdminRoleGranted {
            grantee_id: grantee.id,
            grantee_username: grantee.username.clone(),
            admin_role_id: role.id,
            admin_role_name: role.name.clone(),
            actor_user_id: admin.auth.user_id(),
            related_admin_roles: format_related_ids(&[role.id]),
        }
        .emit();

        Ok(AddUserAdminRoleResponse::Created)
    }

    #[oai(
        path = "/users/:id/admin-roles/:role_id",
        method = "delete",
        operation_id = "delete_user_admin_role",
        transform = "guard_user_mutation"
    )]
    async fn api_delete_user_admin_role(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
        role_id: Path<Uuid>,
    ) -> Result<DeleteUserAdminRoleResponse, WarpgateError> {
        admin.require(AdminPermission::AdminRolesManage)?;

        let db = &admin.services().db;

        let Some(grantee) = User::Entity::find_by_id(id.0).one(db).await? else {
            return Ok(DeleteUserAdminRoleResponse::NotFound);
        };

        let Some(role) = AdminRole::Entity::find_by_id(role_id.0).one(db).await? else {
            return Ok(DeleteUserAdminRoleResponse::NotFound);
        };

        let Some(model) = warpgate_db_entities::UserAdminRoleAssignment::Entity::find()
            .filter(warpgate_db_entities::UserAdminRoleAssignment::Column::UserId.eq(id.0))
            .filter(
                warpgate_db_entities::UserAdminRoleAssignment::Column::AdminRoleId.eq(role_id.0),
            )
            .one(db)
            .await
            .map_err(WarpgateError::from)?
        else {
            return Ok(DeleteUserAdminRoleResponse::NotFound);
        };

        model.delete(db).await.map_err(WarpgateError::from)?;

        AuditEvent::AdminRoleRevoked {
            grantee_id: grantee.id,
            grantee_username: grantee.username.clone(),
            admin_role_id: role.id,
            admin_role_name: role.name.clone(),
            actor_user_id: admin.auth.user_id(),
            related_admin_roles: format_related_ids(&[role.id]),
        }
        .emit();

        Ok(DeleteUserAdminRoleResponse::Deleted)
    }
}

/// The name the public-target bypass's throwaway session is served under.
const RESERVED_USERNAME: &str = "<public>";
const RESERVED_USERNAME_MESSAGE: &str = "this username is reserved";

fn is_reserved_username(username: &str) -> bool {
    username.eq_ignore_ascii_case(RESERVED_USERNAME)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;

    use sea_orm::ConnectionTrait as _;
    use sea_orm::Database;
    use tokio::sync::Mutex;
    use warpgate_common::{GlobalParams, UserSessionId, WarpgateConfig, WarpgateConfigStore};
    use warpgate_core::cluster::Cluster;
    use warpgate_core::login_protection::LoginProtectionService;
    use warpgate_core::rate_limiting::RateLimiterRegistry;
    use warpgate_core::recordings::SessionRecordings;
    use warpgate_core::{
        ApprovalRequestSink, AuthStateStore, DatabaseConfigProvider, SecretBackendRegistry,
        Services, State,
    };
    use warpgate_db_entities::Parameters::{ConfigMigrationValues, set_config_migration_values};
    use warpgate_db_entities::PendingUserClose;
    use warpgate_db_entities::Target::{self, TargetKind};
    use warpgate_db_entities::TicketRequest::TicketRequestStatus;
    use warpgate_db_migrations::migrate_database;

    use super::*;

    #[test]
    fn the_public_session_name_is_reserved() {
        assert!(is_reserved_username("<public>"));
        assert!(is_reserved_username("<PUBLIC>"));
        assert!(!is_reserved_username("public"));
        assert!(!is_reserved_username("alice"));
        assert!(!is_reserved_username(""));
    }

    #[test]
    fn own_range_edit_must_keep_the_callers_address() {
        let ip = |s: &str| Some(s.parse::<std::net::IpAddr>().unwrap());
        let nets =
            |v: &[&str]| -> Vec<ipnet::IpNet> { v.iter().map(|x| x.parse().unwrap()).collect() };

        // No restriction, or an empty list.
        assert!(!edit_locks_out_caller(None, ip("192.0.2.5")));
        assert!(!edit_locks_out_caller(Some(&[]), ip("192.0.2.5")));
        // Range that includes the caller.
        assert!(!edit_locks_out_caller(
            Some(&nets(&["192.0.2.0/24"])),
            ip("192.0.2.5")
        ));
        assert!(!edit_locks_out_caller(
            Some(&nets(&["10.0.0.0/8", "192.0.2.5/32"])),
            ip("192.0.2.5")
        ));
        // Range that excludes the caller.
        assert!(edit_locks_out_caller(
            Some(&nets(&["10.0.0.0/8"])),
            ip("192.0.2.5")
        ));
        assert!(edit_locks_out_caller(
            Some(&nets(&["2001:db8::/32"])),
            ip("192.0.2.5")
        ));
        // IPv4-mapped IPv6 address is matched as IPv4.
        assert!(!edit_locks_out_caller(
            Some(&nets(&["192.0.2.0/24"])),
            ip("::ffff:192.0.2.5")
        ));
        // Unknown caller address cannot be judged.
        assert!(!edit_locks_out_caller(Some(&nets(&["10.0.0.0/8"])), None));
    }

    async fn setup_db() -> DatabaseConnection {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        db
    }

    async fn insert_user(db: &DatabaseConnection, username: &str) -> User::Model {
        User::ActiveModel {
            id: Set(Uuid::new_v4()),
            username: Set(username.into()),
            description: Set(String::new()),
            credential_policy: Set(serde_json::json!({})),
            rate_limit_bytes_per_second: Set(None),
            ldap_server_id: Set(None),
            ldap_object_uuid: Set(None),
            allowed_ip_ranges: Set(serde_json::Value::Null),
        }
        .insert(db)
        .await
        .unwrap()
    }

    async fn insert_target(db: &DatabaseConnection) -> Uuid {
        let id = Uuid::new_v4();
        Target::ActiveModel {
            id: Set(id),
            name: Set("web".into()),
            description: Set(String::new()),
            kind: Set(TargetKind::Http),
            options: Set(serde_json::json!({})),
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

    async fn insert_ticket(db: &DatabaseConnection, user_id: Uuid, target_id: Uuid) -> Uuid {
        let id = Uuid::new_v4();
        Ticket::ActiveModel {
            id: Set(id),
            secret_hash: Set("not-a-real-hash".into()),
            user_id: Set(user_id),
            description: Set(String::new()),
            target_id: Set(target_id),
            uses_left: Set(None),
            self_service: Set(true),
            expiry: Set(None),
            created: Set(OffsetDateTime::now_utc()),
        }
        .insert(db)
        .await
        .unwrap();
        id
    }

    async fn insert_request(
        db: &DatabaseConnection,
        user_id: Uuid,
        target_id: Uuid,
        status: TicketRequestStatus,
        ticket_id: Option<Uuid>,
        resolved_by_user_id: Option<Uuid>,
    ) -> Uuid {
        let id = Uuid::new_v4();
        TicketRequest::ActiveModel {
            id: Set(id),
            user_id: Set(user_id),
            target_id: Set(target_id),
            requested_duration_seconds: Set(None),
            description: Set(String::new()),
            status: Set(status),
            resolved_by_user_id: Set(resolved_by_user_id),
            ticket_id: Set(ticket_id),
            created: Set(OffsetDateTime::now_utc()),
            resolved_at: Set(None),
            deny_reason: Set(None),
        }
        .insert(db)
        .await
        .unwrap();
        id
    }

    /// A user who has used ticket self-service (an approved request with its
    /// ticket, a pending one, a denied one) can be deleted, and the delete
    /// takes exactly that user's tickets and ticket requests with it.
    #[tokio::test]
    async fn deleting_a_user_removes_their_tickets_and_ticket_requests() {
        let db = setup_db().await;
        let target_id = insert_target(&db).await;
        let alice = insert_user(&db, "alice").await;
        let bob = insert_user(&db, "bob").await;

        let alice_ticket = insert_ticket(&db, alice.id, target_id).await;
        let mut alice_requests = vec![
            insert_request(
                &db,
                alice.id,
                target_id,
                TicketRequestStatus::Approved,
                Some(alice_ticket),
                None,
            )
            .await,
        ];
        for status in [TicketRequestStatus::Pending, TicketRequestStatus::Denied] {
            alice_requests.push(insert_request(&db, alice.id, target_id, status, None, None).await);
        }

        // Bob's rows survive, including a request that alice resolved:
        // `resolved_by_user_id` is a record, not a reference that blocks.
        let bob_ticket = insert_ticket(&db, bob.id, target_id).await;
        let bob_request = insert_request(
            &db,
            bob.id,
            target_id,
            TicketRequestStatus::Approved,
            Some(bob_ticket),
            Some(alice.id),
        )
        .await;

        // A request that points at one of alice's tickets goes too, whoever
        // filed it: `ticket_requests.ticket_id` references `tickets`.
        alice_requests.push(
            insert_request(
                &db,
                bob.id,
                target_id,
                TicketRequestStatus::Approved,
                Some(alice_ticket),
                None,
            )
            .await,
        );

        let alice_id = alice.id;
        let _admitted = delete_user_records(&db, alice).await.unwrap();

        assert!(
            User::Entity::find_by_id(alice_id)
                .one(&db)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            Ticket::Entity::find_by_id(alice_ticket)
                .one(&db)
                .await
                .unwrap()
                .is_none()
        );
        for id in alice_requests {
            assert!(
                TicketRequest::Entity::find_by_id(id)
                    .one(&db)
                    .await
                    .unwrap()
                    .is_none()
            );
        }

        assert!(
            User::Entity::find_by_id(bob.id)
                .one(&db)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            Ticket::Entity::find_by_id(bob_ticket)
                .one(&db)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            TicketRequest::Entity::find_by_id(bob_request)
                .one(&db)
                .await
                .unwrap()
                .is_some()
        );
    }

    async fn open_session_under(
        db: &DatabaseConnection,
        target_id: Uuid,
        ticket_id: Uuid,
    ) -> warpgate_common::UserSessionId {
        let session_id = warpgate_common::UserSessionId(Uuid::new_v4());
        warpgate_db_entities::UserSession::ActiveModel {
            id: Set(session_id),
            username: Set(Some("alice".into())),
            user_id: Set(None),
            remote_address: Set("127.0.0.1:22".into()),
            started: Set(OffsetDateTime::now_utc()),
            ended: Set(None),
            protocol: Set("HTTP".into()),
            node_id: Set(None),
            auth_state_node_id: Set(None),
        }
        .insert(db)
        .await
        .unwrap();
        TargetSession::ActiveModel {
            id: Set(warpgate_common::TargetSessionId(Uuid::new_v4())),
            user_session_id: Set(session_id),
            target_snapshot: Set(r#"{"name":"web"}"#.into()),
            target_id: Set(target_id),
            started: Set(OffsetDateTime::now_utc()),
            ended: Set(None),
            ticket_id: Set(Some(ticket_id)),
            node_id: Set(None),
        }
        .insert(db)
        .await
        .unwrap();
        session_id
    }

    /// Deleting a user removes their tickets, and with them the only record of
    /// which open sessions those tickets admitted, so the delete must hand
    /// those sessions back to be closed (and record them for the sweep).
    /// Another user's sessions are not touched.
    #[tokio::test]
    async fn deleting_a_user_returns_the_sessions_their_tickets_admitted() {
        let db = setup_db().await;
        let target_id = insert_target(&db).await;
        let alice = insert_user(&db, "alice").await;
        let bob = insert_user(&db, "bob").await;

        let alice_ticket = insert_ticket(&db, alice.id, target_id).await;
        let bob_ticket = insert_ticket(&db, bob.id, target_id).await;
        let alice_session = open_session_under(&db, target_id, alice_ticket).await;
        let bob_session = open_session_under(&db, target_id, bob_ticket).await;

        let (admitted, _) = delete_user_records(&db, alice).await.unwrap();

        assert_eq!(admitted.0, vec![alice_session]);
        assert_eq!(
            PendingSessionClose::pending(&db).await.unwrap(),
            vec![alice_session],
        );
        assert!(!admitted.0.contains(&bob_session));
    }

    /// A session of the user that is opened after the first close and before
    /// the delete commits is still matched by the user filter once the delete
    /// has committed, so closing again after the commit ends it.
    #[tokio::test]
    async fn a_session_opened_before_the_delete_commits_is_closed_by_the_second_close() {
        let db = setup_db().await;
        let alice = insert_user(&db, "alice").await;
        let alice_id = alice.id;

        let session_id = warpgate_common::UserSessionId(Uuid::new_v4());
        warpgate_db_entities::UserSession::ActiveModel {
            id: Set(session_id),
            username: Set(Some("alice".into())),
            user_id: Set(Some(alice_id)),
            remote_address: Set("127.0.0.1:22".into()),
            started: Set(OffsetDateTime::now_utc()),
            ended: Set(None),
            protocol: Set("HTTP".into()),
            node_id: Set(None),
            auth_state_node_id: Set(None),
        }
        .insert(&db)
        .await
        .unwrap();

        delete_user_records(&db, alice).await.unwrap();
        SessionsFilter::User { user_id: alice_id }
            .revoke(&db)
            .await
            .unwrap();

        let session = warpgate_db_entities::UserSession::Entity::find_by_id(session_id)
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert!(session.ended.is_some());
    }

    /// The services a node runs with, over `db`.
    async fn services(db: &DatabaseConnection) -> Services {
        capture_audit_events();
        let params = GlobalParams::new(PathBuf::from("/warpgate.yaml"), false).unwrap();
        let rate_limiter_registry = Arc::new(Mutex::new(RateLimiterRegistry::new(db.clone())));
        let cluster = Arc::new(Cluster::new(db.clone(), 0).await.unwrap());
        Services {
            db: db.clone(),
            recordings: Arc::new(SessionRecordings::new(db.clone(), &params)),
            config: Arc::new(Mutex::new(WarpgateConfig {
                store: WarpgateConfigStore::default(),
            })),
            state: State::new(db, &rate_limiter_registry, cluster.node_id),
            cluster: cluster.clone(),
            rate_limiter_registry,
            config_provider: Arc::new(DatabaseConfigProvider::new(db).into()),
            auth_state_store: Arc::new(Mutex::new(AuthStateStore::new(ApprovalRequestSink {
                db: db.clone(),
                cluster: cluster.clone(),
            }))),
            admin_token: Arc::new(None),
            login_protection: Arc::new(LoginProtectionService::new(db.clone()).await.unwrap()),
            global_params: Arc::new(params),
            listener_status: Default::default(),
            secret_backends: Arc::new(SecretBackendRegistry::new(db.clone())),
            live_streams: Default::default(),
            pending_revocations: Default::default(),
        }
    }

    async fn open_session_of(db: &DatabaseConnection, user: &User::Model) -> UserSessionId {
        let session_id = UserSessionId(Uuid::new_v4());
        warpgate_db_entities::UserSession::ActiveModel {
            id: Set(session_id),
            username: Set(Some(user.username.clone())),
            user_id: Set(Some(user.id)),
            remote_address: Set("127.0.0.1:22".into()),
            started: Set(OffsetDateTime::now_utc()),
            ended: Set(None),
            protocol: Set("HTTP".into()),
            node_id: Set(None),
            auth_state_node_id: Set(None),
        }
        .insert(db)
        .await
        .unwrap();
        session_id
    }

    async fn session_ended(db: &DatabaseConnection, id: UserSessionId) -> bool {
        warpgate_db_entities::UserSession::Entity::find_by_id(id)
            .one(db)
            .await
            .unwrap()
            .unwrap()
            .ended
            .is_some()
    }

    fn edit(username: &str, ranges: Option<&[&str]>) -> UserDataRequest {
        UserDataRequest {
            username: username.into(),
            credential_policy: None,
            description: None,
            rate_limit_bytes_per_second: None,
            allowed_ip_ranges: ranges.map(|r| r.iter().map(ToString::to_string).collect()),
        }
    }

    async fn save(
        services: &Services,
        user: User::Model,
        body: &UserDataRequest,
    ) -> Result<User::Model, WarpgateError> {
        let ranges = match body.allowed_ip_ranges.clone() {
            Some(ranges) => Some(User::parse_allowed_ip_ranges(ranges)?),
            None => None,
        };
        let user_id = user.id;
        save_user_update(services, user, body, ranges, |_| {
            services.close_sessions(SessionsFilter::User { user_id })
        })
        .await
    }

    /// Like `save`, but the close at `failing` fails; the stages reached are
    /// recorded in order. A failing after-write close first opens a session
    /// for the user, as a login landing between the two closes would, and
    /// returns its id.
    async fn save_failing_close(
        services: &Services,
        user: User::Model,
        body: &UserDataRequest,
        failing: CloseStage,
    ) -> (
        Result<User::Model, WarpgateError>,
        Vec<CloseStage>,
        Option<UserSessionId>,
    ) {
        let ranges =
            Some(User::parse_allowed_ip_ranges(body.allowed_ip_ranges.clone().unwrap()).unwrap());
        let user_id = user.id;
        let stages = std::sync::Mutex::new(vec![]);
        let late = std::sync::Mutex::new(None);
        let (db, late_user) = (services.db.clone(), user.clone());
        let result = save_user_update(services, user, body, ranges, |stage| {
            stages.lock().unwrap().push(stage);
            let fail = stage == failing;
            let (db, late_user, late) = (&db, &late_user, &late);
            async move {
                if fail {
                    if stage == CloseStage::AfterWrite {
                        *late.lock().unwrap() = Some(open_session_of(db, late_user).await);
                    }
                    return Err(WarpgateError::InvalidNetworkAddress("injected".into()));
                }
                services
                    .close_sessions(SessionsFilter::User { user_id })
                    .await
            }
        })
        .await;
        (
            result,
            stages.into_inner().unwrap(),
            late.into_inner().unwrap(),
        )
    }

    #[test]
    fn only_a_real_change_of_the_ranges_counts_as_a_change() {
        let nets =
            |v: &[&str]| -> Vec<ipnet::IpNet> { v.iter().map(|x| x.parse().unwrap()).collect() };
        let stored = |v: &[&str]| serde_json::json!(v);
        let null = serde_json::Value::Null;

        // Same list, in any order, with repeats, or with host bits set.
        assert!(!allowed_ranges_changed(
            &stored(&["10.0.0.0/8", "192.0.2.0/24"]),
            Some(&nets(&["10.0.0.0/8", "192.0.2.0/24"])),
        ));
        assert!(!allowed_ranges_changed(
            &stored(&["10.0.0.0/8", "192.0.2.0/24"]),
            Some(&nets(&["192.0.2.0/24", "10.0.0.0/8", "10.0.0.0/8"])),
        ));
        assert!(!allowed_ranges_changed(
            &stored(&["192.0.2.0/24"]),
            Some(&nets(&["192.0.2.7/24"])),
        ));
        // Unset and empty both mean no restriction.
        assert!(!allowed_ranges_changed(&null, None));
        assert!(!allowed_ranges_changed(&null, Some(&[])));
        assert!(!allowed_ranges_changed(&stored(&[]), None));

        // Anything that changes who is admitted.
        assert!(allowed_ranges_changed(&null, Some(&nets(&["10.0.0.0/8"]))));
        assert!(allowed_ranges_changed(&stored(&["10.0.0.0/8"]), None));
        assert!(allowed_ranges_changed(&stored(&["10.0.0.0/8"]), Some(&[])));
        assert!(allowed_ranges_changed(
            &stored(&["10.0.0.0/8"]),
            Some(&nets(&["10.0.0.0/16"])),
        ));
        assert!(allowed_ranges_changed(
            &stored(&["10.0.0.0/8"]),
            Some(&nets(&["10.0.0.0/8", "192.0.2.0/24"])),
        ));
        assert!(allowed_ranges_changed(
            &stored(&["10.0.0.0/8", "192.0.2.0/24"]),
            Some(&nets(&["10.0.0.0/8"])),
        ));
        // A stored value that cannot be read is replaced, so it counts.
        assert!(allowed_ranges_changed(
            &serde_json::json!("garbage"),
            Some(&nets(&["10.0.0.0/8"])),
        ));
        assert!(allowed_ranges_changed(&stored(&["not a network"]), None));
    }

    /// An edit that changes the allowed ranges ends the user's open sessions,
    /// whichever way the ranges change, and no one else's.
    #[tokio::test]
    async fn changing_a_users_allowed_ranges_closes_their_sessions() {
        let db = setup_db().await;
        let services = services(&db).await;
        let alice = insert_user(&db, "alice").await;
        let bob = insert_user(&db, "bob").await;

        let mut alice = alice;
        for (stored_before, ranges) in [
            // Restricting a user who had no restriction.
            (None, Some(&["10.0.0.0/8"][..])),
            // Narrowing, widening and replacing.
            (Some(&["10.0.0.0/8"][..]), Some(&["10.1.0.0/16"][..])),
            (
                Some(&["10.1.0.0/16"][..]),
                Some(&["10.0.0.0/8", "192.0.2.0/24"][..]),
            ),
            (
                Some(&["10.0.0.0/8", "192.0.2.0/24"][..]),
                Some(&["198.51.100.0/24"][..]),
            ),
            // Lifting the restriction.
            (Some(&["198.51.100.0/24"][..]), None),
        ] {
            let alice_session = open_session_of(&db, &alice).await;
            let bob_session = open_session_of(&db, &bob).await;

            let saved = save(&services, alice.clone(), &edit("alice", ranges))
                .await
                .unwrap();

            assert!(
                session_ended(&db, alice_session).await,
                "{stored_before:?} -> {ranges:?} left the user's session open"
            );
            assert!(
                !session_ended(&db, bob_session).await,
                "{stored_before:?} -> {ranges:?} closed another user's session"
            );
            match ranges {
                Some(ranges) => assert_eq!(saved.allowed_ip_ranges, serde_json::json!(ranges)),
                None => assert!(saved.allowed_ip_ranges.is_null()),
            }
            // The close succeeded, so the row written with the edit is gone.
            assert!(PendingUserClose::pending(&db).await.unwrap().is_empty());
            alice = saved;
        }
    }

    /// An edit that leaves the allowed ranges as they are keeps the user's
    /// sessions, whatever else it changes.
    #[tokio::test]
    async fn an_update_that_keeps_the_allowed_ranges_leaves_sessions_open() {
        let db = setup_db().await;
        let services = services(&db).await;
        let alice = insert_user(&db, "alice").await;
        let alice = save(
            &services,
            alice,
            &edit("alice", Some(&["10.0.0.0/8", "192.0.2.0/24"])),
        )
        .await
        .unwrap();
        let session = open_session_of(&db, &alice).await;

        // The same ranges, with other fields changed.
        let mut body = edit("alice-renamed", Some(&["10.0.0.0/8", "192.0.2.0/24"]));
        body.description = Some("renamed".into());
        body.rate_limit_bytes_per_second = Some(1000);
        let alice = save(&services, alice, &body).await.unwrap();
        assert_eq!(alice.username, "alice-renamed");
        assert!(!session_ended(&db, session).await);

        // The same ranges listed in another order.
        let alice = save(
            &services,
            alice,
            &edit("alice-renamed", Some(&["192.0.2.0/24", "10.0.0.0/8"])),
        )
        .await
        .unwrap();
        assert!(!session_ended(&db, session).await);

        // A user with no restriction who stays unrestricted.
        let bob = insert_user(&db, "bob").await;
        let bob_session = open_session_of(&db, &bob).await;
        save(&services, bob, &edit("bob", None)).await.unwrap();
        assert!(!session_ended(&db, bob_session).await);

        // And the first change after all that still closes it.
        save(&services, alice, &edit("alice-renamed", None))
            .await
            .unwrap();
        assert!(session_ended(&db, session).await);
    }

    /// A failing close before the write aborts the edit: nothing is written,
    /// the second close is never attempted, no row is left, and the sessions
    /// stay for a retry.
    #[tokio::test]
    async fn a_failing_close_before_the_write_aborts_the_update() {
        let db = setup_db().await;
        let services = services(&db).await;
        let alice = insert_user(&db, "alice").await;
        let session = open_session_of(&db, &alice).await;

        let (result, stages, _) = save_failing_close(
            &services,
            alice.clone(),
            &edit("alice", Some(&["10.0.0.0/8"])),
            CloseStage::BeforeWrite,
        )
        .await;

        assert!(result.is_err());
        assert_eq!(stages, vec![CloseStage::BeforeWrite]);
        let stored = User::Entity::find_by_id(alice.id)
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert!(stored.allowed_ip_ranges.is_null());
        assert!(!session_ended(&db, session).await);
        assert!(PendingUserClose::pending(&db).await.unwrap().is_empty());
    }

    /// A failing close after the write does not fail the edit: it is saved,
    /// the row written with it stays for the sweep, and the sweep closes every
    /// open session of the user.
    #[tokio::test]
    async fn a_failing_close_after_the_write_leaves_the_row_and_the_update_succeeds() {
        let db = setup_db().await;
        let services = services(&db).await;
        let alice = insert_user(&db, "alice").await;
        let bob = insert_user(&db, "bob").await;
        let bob_session = open_session_of(&db, &bob).await;

        let (result, stages, late) = save_failing_close(
            &services,
            alice.clone(),
            &edit("alice", Some(&["10.0.0.0/8"])),
            CloseStage::AfterWrite,
        )
        .await;

        let saved = result.unwrap();
        assert_eq!(
            stages,
            vec![CloseStage::BeforeWrite, CloseStage::AfterWrite]
        );
        assert_eq!(saved.allowed_ip_ranges, serde_json::json!(["10.0.0.0/8"]));
        // The session that landed between the two closes is covered too.
        let session = late.unwrap();
        assert_eq!(
            PendingUserClose::pending(&db).await.unwrap(),
            vec![alice.id]
        );
        assert!(!session_ended(&db, session).await);

        // The first sweep closes the session but keeps the row for one more
        // sweep, in case a session still opening was missed.
        services.retry_pending_revocations().await;
        assert!(session_ended(&db, session).await);
        assert!(!session_ended(&db, bob_session).await);
        assert_eq!(
            PendingUserClose::pending(&db).await.unwrap(),
            vec![alice.id]
        );
        age_pending_rows(&db).await;
        services.retry_pending_revocations().await;
        assert!(PendingUserClose::pending(&db).await.unwrap().is_empty());
    }

    /// Pushes the queue rows back in time, as if written long ago.
    async fn age_pending_rows(db: &DatabaseConnection) {
        PendingUserClose::Entity::update_many()
            .col_expr(
                PendingUserClose::Column::Queued,
                sea_orm::sea_query::Expr::value(
                    OffsetDateTime::now_utc() - time::Duration::hours(1),
                ),
            )
            .exec(db)
            .await
            .unwrap();
    }

    /// The row is written in the transaction of the edit: when it cannot be
    /// written the edit fails with it and nothing is saved, not even the
    /// fields that have nothing to do with the close.
    #[tokio::test]
    async fn an_update_whose_row_cannot_be_written_is_not_saved() {
        let db = setup_db().await;
        let services = services(&db).await;
        let alice = insert_user(&db, "alice").await;
        db.execute_unprepared("DROP TABLE pending_user_closes")
            .await
            .unwrap();

        let (result, stages, _) = save_failing_close(
            &services,
            alice.clone(),
            &edit("alice-renamed", Some(&["10.0.0.0/8"])),
            CloseStage::AfterWrite,
        )
        .await;

        assert!(
            matches!(result, Err(WarpgateError::DatabaseError(_))),
            "expected the database error of the row write"
        );
        // The second close is never reached: there is no committed edit to close for.
        assert_eq!(stages, vec![CloseStage::BeforeWrite]);
        let stored = User::Entity::find_by_id(alice.id)
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.username, "alice");
        assert!(stored.allowed_ip_ranges.is_null());
    }

    /// The same for a delete: when the row cannot be written, the user is not
    /// deleted, and nothing is audited as deleted.
    #[tokio::test]
    async fn a_delete_whose_row_cannot_be_written_deletes_nothing() {
        let db = setup_db().await;
        let services = services(&db).await;
        let alice = insert_user(&db, "alice").await;
        db.execute_unprepared("DROP TABLE pending_user_closes")
            .await
            .unwrap();

        let result = delete_user_and_close(&services, alice.clone(), Uuid::new_v4(), |_| async {
            Ok(())
        })
        .await;

        assert!(
            matches!(result, Err(WarpgateError::DatabaseError(_))),
            "expected the database error of the row write"
        );
        assert!(
            User::Entity::find_by_id(alice.id)
                .one(&db)
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(user_deleted_events(alice.id), 0);
    }

    /// A queue that cannot be read counts as pending, so an edit that leaves
    /// the ranges as they are still closes the user's sessions first. It cannot
    /// then record the close, so it fails and saves nothing.
    #[tokio::test]
    async fn an_unreadable_queue_counts_as_pending() {
        let db = setup_db().await;
        let services = services(&db).await;
        let alice = insert_user(&db, "alice").await;
        let session = open_session_of(&db, &alice).await;
        assert!(!services.user_close_pending(alice.id).await);

        db.execute_unprepared("DROP TABLE pending_user_closes")
            .await
            .unwrap();
        assert!(services.user_close_pending(alice.id).await);

        let result = save(&services, alice.clone(), &edit("alice-renamed", None)).await;
        assert!(matches!(result, Err(WarpgateError::DatabaseError(_))));
        assert!(session_ended(&db, session).await);
        let stored = User::Entity::find_by_id(alice.id)
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.username, "alice");
    }

    /// A restart loses everything in memory; the row written with the edit
    /// still lets the next process's sweep end the user's session.
    #[tokio::test]
    async fn a_recorded_row_survives_a_restart() {
        let db = setup_db().await;
        let before = services(&db).await;
        let alice = insert_user(&db, "alice").await;
        let session = open_session_of(&db, &alice).await;
        PendingUserClose::mark(&db, alice.id).await.unwrap();
        drop(before);

        let after = services(&db).await;
        after.retry_pending_revocations().await;
        assert!(session_ended(&db, session).await);
    }

    /// The edit commits, its close fails, and the node restarts: the next
    /// process (nothing in memory) still has the row, so a repeat of the edit
    /// would close first and its sweep closes every open session of the user.
    #[tokio::test]
    async fn a_failed_close_is_retried_by_the_next_process() {
        let db = setup_db().await;
        let before = services(&db).await;
        let alice = insert_user(&db, "alice").await;
        let early = open_session_of(&db, &alice).await;

        let (result, _, late) = save_failing_close(
            &before,
            alice.clone(),
            &edit("alice", Some(&["10.0.0.0/8"])),
            CloseStage::AfterWrite,
        )
        .await;
        result.unwrap();
        let late = late.unwrap();
        drop(before);

        let after = services(&db).await;
        assert!(after.user_close_pending(alice.id).await);
        after.retry_pending_revocations().await;
        assert!(session_ended(&db, early).await);
        assert!(session_ended(&db, late).await);
    }

    /// The node stops after the edit committed and before its close returned,
    /// so nothing after the commit ran: the row written with the edit is all
    /// the next process has, and its sweep ends the session.
    #[tokio::test]
    async fn an_update_cut_short_after_the_commit_is_closed_by_the_next_process() {
        let db = setup_db().await;
        let before = services(&db).await;
        let alice = insert_user(&db, "alice").await;
        let session = open_session_of(&db, &alice).await;
        let body = edit("alice", Some(&["10.0.0.0/8"]));
        let ranges =
            Some(User::parse_allowed_ip_ranges(body.allowed_ip_ranges.clone().unwrap()).unwrap());

        let cut_short = tokio::time::timeout(
            std::time::Duration::from_millis(300),
            save_user_update(&before, alice.clone(), &body, ranges, |stage| async move {
                if stage == CloseStage::AfterWrite {
                    std::future::pending::<()>().await;
                }
                Ok(())
            }),
        )
        .await;
        assert!(cut_short.is_err(), "the close was meant to never return");
        drop(before);

        let stored = User::Entity::find_by_id(alice.id)
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.allowed_ip_ranges, serde_json::json!(["10.0.0.0/8"]));
        assert!(!session_ended(&db, session).await);

        let after = services(&db).await;
        after.retry_pending_revocations().await;
        assert!(session_ended(&db, session).await);
    }

    /// A close that fails after a delete's commit does not fail the delete; the
    /// row stays, and a session that opened in between is ended by the sweep.
    #[tokio::test]
    async fn a_failing_close_after_a_delete_leaves_the_row_and_the_delete_succeeds() {
        let db = setup_db().await;
        let services = services(&db).await;
        let alice = insert_user(&db, "alice").await;
        let early = open_session_of(&db, &alice).await;
        let late = std::sync::Mutex::new(None);

        let (db2, alice2) = (db.clone(), alice.clone());
        let user_id = alice.id;
        delete_user_and_close(&services, alice.clone(), Uuid::new_v4(), |stage| {
            let (db2, alice2, late, services) = (&db2, &alice2, &late, &services);
            async move {
                if stage == CloseStage::BeforeWrite {
                    return services
                        .close_sessions(SessionsFilter::User { user_id })
                        .await;
                }
                *late.lock().unwrap() = Some(open_session_of(db2, alice2).await);
                Err(WarpgateError::InvalidNetworkAddress("injected".into()))
            }
        })
        .await
        .unwrap();

        let late = late.into_inner().unwrap().unwrap();
        assert!(
            User::Entity::find_by_id(user_id)
                .one(&db)
                .await
                .unwrap()
                .is_none()
        );
        assert!(session_ended(&db, early).await);
        assert!(!session_ended(&db, late).await);
        assert_eq!(PendingUserClose::pending(&db).await.unwrap(), vec![user_id]);

        services.retry_pending_revocations().await;
        assert!(session_ended(&db, late).await);
    }

    /// A delete is audited as soon as it has committed, before the user's
    /// sessions are closed, so a close that fails cannot lose the event.
    #[tokio::test]
    async fn a_delete_is_audited_before_its_close_fails() {
        let db = setup_db().await;
        let services = services(&db).await;
        let alice = insert_user(&db, "alice").await;
        let user_id = alice.id;
        let audited_at_close = std::sync::Mutex::new(None);

        delete_user_and_close(&services, alice, Uuid::new_v4(), |stage| {
            let audited_at_close = &audited_at_close;
            async move {
                if stage == CloseStage::AfterWrite {
                    *audited_at_close.lock().unwrap() = Some(user_deleted_events(user_id));
                    return Err(WarpgateError::InvalidNetworkAddress("injected".into()));
                }
                Ok(())
            }
        })
        .await
        .unwrap();

        assert_eq!(audited_at_close.into_inner().unwrap(), Some(1));
        assert_eq!(user_deleted_events(user_id), 1);
    }

    /// The node stops after the delete committed and before its close returned
    /// (or the request is dropped there): the audit event was already emitted,
    /// and the row written with the delete lets the next process's sweep end
    /// the user's session.
    #[tokio::test]
    async fn a_delete_cut_short_after_the_commit_is_audited_and_closed_by_the_next_process() {
        let db = setup_db().await;
        let before = services(&db).await;
        let alice = insert_user(&db, "alice").await;
        let session = open_session_of(&db, &alice).await;
        let user_id = alice.id;

        let cut_short = tokio::time::timeout(
            std::time::Duration::from_millis(300),
            delete_user_and_close(&before, alice, Uuid::new_v4(), |stage| async move {
                if stage == CloseStage::AfterWrite {
                    std::future::pending::<()>().await;
                }
                Ok(())
            }),
        )
        .await;
        assert!(cut_short.is_err(), "the close was meant to never return");
        drop(before);

        assert!(
            User::Entity::find_by_id(user_id)
                .one(&db)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(user_deleted_events(user_id), 1);
        assert!(!session_ended(&db, session).await);

        let after = services(&db).await;
        after.retry_pending_revocations().await;
        assert!(session_ended(&db, session).await);
    }

    /// A delete whose close succeeds leaves no row behind for the sweep.
    #[tokio::test]
    async fn a_successful_delete_leaves_no_row() {
        let db = setup_db().await;
        let services = services(&db).await;
        let alice = insert_user(&db, "alice").await;
        let session = open_session_of(&db, &alice).await;
        let user_id = alice.id;

        delete_user_and_close(&services, alice, Uuid::new_v4(), |_| {
            services.close_sessions(SessionsFilter::User { user_id })
        })
        .await
        .unwrap();

        assert!(session_ended(&db, session).await);
        assert!(PendingUserClose::pending(&db).await.unwrap().is_empty());
        assert_eq!(user_deleted_events(user_id), 1);
    }

    /// A record written after the sweep read the table survives the sweep's
    /// clear, and so does one written within the last sweep interval.
    #[tokio::test]
    async fn a_newer_record_survives_the_clear_of_an_older_read() {
        let db = setup_db().await;
        let alice = Uuid::new_v4();
        PendingUserClose::mark(&db, alice).await.unwrap();
        age_pending_rows(&db).await;
        let read_at = OffsetDateTime::now_utc();

        // Marked again after the read: the time is refreshed, not kept.
        PendingUserClose::mark(&db, alice).await.unwrap();
        PendingUserClose::clear(&db, alice, read_at).await.unwrap();
        assert_eq!(PendingUserClose::pending(&db).await.unwrap(), vec![alice]);

        // A clear no earlier than the write removes it.
        PendingUserClose::clear(&db, alice, OffsetDateTime::now_utc())
            .await
            .unwrap();
        assert!(PendingUserClose::pending(&db).await.unwrap().is_empty());
    }

    /// A close that succeeded removes the row its own change wrote, but not
    /// one a later change wrote again: that change's close is still owed.
    #[tokio::test]
    async fn a_successful_close_keeps_a_row_a_later_change_wrote() {
        let db = setup_db().await;
        let services = services(&db).await;
        let alice = Uuid::new_v4();
        let first = PendingUserClose::mark(&db, alice).await.unwrap();
        let second = PendingUserClose::mark(&db, alice).await.unwrap();

        services
            .settle_user_session_close(alice, first, Ok(()))
            .await;
        assert_eq!(PendingUserClose::pending(&db).await.unwrap(), vec![alice]);

        services
            .settle_user_session_close(alice, second, Ok(()))
            .await;
        assert!(PendingUserClose::pending(&db).await.unwrap().is_empty());
    }

    /// Repeating an edit whose close failed closes the user's sessions even
    /// though the stored ranges already match, and then removes the row.
    #[tokio::test]
    async fn a_repeated_update_forces_the_close_that_failed() {
        let db = setup_db().await;
        let services = services(&db).await;
        let alice = insert_user(&db, "alice").await;

        let (result, _, late) = save_failing_close(
            &services,
            alice.clone(),
            &edit("alice", Some(&["10.0.0.0/8"])),
            CloseStage::AfterWrite,
        )
        .await;
        let saved = result.unwrap();
        let session = late.unwrap();
        assert!(services.user_close_pending(alice.id).await);

        // The ranges now match the stored ones.
        save(&services, saved, &edit("alice", Some(&["10.0.0.0/8"])))
            .await
            .unwrap();
        assert!(session_ended(&db, session).await);
        assert!(PendingUserClose::pending(&db).await.unwrap().is_empty());
    }

    /// The `_type` and `user_id` of every audit event this test binary emits,
    /// recorded by the one global subscriber a test binary can install: a
    /// thread-local one can miss an event whose callsite another test thread
    /// reached first.
    fn recorded_audit() -> &'static std::sync::Mutex<Vec<(String, String)>> {
        static EVENTS: std::sync::OnceLock<std::sync::Mutex<Vec<(String, String)>>> =
            std::sync::OnceLock::new();
        EVENTS.get_or_init(Default::default)
    }

    fn capture_audit_events() {
        static INSTALLED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
        INSTALLED.get_or_init(|| {
            let _ = tracing::subscriber::set_global_default(AuditCapture);
        });
    }

    fn user_deleted_events(user_id: Uuid) -> usize {
        let user_id = user_id.to_string();
        recorded_audit()
            .lock()
            .unwrap()
            .iter()
            .filter(|(kind, id)| kind == "UserDeleted1" && *id == user_id)
            .count()
    }

    struct AuditCapture;

    #[derive(Default)]
    struct AuditFields {
        kind: Option<String>,
        user_id: Option<String>,
    }

    impl AuditFields {
        fn set(&mut self, name: &str, value: String) {
            match name {
                "_type" => self.kind = Some(value),
                "user_id" => self.user_id = Some(value),
                _ => {}
            }
        }
    }

    impl tracing::field::Visit for AuditFields {
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.set(field.name(), value.to_owned());
        }

        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.set(field.name(), format!("{value:?}"));
        }
    }

    impl tracing::Subscriber for AuditCapture {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            if event.metadata().target() != "audit" {
                return;
            }
            let mut fields = AuditFields::default();
            event.record(&mut fields);
            if let (Some(kind), Some(user_id)) = (fields.kind, fields.user_id) {
                recorded_audit().lock().unwrap().push((kind, user_id));
            }
        }

        fn enter(&self, _: &tracing::span::Id) {}

        fn exit(&self, _: &tracing::span::Id) {}
    }
}
