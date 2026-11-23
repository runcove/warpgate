use crate::WarpgateIdToken;

#[derive(Clone, Debug)]
pub struct SsoLoginResponse {
    pub name: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub access_roles: Option<Vec<String>>,
    pub admin_roles: Option<Vec<String>>,
    pub id_token: WarpgateIdToken,
    /// The ID token's `auth_time` (unix seconds): when the user last
    /// authenticated at the provider, if it said.
    pub auth_time: Option<i64>,
    pub subject: String,
    pub sid: Option<String>,
    pub preferred_username: Option<String>,
}
