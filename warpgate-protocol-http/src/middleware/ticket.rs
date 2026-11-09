use std::net::IpAddr;
use std::sync::Arc;

use poem::http::{HeaderValue, Method, StatusCode, header};
use poem::session::{Session, SessionStatus};
use poem::web::{Data, FromRequest};
use poem::{Endpoint, IntoResponse, Middleware, Request, Response};
use serde::Deserialize;
use time::OffsetDateTime;
use tokio::sync::Mutex;
use tracing::warn;
use uuid::Uuid;
use warpgate_common::Secret;
use warpgate_common::auth::AuthResult;
use warpgate_common_http::auth::UnauthenticatedRequestContext;
use warpgate_common_http::logging::get_client_ip;
use warpgate_common_http::ticket_query::without_ticket_query_param;
use warpgate_common_http::{SessionAuthorization, authorization_token};
use warpgate_core::{authorize_and_spend_ticket, ticket_user_still_admitted};
use warpgate_db_entities::Ticket;

use crate::api::common::end_login;
use crate::common::{SessionExt, SessionRotation, get_auth_state_for_request};
use crate::session::SessionStore;

/// Request-data marker for a header-borne ticket: the request runs on a
/// detached session that is never stored, so the user session registered for
/// it is kept alive by the node's `SessionStore` entry rather than by a
/// stored cookie.
#[derive(Clone, Copy)]
pub(crate) struct TemporaryTicketSession;

/// What consecutive header-ticket requests are recognised by. The database id
/// distinguishes separate tickets issued to the same user for the same target
/// without keeping the secret around to key on.
pub(crate) type TicketSessionKey = (Uuid, Uuid, Option<Uuid>);

/// The ticket identity of a request that carries a header-borne ticket, or
/// `None` for anything cookie-backed.
pub(crate) fn ticket_session_key(req: &Request, session: &Session) -> Option<TicketSessionKey> {
    req.data::<TemporaryTicketSession>()?;
    match session.get_auth()? {
        SessionAuthorization::Ticket {
            user_id,
            target_id,
            ticket_id,
            ..
        } => Some((user_id, target_id, ticket_id)),
        SessionAuthorization::User { .. } => None,
    }
}

pub struct TicketMiddleware {}

impl TicketMiddleware {
    pub const fn new() -> Self {
        Self {}
    }
}

pub struct TicketMiddlewareEndpoint<E: Endpoint> {
    inner: E,
}

impl<E: Endpoint> Middleware<E> for TicketMiddleware {
    type Output = TicketMiddlewareEndpoint<E>;

    fn transform(&self, inner: E) -> Self::Output {
        TicketMiddlewareEndpoint { inner }
    }
}

/// True when a request that has just been authenticated by a ticket in its
/// query should be answered with a redirect to the same address without the
/// ticket, rather than served at the ticket-bearing address.
///
/// Only a browser's top-level page load qualifies: a `GET` that says so
/// explicitly with `Sec-Fetch-Mode: navigate` and `Sec-Fetch-Dest: document`
/// and is not a protocol upgrade.
/// A client that does not send those headers (curl, scripts, older browsers)
/// keeps being served directly, since it may not carry the session cookie
/// across a redirect and would arrive unauthenticated; a framed page
/// (`Sec-Fetch-Dest: iframe`) may have its cookie blocked as a third-party
/// one; any other method would lose its body or change method; a websocket
/// upgrade cannot be redirected.
///
/// The path must also be one the redirect can only lead back to this origin
/// (see [`is_same_origin_path`]); anything else is served in place.
fn should_redirect_to_clean_address(req: &Request) -> bool {
    let header_is = |name: &str, expected: &str| {
        req.headers()
            .get(name)
            .is_some_and(|value| value == expected)
    };
    req.method() == Method::GET
        && header_is("sec-fetch-mode", "navigate")
        && header_is("sec-fetch-dest", "document")
        && !req.headers().contains_key(header::UPGRADE)
        && is_same_origin_path(req.original_uri().path())
}

/// True for a path that, used as a `Location`, a browser resolves on the
/// current origin: one that starts with a single `/`. A path starting `//`
/// is read as a scheme-relative address on another host, and so is one
/// starting `/\`, since browsers treat `\` as `/` in http(s) addresses. The
/// path is used exactly as it arrived, never percent-decoded, so an encoded
/// `/%2F` or `/%5C` stays a path segment on this origin.
fn is_same_origin_path(path: &str) -> bool {
    let mut chars = path.chars();
    chars.next() == Some('/') && !matches!(chars.next(), Some('/' | '\\'))
}

/// Stops the browser sending the address of the page this response belongs
/// to, which carries a ticket, as the `Referer` of the requests it makes.
fn with_no_referrer(mut response: Response) -> Response {
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

/// A `303 See Other` to the request's own path and query without the
/// `warpgate-ticket` parameter. The ticket has been spent into the session,
/// which the session middleware persists on this response, so the browser
/// arrives at the clean address already authenticated, and the ticket leaves
/// its address bar, its history and the page the target serves.
fn clean_address_redirect(req: &Request) -> Response {
    let location = req.original_uri().path_and_query().map_or_else(
        || "/".to_owned(),
        |path| without_ticket_query_param(path.as_str()),
    );
    with_no_referrer(
        Response::builder()
            .status(StatusCode::SEE_OTHER)
            .header(header::LOCATION, location)
            .finish(),
    )
}

/// True when the session already belongs to someone other than the user the
/// ticket was issued to: a signed-in user session, or a session that another
/// ticket started. A ticket session that names no one (the nil user) belongs
/// to nobody and is not protected. A session for the same user is not matched,
/// so that case behaves as it always has.
fn ticket_belongs_to_another_user(
    current: Option<&SessionAuthorization>,
    ticket_user_id: Uuid,
) -> bool {
    matches!(
        current,
        Some(
            SessionAuthorization::User { user_id, .. }
                | SessionAuthorization::Ticket { user_id, .. }
        ) if !user_id.is_nil() && *user_id != ticket_user_id
    )
}

/// What a stored session's authorization asks of the per-request re-check.
#[derive(Debug, PartialEq, Eq)]
enum TicketRecheck {
    /// Not backed by a ticket, or the synthetic `<public>` authorization (nil
    /// user id), which has no ticket behind it.
    Skip,
    /// A ticket session that records no ticket id (stored by an older
    /// version): nothing can vouch for it, so it counts as ended.
    NoTicketId,
    /// A ticket session to check against this ticket and its user.
    Check { ticket_id: Uuid, user_id: Uuid },
}

fn ticket_to_recheck(auth: &SessionAuthorization) -> TicketRecheck {
    match auth {
        SessionAuthorization::Ticket { user_id, .. } if user_id.is_nil() => TicketRecheck::Skip,
        SessionAuthorization::Ticket {
            user_id,
            ticket_id: Some(ticket_id),
            ..
        } => TicketRecheck::Check {
            ticket_id: *ticket_id,
            user_id: *user_id,
        },
        SessionAuthorization::Ticket {
            ticket_id: None, ..
        } => TicketRecheck::NoTicketId,
        _ => TicketRecheck::Skip,
    }
}

/// True when a ticket session may keep serving requests: its ticket still
/// exists and has not expired. `ticket_expiry` is `None` for a ticket that is
/// gone, `Some(None)` for one that never expires.
///
/// Uses left do not matter here: a use is spent when the ticket starts the
/// session, and the session then carries on after the last one is spent.
fn ticket_session_is_current(
    ticket_expiry: Option<Option<OffsetDateTime>>,
    now: OffsetDateTime,
) -> bool {
    match ticket_expiry {
        None => false,
        Some(None) => true,
        Some(Some(expiry)) => expiry >= now,
    }
}

/// True when a sign-in that is still under way on the session (for example a
/// password accepted and a second factor awaited) is for someone other than
/// the user the ticket was issued to. Such a session has no authorization yet,
/// so [`ticket_belongs_to_another_user`] cannot see it. `pending_user_id` is
/// `None` when no sign-in is under way, and the nil id names no one.
fn pending_login_belongs_to_another_user(
    pending_user_id: Option<Uuid>,
    ticket_user_id: Uuid,
) -> bool {
    matches!(pending_user_id, Some(id) if !id.is_nil() && id != ticket_user_id)
}

/// The user a sign-in that is still under way on this session is for, if any.
/// A sign-in that has been rejected can never complete and counts as none.
async fn pending_login_user_id(
    req: &Request,
    ctx: &UnauthenticatedRequestContext,
) -> poem::Result<Option<Uuid>> {
    let Some(state) = get_auth_state_for_request(req, ctx).await? else {
        return Ok(None);
    };
    let state = state.lock().await;
    Ok(if matches!(state.verify(), AuthResult::Rejected) {
        None
    } else {
        Some(state.user_info().id)
    })
}

#[derive(Deserialize)]
struct QueryParams {
    #[serde(rename = "warpgate-ticket")]
    ticket: Option<String>,
}

impl<E: Endpoint> Endpoint for TicketMiddlewareEndpoint<E> {
    type Output = Response;

    async fn call(&self, mut req: Request) -> poem::Result<Self::Output> {
        let mut session_is_temporary = false;
        let ctx = Data::<&UnauthenticatedRequestContext>::from_request_without_body(&req)
            .await?
            .clone();

        let params: QueryParams = req.params()?;
        // A ticket in the query sits in the page's address, where the browser
        // would otherwise keep it and send it on.
        let ticket_in_address = params.ticket.is_some();
        let mut ticket_value = params.ticket;

        if let Some(token_value) = authorization_token(&req, "Warpgate") {
            ticket_value = Some(token_value.to_string());
            session_is_temporary = true;
        }

        if session_is_temporary {
            // ticket/token requests get a fake temp session
            // which is never persisted into the store
            req.extensions_mut().insert(Session::default());
            req.set_data(TemporaryTicketSession);
        }
        let session = <&Session>::from_request_without_body(&req).await?.clone();
        let mut rotation = None;

        // A browser session that a ticket started lasts as long as the ticket
        // and as long as its user may sign in from where the request comes
        // from: once the ticket is deleted or expired, or the user is locked,
        // outside their allowed IP ranges or on a blocked address, the session
        // ends as at logout and the request carries on anonymous on a fresh
        // session, with any ticket presented with it judged on its own.
        if !session_is_temporary && let Some(auth) = session.get_auth() {
            let ended = match ticket_to_recheck(&auth) {
                TicketRecheck::Skip => false,
                TicketRecheck::NoTicketId => true,
                TicketRecheck::Check { ticket_id, user_id } => {
                    let expiry = Ticket::expiry_by_id(&ctx.services().db, ticket_id).await?;
                    if ticket_session_is_current(expiry, OffsetDateTime::now_utc()) {
                        // Only for a ticket that is still current: the user
                        // is judged by the rules the session started under.
                        let client_ip = get_client_ip(&req, ctx.services())
                            .await
                            .and_then(|s| s.parse().ok());
                        !ticket_user_still_admitted(
                            &ctx.services().db,
                            &ctx.services().login_protection,
                            user_id,
                            client_ip,
                        )
                        .await?
                    } else {
                        true
                    }
                }
            };
            if ended {
                // As the step-up logout does: the login is ended, then the
                // browser session is cleared rather than purged, because a
                // purged session ignores every later write in this request.
                let session_store =
                    Data::<&Arc<Mutex<SessionStore>>>::from_request_without_body(&req).await?;
                end_login(&session, session_store.0, &ctx.services().db).await;
                session.clear();
            }
        }

        if let Some(ticket) = ticket_value {
            let ticket_secret = Secret::new(ticket);

            let presented_owner =
                Ticket::owner_for_secret(&ctx.services().db, &ticket_secret).await?;
            let presented = presented_owner.map(|(ticket_id, _)| ticket_id);
            if presented_owner.is_none() {
                // The fact only: the secret is never logged.
                warn!("Ticket not found");
            }

            // A ticket issued to a different user than the one this browser
            // session belongs to (signed in, started by another ticket, or
            // part-way through signing in) is ignored: the session is kept and
            // no use is spent. Nothing about the request tells it apart from
            // one that presents an unknown ticket, so the answer does not
            // confirm that the ticket exists.
            //
            // The same lookups run whether the ticket is unknown or belongs to
            // another user (the owner lookup above, then the part-way login
            // check), and neither goes on to the sign-in checks, so the two
            // take the same steps and the same time.
            let pending = if session_is_temporary {
                None
            } else {
                pending_login_user_id(&req, &ctx).await?
            };
            let belongs_to_another_user = match presented_owner {
                Some((ticket_id, ticket_user_id)) if !session_is_temporary => {
                    let other =
                        ticket_belongs_to_another_user(session.get_auth().as_ref(), ticket_user_id)
                            || pending_login_belongs_to_another_user(pending, ticket_user_id);
                    if other {
                        warn!(%ticket_id, "Ticket belongs to a different user than this session, ignoring it");
                    }
                    other
                }
                _ => false,
            };

            // Do not re-spend the ticket if it has authenticated the current session already
            let already_this_ticket = matches!(
                (session.get_auth(), presented),
                (
                    Some(SessionAuthorization::Ticket {
                        ticket_id: Some(session_ticket),
                        ..
                    }),
                    Some(presented),
                ) if session_ticket == presented
            );

            if presented_owner.is_some() && !already_this_ticket && !belongs_to_another_user {
                let client_ip: Option<IpAddr> = get_client_ip(&req, ctx.services())
                    .await
                    .and_then(|s| s.parse().ok());
                if let Some(authorization) = authorize_and_spend_ticket(
                    &ctx.services().db,
                    &ctx.services().login_protection,
                    &ticket_secret,
                    client_ip,
                    crate::common::PROTOCOL_NAME,
                )
                .await?
                {
                    session.set_auth(SessionAuthorization::Ticket {
                        user_id: authorization.user_info().id,
                        username: authorization.user_info().username.clone(),
                        target_id: authorization.target().id,
                        ticket_id: authorization.ticket_id(),
                    });
                    if !session_is_temporary {
                        rotation = SessionRotation::for_request(&req).await?;
                    }
                }
            }
        }

        // A header ticket takes precedence over a query one and never sits in
        // an address, so only a query ticket is redirected away. This holds
        // whether or not the ticket authenticated: a ticket that did not
        // (unknown, expired, used up, or issued to another user) is answered
        // the same way for each of those, and its address leaves the browser's
        // history too.
        if ticket_in_address && !session_is_temporary && should_redirect_to_clean_address(&req) {
            let response = clean_address_redirect(&req);
            // Nothing is proxied on this path, so a rotated id is written
            // back by the session middleware on this very response.
            apply_session_rotation(rotation, &session).await;
            return Ok(response);
        }

        let result = self.inner.call(req).await;

        // Rotating deletes the stored row until the session middleware writes
        // the new one, so doing it before the inner call would leave the user
        // session unbacked (and reapable) for the length of a proxied request.
        // It runs on error too: the ticket is spent and its grant is in the
        // session either way.
        apply_session_rotation(rotation, &session).await;

        let response = result?.into_response();
        Ok(if ticket_in_address {
            with_no_referrer(response)
        } else {
            response
        })
    }
}

/// Rotates the session id once a ticket has authenticated a stored session.
/// A rotation that fails purges the session rather than keep the old id.
async fn apply_session_rotation(rotation: Option<SessionRotation>, session: &Session) {
    if let Some(rotation) = rotation
        && session.status() != SessionStatus::Purged
        && let Err(error) = rotation.apply(session).await
    {
        warn!(%error, "Could not rotate the session id after ticket auth");
        session.purge();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user_auth(user_id: Uuid) -> SessionAuthorization {
        SessionAuthorization::User {
            user_id,
            username: "someone".into(),
        }
    }

    /// A signed-in user session is kept when the ticket belongs to a different user.
    #[test]
    fn a_ticket_for_another_user_does_not_replace_a_user_session() {
        let me = Uuid::new_v4();
        let other = Uuid::new_v4();
        assert!(ticket_belongs_to_another_user(Some(&user_auth(me)), other));
    }

    fn ticket_auth(user_id: Uuid) -> SessionAuthorization {
        SessionAuthorization::Ticket {
            user_id,
            username: "t".into(),
            target_id: Uuid::new_v4(),
            ticket_id: Some(Uuid::new_v4()),
        }
    }

    /// A session that another ticket started is kept too.
    #[test]
    fn a_ticket_for_another_user_does_not_replace_a_ticket_session() {
        let me = Uuid::new_v4();
        let other = Uuid::new_v4();
        assert!(ticket_belongs_to_another_user(
            Some(&ticket_auth(me)),
            other
        ));
    }

    /// The same user's ticket, no session, and a ticket session that names no
    /// one are all handled as before.
    #[test]
    fn other_sessions_do_not_block_a_ticket() {
        let me = Uuid::new_v4();
        assert!(!ticket_belongs_to_another_user(Some(&user_auth(me)), me));
        assert!(!ticket_belongs_to_another_user(Some(&ticket_auth(me)), me));
        assert!(!ticket_belongs_to_another_user(None, me));
        assert!(!ticket_belongs_to_another_user(
            Some(&ticket_auth(Uuid::nil())),
            me
        ));
    }

    /// A ticket session goes on while its ticket exists and has not expired,
    /// and ends when the ticket is gone or past its expiry.
    #[test]
    fn a_ticket_session_follows_its_ticket() {
        let now = OffsetDateTime::now_utc();
        let hour = time::Duration::hours(1);
        assert!(ticket_session_is_current(Some(None), now));
        assert!(ticket_session_is_current(Some(Some(now + hour)), now));
        assert!(ticket_session_is_current(Some(Some(now)), now));
        assert!(!ticket_session_is_current(Some(Some(now - hour)), now));
        assert!(!ticket_session_is_current(None, now));
    }

    /// Only a ticket session that names a user is re-checked against its
    /// ticket: a nil user id or the reserved public name has no ticket behind
    /// it, and a user login has none either.
    #[test]
    fn only_a_ticket_session_naming_a_user_is_rechecked() {
        let ticket_id = Uuid::new_v4();
        let ticket =
            |user_id: Uuid, username: &str, ticket_id: Option<Uuid>| SessionAuthorization::Ticket {
                user_id,
                username: username.into(),
                target_id: Uuid::new_v4(),
                ticket_id,
            };
        let user = Uuid::new_v4();
        assert_eq!(
            ticket_to_recheck(&ticket(user, "alice", Some(ticket_id))),
            TicketRecheck::Check {
                ticket_id,
                user_id: user
            }
        );
        assert_eq!(
            ticket_to_recheck(&ticket(Uuid::nil(), "alice", Some(ticket_id))),
            TicketRecheck::Skip
        );
        assert_eq!(
            ticket_to_recheck(&ticket(Uuid::nil(), "alice", None)),
            TicketRecheck::Skip
        );
        // A real user may be named like the synthetic public user.
        assert_eq!(
            ticket_to_recheck(&ticket(user, "<public>", Some(ticket_id))),
            TicketRecheck::Check {
                ticket_id,
                user_id: user
            }
        );
        // Stored without a ticket id: counts as ended.
        assert_eq!(
            ticket_to_recheck(&ticket(user, "alice", None)),
            TicketRecheck::NoTicketId
        );
        assert_eq!(ticket_to_recheck(&user_auth(user)), TicketRecheck::Skip);
    }

    /// A sign-in under way for someone else keeps the session from being
    /// taken over by a ticket for a different user; one for the ticket's own
    /// user, none at all, and a nil user id do not.
    #[test]
    fn a_sign_in_under_way_is_kept_from_another_users_ticket() {
        let me = Uuid::new_v4();
        let other = Uuid::new_v4();
        assert!(pending_login_belongs_to_another_user(Some(me), other));
        assert!(!pending_login_belongs_to_another_user(Some(me), me));
        assert!(!pending_login_belongs_to_another_user(None, me));
        assert!(!pending_login_belongs_to_another_user(
            Some(Uuid::nil()),
            me
        ));
    }

    const BROWSER_ACCEPT: &str = "text/html,application/xhtml+xml,*/*;q=0.8";

    /// A request as the server builds it. poem's `RequestBuilder` leaves
    /// `original_uri` at `/` whatever the URI, and the redirect reads
    /// `original_uri`.
    fn served_request(method: Method, uri: &str, headers: &[(&str, &str)]) -> Request {
        let mut builder = poem::http::Request::builder().method(method).uri(uri);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let (parts, ()) = builder.body(()).unwrap().into_parts();
        let req = Request::from_parts(
            poem::RequestParts::from((
                parts,
                poem::web::LocalAddr::default(),
                poem::web::RemoteAddr::default(),
                poem::http::uri::Scheme::HTTP,
            )),
            poem::Body::empty(),
        );
        // Positive control: the address under test is the one the code reads.
        assert_eq!(req.original_uri().to_string(), uri);
        req
    }

    fn request(method: Method, headers: &[(&str, &str)]) -> Request {
        served_request(
            method,
            "/app?a=1&warpgate-ticket=s3cr3t-ticket-value&b=two%20words",
            headers,
        )
    }

    const PAGE_LOAD: &[(&str, &str)] = &[
        ("accept", BROWSER_ACCEPT),
        ("sec-fetch-mode", "navigate"),
        ("sec-fetch-dest", "document"),
    ];

    /// A browser's top-level page load, which says so with `Sec-Fetch-Mode:
    /// navigate` and `Sec-Fetch-Dest: document`, is redirected to the clean
    /// address.
    #[test]
    fn a_page_load_is_redirected_to_the_clean_address() {
        let req = request(Method::GET, PAGE_LOAD);
        assert!(should_redirect_to_clean_address(&req));
    }

    /// A page load whose path a browser would read as another host (`//` or
    /// `/\` at the start) is never redirected: served in place, it cannot
    /// send the visitor off-site. An encoded slash or backslash stays a path
    /// segment on this origin, since the path is never decoded, and is
    /// redirected with the path unchanged.
    #[test]
    fn a_path_naming_another_host_is_not_redirected() {
        for path in [
            "//evil.example/?warpgate-ticket=s",
            "//evil.example/x?a=1&warpgate-ticket=s",
            "///evil.example/?warpgate-ticket=s",
            "/\\evil.example/?warpgate-ticket=s",
            "/\\/evil.example/?warpgate-ticket=s",
        ] {
            let req = served_request(Method::GET, path, PAGE_LOAD);
            assert!(!should_redirect_to_clean_address(&req), "{path}");
        }

        for (path, location) in [
            ("/%2Fevil.example/?warpgate-ticket=s", "/%2Fevil.example/"),
            ("/%5Cevil.example/?warpgate-ticket=s", "/%5Cevil.example/"),
            (
                "/%2f%2fevil.example/?warpgate-ticket=s",
                "/%2f%2fevil.example/",
            ),
        ] {
            let req = served_request(Method::GET, path, PAGE_LOAD);
            assert!(should_redirect_to_clean_address(&req), "{path}");
            assert_eq!(
                clean_address_redirect(&req)
                    .headers()
                    .get(header::LOCATION)
                    .unwrap(),
                location
            );
        }
    }

    /// Anything that is not an explicit page load is served where it is: a
    /// client that sends no `Sec-Fetch-Mode` (curl, scripts), a fetch from a
    /// page, a form post, and a websocket upgrade.
    #[test]
    fn other_requests_are_not_redirected() {
        for (method, headers) in [
            (Method::GET, &[("accept", BROWSER_ACCEPT)][..]),
            (Method::GET, &[("accept", "*/*")]),
            (
                Method::GET,
                &[("accept", BROWSER_ACCEPT), ("sec-fetch-mode", "navigate")],
            ),
            (
                Method::GET,
                &[("sec-fetch-mode", "navigate"), ("sec-fetch-dest", "iframe")],
            ),
            (
                Method::GET,
                &[("sec-fetch-mode", "navigate"), ("sec-fetch-dest", "frame")],
            ),
            (Method::GET, &[("sec-fetch-dest", "document")]),
            (Method::GET, &[("sec-fetch-mode", "cors")]),
            (Method::GET, &[("sec-fetch-mode", "no-cors")]),
            (Method::POST, PAGE_LOAD),
            (Method::HEAD, PAGE_LOAD),
            (
                Method::GET,
                &[
                    ("sec-fetch-mode", "navigate"),
                    ("sec-fetch-dest", "document"),
                    ("connection", "upgrade"),
                    ("upgrade", "websocket"),
                ],
            ),
            (
                Method::GET,
                &[("sec-fetch-mode", "websocket"), ("upgrade", "websocket")],
            ),
        ] {
            let req = request(method.clone(), headers);
            assert!(
                !should_redirect_to_clean_address(&req),
                "{method} {headers:?}"
            );
        }
    }

    /// The redirect is a `303` to the same path and query without the ticket,
    /// the other parameters kept exactly, and tells the browser to send no
    /// `Referer` from the ticket-bearing address.
    #[test]
    fn the_redirect_leads_to_the_clean_address_without_a_referer() {
        let req = request(Method::GET, &[("sec-fetch-mode", "navigate")]);
        let resp = clean_address_redirect(&req);
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            resp.headers().get(header::LOCATION).unwrap(),
            "/app?a=1&b=two%20words"
        );
        assert_eq!(
            resp.headers().get(header::REFERRER_POLICY).unwrap(),
            "no-referrer"
        );

        let only_ticket = served_request(Method::GET, "/?warpgate-ticket=s3cr3t-ticket-value", &[]);
        assert_eq!(
            clean_address_redirect(&only_ticket)
                .headers()
                .get(header::LOCATION)
                .unwrap(),
            "/"
        );
    }

    /// A response served at a ticket-bearing address tells the browser to send
    /// no `Referer` from it, replacing any policy the target set.
    #[test]
    fn a_response_at_a_ticket_address_sends_no_referer() {
        let resp = with_no_referrer(
            Response::builder()
                .header(header::REFERRER_POLICY, "unsafe-url")
                .finish(),
        );
        let values: Vec<_> = resp
            .headers()
            .get_all(header::REFERRER_POLICY)
            .iter()
            .collect();
        assert_eq!(values, ["no-referrer"]);
    }

    #[test]
    fn temporary_ticket_sessions_are_keyed_by_ticket_id() {
        let user_id = Uuid::new_v4();
        let target_id = Uuid::new_v4();
        let first_ticket_id = Uuid::new_v4();
        let second_ticket_id = Uuid::new_v4();
        let mut req = Request::builder().finish();
        req.set_data(TemporaryTicketSession);
        let session = Session::default();
        session.set_auth(SessionAuthorization::Ticket {
            user_id,
            username: "alice".into(),
            target_id,
            ticket_id: Some(first_ticket_id),
        });
        let first_key = ticket_session_key(&req, &session);

        session.set_auth(SessionAuthorization::Ticket {
            user_id,
            username: "alice".into(),
            target_id,
            ticket_id: Some(second_ticket_id),
        });

        assert_ne!(first_key, ticket_session_key(&req, &session));
    }
}
