use std::net::IpAddr;

use poem::http::{HeaderValue, Method, StatusCode, header};
use poem::session::Session;
use poem::web::{Data, FromRequest};
use poem::{Endpoint, IntoResponse, Middleware, Request, Response};
use serde::Deserialize;
use uuid::Uuid;
use warpgate_common::Secret;
use warpgate_common_http::auth::UnauthenticatedRequestContext;
use warpgate_common_http::logging::get_client_ip;
use warpgate_common_http::ticket_query::without_ticket_query_param;
use warpgate_common_http::{SessionAuthorization, authorization_token};
use warpgate_core::authorize_and_spend_ticket;
use warpgate_db_entities::Ticket;

use crate::common::SessionExt;

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
/// explicitly with `Sec-Fetch-Mode: navigate` and is not a protocol upgrade.
/// A client that does not send `Sec-Fetch-Mode` (curl, scripts, older
/// browsers) keeps being served directly, since it may not carry the session
/// cookie across a redirect and would arrive unauthenticated; any other
/// method would lose its body or change method; a websocket upgrade cannot
/// be redirected.
fn should_redirect_to_clean_address(req: &Request) -> bool {
    req.method() == Method::GET
        && req
            .headers()
            .get("sec-fetch-mode")
            .is_some_and(|mode| mode == "navigate")
        && !req.headers().contains_key(header::UPGRADE)
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
    let location = req
        .original_uri()
        .path_and_query()
        .map_or_else(|| "/".to_owned(), |path| without_ticket_query_param(path.as_str()));
    with_no_referrer(
        Response::builder()
            .status(StatusCode::SEE_OTHER)
            .header(header::LOCATION, location)
            .finish(),
    )
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
        let mut ticket_authenticated = false;

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

        if let Some(ticket) = ticket_value {
            let ticket_secret = Secret::new(ticket);

            let presented = Ticket::for_secret(&ctx.services().db, &ticket_secret).await?;
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

            ticket_authenticated = already_this_ticket;
            if !already_this_ticket {
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
                    ticket_authenticated = true;
                }
            }
        }

        // A header ticket takes precedence over a query one and never sits in
        // an address, so only a query ticket that authenticated the request is
        // redirected away.
        if ticket_in_address
            && !session_is_temporary
            && ticket_authenticated
            && should_redirect_to_clean_address(&req)
        {
            return Ok(clean_address_redirect(&req));
        }

        let response = self.inner.call(req).await?.into_response();
        Ok(if ticket_in_address {
            with_no_referrer(response)
        } else {
            response
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BROWSER_ACCEPT: &str = "text/html,application/xhtml+xml,*/*;q=0.8";

    fn request(method: Method, headers: &[(&str, &str)]) -> Request {
        let mut builder = Request::builder()
            .method(method)
            .uri_str("/app?a=1&warpgate-ticket=s3cr3t-ticket-value&b=two%20words");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.finish()
    }

    /// A browser's page load, which says so with `Sec-Fetch-Mode: navigate`,
    /// is redirected to the clean address.
    #[test]
    fn a_page_load_is_redirected_to_the_clean_address() {
        let req = request(
            Method::GET,
            &[("accept", BROWSER_ACCEPT), ("sec-fetch-mode", "navigate")],
        );
        assert!(should_redirect_to_clean_address(&req));
    }

    /// Anything that is not an explicit page load is served where it is: a
    /// client that sends no `Sec-Fetch-Mode` (curl, scripts), a fetch from a
    /// page, a form post, and a websocket upgrade.
    #[test]
    fn other_requests_are_not_redirected() {
        for (method, headers) in [
            (Method::GET, &[("accept", BROWSER_ACCEPT)][..]),
            (Method::GET, &[("accept", "*/*")]),
            (Method::GET, &[("sec-fetch-mode", "cors")]),
            (Method::GET, &[("sec-fetch-mode", "no-cors")]),
            (
                Method::POST,
                &[("accept", BROWSER_ACCEPT), ("sec-fetch-mode", "navigate")],
            ),
            (
                Method::HEAD,
                &[("accept", BROWSER_ACCEPT), ("sec-fetch-mode", "navigate")],
            ),
            (
                Method::GET,
                &[
                    ("sec-fetch-mode", "navigate"),
                    ("connection", "upgrade"),
                    ("upgrade", "websocket"),
                ],
            ),
            (Method::GET, &[("sec-fetch-mode", "websocket"), ("upgrade", "websocket")]),
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

        let only_ticket = Request::builder()
            .uri_str("/?warpgate-ticket=s3cr3t-ticket-value")
            .finish();
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
