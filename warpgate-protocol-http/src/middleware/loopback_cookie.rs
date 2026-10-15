use std::time::Duration;

use cookie::{Cookie, SameSite};
use http::{HeaderValue, header};
use poem::{Endpoint, IntoResponse, Middleware, Request, Response};

use crate::common::{LOOPBACK_SESSION_COOKIE_NAME, SESSION_COOKIE_NAME};

/// The longest a loopback session cookie is kept, whatever `cookie_max_age` says.
pub const LOOPBACK_SESSION_COOKIE_MAX_AGE_CAP: Duration = Duration::from_hours(12);

/// The session cookie on a plain-HTTP loopback listener
/// (`http.plain_http_on_loopback`), installed outside `ServerSession` and
/// `CookieHostMiddleware`.
///
/// Inside, Warpgate reads and writes the session under [`SESSION_COOKIE_NAME`]
/// as everywhere else (the API's cookie security schemes name it too). The
/// browser only ever holds [`LOOPBACK_SESSION_COOKIE_NAME`]: on the way in it
/// is renamed to the session cookie, and a session cookie the browser sent
/// under its own name is dropped; on the way out the session cookie is renamed
/// and given exactly `HttpOnly`, `SameSite=Strict`, no `Domain` (host-only),
/// no `Secure` (Safari drops a `Secure` cookie on `http://localhost`) and a
/// `Max-Age` of at most [`LOOPBACK_SESSION_COOKIE_MAX_AGE_CAP`].
#[derive(Clone)]
pub struct LoopbackSessionCookieMiddleware {
    max_age: Duration,
}

impl LoopbackSessionCookieMiddleware {
    /// `max_age` is the session's own lifetime (`cookie_max_age`), capped here.
    pub fn new(max_age: Duration) -> Self {
        Self {
            max_age: max_age.min(LOOPBACK_SESSION_COOKIE_MAX_AGE_CAP),
        }
    }
}

impl<E: Endpoint> Middleware<E> for LoopbackSessionCookieMiddleware {
    type Output = LoopbackSessionCookieEndpoint<E>;

    fn transform(&self, inner: E) -> Self::Output {
        LoopbackSessionCookieEndpoint {
            inner,
            max_age: self.max_age,
        }
    }
}

pub struct LoopbackSessionCookieEndpoint<E: Endpoint> {
    inner: E,
    max_age: Duration,
}

impl<E: Endpoint> Endpoint for LoopbackSessionCookieEndpoint<E> {
    type Output = Response;

    async fn call(&self, mut req: Request) -> poem::Result<Self::Output> {
        let translated = request_cookie_header(
            req.headers()
                .get_all(header::COOKIE)
                .iter()
                .map(|value| String::from_utf8_lossy(value.as_bytes())),
        );
        if let Some(cookies) = translated {
            let headers = req.headers_mut();
            headers.remove(header::COOKIE);
            if !cookies.is_empty()
                && let Ok(value) = HeaderValue::from_str(&cookies)
            {
                headers.insert(header::COOKIE, value);
            }
        }

        let mut resp = self.inner.call(req).await?.into_response();

        if let header::Entry::Occupied(mut entry) = resp.headers_mut().entry(header::SET_COOKIE) {
            for value in entry.iter_mut() {
                if let Ok(set_cookie) = value.to_str()
                    && let Some(loopback) = loopback_set_cookie(set_cookie, self.max_age)
                    && let Ok(loopback) = HeaderValue::from_str(&loopback)
                {
                    *value = loopback;
                }
            }
        }

        Ok(resp)
    }
}

/// The request's `Cookie` header as Warpgate reads it on a loopback listener:
/// the loopback cookie under the session cookie's name, and any cookie sent
/// under the session cookie's own name dropped. Every other pair is kept as
/// sent. `None` when there is nothing to change.
fn request_cookie_header<S: AsRef<str>>(values: impl IntoIterator<Item = S>) -> Option<String> {
    let mut changed = false;
    let mut pairs = Vec::new();
    for value in values {
        for pair in value.as_ref().split(';') {
            let pair = pair.trim();
            if pair.is_empty() {
                continue;
            }
            let (name, cookie_value) = pair.split_once('=').unwrap_or((pair, ""));
            let name = name.trim();
            if name == SESSION_COOKIE_NAME {
                changed = true;
            } else if name == LOOPBACK_SESSION_COOKIE_NAME {
                changed = true;
                pairs.push(format!("{SESSION_COOKIE_NAME}={}", cookie_value.trim()));
            } else {
                pairs.push(pair.to_owned());
            }
        }
    }
    changed.then(|| pairs.join("; "))
}

/// The loopback form of a session `Set-Cookie`, or `None` for any other
/// cookie. A removal (`Max-Age=0`) stays a removal.
fn loopback_set_cookie(set_cookie: &str, max_age: Duration) -> Option<String> {
    let mut cookie = Cookie::parse(set_cookie).ok()?;
    if cookie.name() != SESSION_COOKIE_NAME {
        return None;
    }
    cookie.set_name(LOOPBACK_SESSION_COOKIE_NAME);
    cookie.unset_domain();
    cookie.set_path("/");
    cookie.set_secure(false);
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Strict);
    if cookie.max_age() != Some(cookie::time::Duration::ZERO) {
        let seconds = max_age
            .min(LOOPBACK_SESSION_COOKIE_MAX_AGE_CAP)
            .as_secs()
            .try_into()
            .unwrap_or(i64::MAX);
        cookie.set_max_age(cookie::time::Duration::seconds(seconds));
    }
    Some(cookie.to_string())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use cookie::{Cookie, SameSite};
    use poem::session::{MemoryStorage, ServerSession, Session};
    use poem::test::{TestClient, TestResponse};
    use poem::{Endpoint, EndpointExt, Request, Route, get, handler};

    use super::{LOOPBACK_SESSION_COOKIE_MAX_AGE_CAP, LoopbackSessionCookieMiddleware};
    use crate::common::{LOOPBACK_SESSION_COOKIE_NAME, SESSION_COOKIE_NAME, session_cookie_config};

    #[handler]
    async fn login(session: &Session) -> &'static str {
        session.set("user", "alice");
        "ok"
    }

    #[handler]
    async fn logout(session: &Session) -> &'static str {
        session.purge();
        "ok"
    }

    #[handler]
    async fn echo_cookie(req: &Request) -> String {
        req.header(http::header::COOKIE)
            .unwrap_or_default()
            .to_owned()
    }

    /// The session wiring of `lib.rs`, without `CookieHostMiddleware` (it
    /// needs a `Services`); the loopback middleware sits outside it there too.
    fn app(loopback: bool, max_age: Duration) -> impl Endpoint {
        Route::new()
            .at("/login", get(login))
            .at("/logout", get(logout))
            .at("/echo", get(echo_cookie))
            .with(ServerSession::new(
                session_cookie_config().max_age(max_age),
                MemoryStorage::new(),
            ))
            .with_if(loopback, LoopbackSessionCookieMiddleware::new(max_age))
    }

    fn set_cookies(resp: &TestResponse) -> Vec<Cookie<'static>> {
        resp.0
            .headers()
            .get_all(http::header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .map(|value| Cookie::parse(value.to_owned()).unwrap())
            .collect()
    }

    fn only_set_cookie(resp: &TestResponse) -> Cookie<'static> {
        let mut cookies = set_cookies(resp);
        assert_eq!(cookies.len(), 1, "{cookies:?}");
        cookies.remove(0)
    }

    #[tokio::test]
    async fn unit_loopback_session_cookie_attributes() {
        let cli = TestClient::new(app(true, Duration::from_hours(24)));
        let resp = cli.get("/login").send().await;
        resp.assert_status_is_ok();

        let cookie = only_set_cookie(&resp);
        assert_eq!(cookie.name(), LOOPBACK_SESSION_COOKIE_NAME);
        assert!(!cookie.value().is_empty());
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Strict));
        assert_ne!(cookie.secure(), Some(true));
        assert_eq!(cookie.domain(), None);
        assert_eq!(cookie.path(), Some("/"));
        // The session's 24h, capped at 12h.
        assert_eq!(cookie.max_age(), Some(cookie::time::Duration::hours(12)));
        assert_eq!(
            LOOPBACK_SESSION_COOKIE_MAX_AGE_CAP,
            Duration::from_hours(12)
        );
    }

    #[tokio::test]
    async fn unit_loopback_session_cookie_keeps_a_shorter_session_lifetime() {
        let cli = TestClient::new(app(true, Duration::from_hours(1)));
        let resp = cli.get("/login").send().await;

        let cookie = only_set_cookie(&resp);
        assert_eq!(cookie.name(), LOOPBACK_SESSION_COOKIE_NAME);
        assert_eq!(cookie.max_age(), Some(cookie::time::Duration::hours(1)));
    }

    #[tokio::test]
    async fn unit_session_cookie_unchanged_outside_loopback_mode() {
        let cli = TestClient::new(app(false, Duration::from_hours(24)));
        let resp = cli.get("/login").send().await;

        let cookie = only_set_cookie(&resp);
        assert_eq!(cookie.name(), SESSION_COOKIE_NAME);
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), None);
        assert_eq!(cookie.max_age(), Some(cookie::time::Duration::hours(24)));
    }

    #[tokio::test]
    async fn unit_loopback_session_cookie_is_read_back_and_removed() {
        let cli = TestClient::new(app(true, Duration::from_hours(24)));
        let login = only_set_cookie(&cli.get("/login").send().await);

        let resp = cli
            .get("/logout")
            .header(
                "cookie",
                format!("{LOOPBACK_SESSION_COOKIE_NAME}={}", login.value()),
            )
            .send()
            .await;
        resp.assert_status_is_ok();

        let removal = only_set_cookie(&resp);
        assert_eq!(removal.name(), LOOPBACK_SESSION_COOKIE_NAME);
        assert_eq!(removal.max_age(), Some(cookie::time::Duration::ZERO));
    }

    #[tokio::test]
    async fn unit_loopback_request_cookie_is_renamed_and_a_raw_session_cookie_dropped() {
        let cli = TestClient::new(app(true, Duration::from_hours(24)));
        let resp = cli
            .get("/echo")
            .header(
                "cookie",
                format!("{LOOPBACK_SESSION_COOKIE_NAME}=abc; {SESSION_COOKIE_NAME}=forged; app=1"),
            )
            .send()
            .await;

        resp.assert_text(format!("{SESSION_COOKIE_NAME}=abc; app=1"))
            .await;
    }

    #[tokio::test]
    async fn unit_request_cookies_unchanged_outside_loopback_mode() {
        let sent = format!("{LOOPBACK_SESSION_COOKIE_NAME}=abc; {SESSION_COOKIE_NAME}=xyz; app=1");
        let cli = TestClient::new(app(false, Duration::from_hours(24)));
        let resp = cli.get("/echo").header("cookie", sent.clone()).send().await;

        resp.assert_text(sent).await;
    }

    #[test]
    fn unit_loopback_request_cookie_header_leaves_other_cookies_alone() {
        assert_eq!(super::request_cookie_header(["app=1; other=2"]), None);
        assert_eq!(
            super::request_cookie_header([format!("{SESSION_COOKIE_NAME}=forged")]),
            Some(String::new())
        );
    }

    #[test]
    fn unit_loopback_set_cookie_leaves_other_cookies_alone() {
        assert_eq!(
            super::loopback_set_cookie("app=1; Path=/; Secure", Duration::from_hours(1)),
            None
        );
    }
}
