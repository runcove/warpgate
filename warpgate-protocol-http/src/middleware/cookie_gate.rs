//! The one place a browser's Warpgate cookies are read and written.
//!
//! Inside, Warpgate reads and writes its session under [`SESSION_COOKIE_NAME`]
//! everywhere (the API's cookie security schemes name it too). The browser
//! never holds that name:
//!
//! - on a TLS listener it holds [`HOST_SESSION_COOKIE_NAME`], a `__Host-`
//!   cookie: `Secure`, `Path=/`, no `Domain`, so it is sent to the host that
//!   set it only, and no other host, a subdomain included, can set or shadow
//!   it. A target page served on its own host therefore never receives the
//!   control plane's session; it gets a session of its own through a handoff
//!   (`crate::handoff`).
//! - on a plain-HTTP loopback listener it holds
//!   [`LOOPBACK_SESSION_COOKIE_NAME`], translated by
//!   `LoopbackSessionCookieMiddleware`, inside this one.
//!
//! On the way in only a byte-exact pair counts. Any other pair whose name,
//! trimmed, percent-decoded and ASCII-case-folded, reads as one of
//! [`WARPGATE_COOKIE_NAMES`] is dropped, because the cookie parser behind the
//! session decodes names, so a sibling host could otherwise plant
//! `%77arpgate-http-session` or `%5F%5FHost-…` (which a browser accepts with a
//! `Domain`) and have it read as the session. Two exact pairs of one name
//! (a shadowing attempt) leave no cookie of that name, and are logged. The
//! old domain-wide [`SESSION_COOKIE_NAME`] cookie is never read: it is dropped
//! and expired, so an upgrade signs every browser in once more.
//!
//! The session is only kept where the browser can hold it safely: on a TLS
//! listener, only when the request is seen as HTTPS (there is no fallback for
//! TLS ended at a proxy that is not trusted to say so); on a loopback
//! listener, only when the Host is `localhost` or an IP literal. Anywhere
//! else the session cookie is neither read nor set, and sign-in fails closed.
//!
//! This never refuses a request.

use std::net::IpAddr;

use cookie::{Cookie, SameSite};
use http::uri::Scheme;
use http::{HeaderValue, header};
use poem::web::Data;
use poem::{Endpoint, FromRequest, IntoResponse, Middleware, Request, Response};
use tracing::warn;
use warpgate_common_http::auth::UnauthenticatedRequestContext;

use crate::common::{
    HANDOFF_COOKIE_NAME, HOST_SESSION_COOKIE_NAME, LOOPBACK_SESSION_COOKIE_NAME,
    SESSION_COOKIE_NAME, WARPGATE_COOKIE_NAMES, decoded_cookie_name, is_localhost_host,
    is_warpgate_cookie_name,
};

/// The listener a request arrived on, as the gate needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Listener {
    /// TLS; `https` is whether the request is seen as HTTPS.
    Tls { https: bool },
    /// Plain HTTP on loopback; `local_host` is whether the Host is `localhost`
    /// or an IP literal.
    Loopback { local_host: bool },
}

impl Listener {
    /// The session cookie's name in the browser, if the session may be used.
    const fn browser_session_name(self) -> Option<&'static str> {
        match self {
            Self::Tls { https: true } => Some(HOST_SESSION_COOKIE_NAME),
            Self::Loopback { local_host: true } => Some(LOOPBACK_SESSION_COOKIE_NAME),
            _ => None,
        }
    }

    /// What the session cookie is called once the gate let it in: on TLS the
    /// internal name; on loopback the browser's, renamed further in.
    const fn inner_session_name(self) -> &'static str {
        match self {
            Self::Tls { .. } => SESSION_COOKIE_NAME,
            Self::Loopback { .. } => LOOPBACK_SESSION_COOKIE_NAME,
        }
    }

    /// Whether the handoff cookie may be used: a `__Host-` cookie, HTTPS only.
    const fn handoff_allowed(self) -> bool {
        matches!(self, Self::Tls { https: true })
    }
}

/// What the gate made of a request's `Cookie` headers.
#[derive(Debug, Default, PartialEq, Eq)]
struct Gated {
    /// The `Cookie` header to pass on (`None`: unchanged; empty: none).
    header: Option<String>,
    /// The old domain-wide session cookie was sent.
    legacy: bool,
    /// Names sent in more than one exact pair; none of their pairs is kept.
    duplicates: Vec<&'static str>,
    /// Look-alike names dropped.
    look_alikes: usize,
}

fn is_ip_literal(host: &str) -> bool {
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    host.parse::<IpAddr>().is_ok()
}

/// Filters the request's cookie pairs for `listener` (see the module docs).
fn gate_request_cookies<S: AsRef<str>>(
    values: impl IntoIterator<Item = S>,
    listener: Listener,
) -> Gated {
    let session_name = listener.browser_session_name();
    let kept_name = |exact: &str| -> Option<&'static str> {
        if Some(exact) == session_name {
            return session_name;
        }
        (exact == HANDOFF_COOKIE_NAME && listener.handoff_allowed()).then_some(HANDOFF_COOKIE_NAME)
    };

    let mut gated = Gated::default();
    let mut changed = false;
    // (exact name, value) of the Warpgate pairs kept, in order.
    let mut ours: Vec<(&'static str, String)> = Vec::new();
    let mut others = Vec::new();
    for value in values {
        for pair in value.as_ref().split(';') {
            let pair = pair.trim();
            if pair.is_empty() {
                continue;
            }
            let (name, cookie_value) = pair.split_once('=').unwrap_or((pair, ""));
            if !is_warpgate_cookie_name(name) {
                others.push(pair.to_owned());
                continue;
            }
            changed = true;
            if let Some(kept) = kept_name(name) {
                ours.push((kept, cookie_value.to_owned()));
            } else if name == SESSION_COOKIE_NAME && matches!(listener, Listener::Tls { .. }) {
                gated.legacy = true;
            } else if !WARPGATE_COOKIE_NAMES.contains(&name) {
                gated.look_alikes += 1;
            }
        }
    }
    if !changed {
        return gated;
    }

    let mut pairs = Vec::new();
    for (name, value) in &ours {
        if ours.iter().filter(|(other, _)| other == name).count() > 1 {
            if !gated.duplicates.contains(name) {
                gated.duplicates.push(name);
            }
            continue;
        }
        let inner = if Some(*name) == session_name {
            listener.inner_session_name()
        } else {
            name
        };
        pairs.push(format!("{inner}={value}"));
    }
    pairs.extend(others);
    gated.header = Some(pairs.join("; "));
    gated
}

/// The browser's form of a `Set-Cookie` for one of Warpgate's cookies, for
/// `listener`: `Some(None)` drops it, `None` leaves it as it is.
fn gate_set_cookie(set_cookie: &str, listener: Listener) -> Option<Option<String>> {
    let mut cookie = Cookie::parse(set_cookie).ok()?;
    let name = decoded_cookie_name(cookie.name()).into_owned();
    if !is_warpgate_cookie_name(&name) {
        return None;
    }
    match listener {
        Listener::Tls { https: true } if name == SESSION_COOKIE_NAME => {
            cookie.set_name(HOST_SESSION_COOKIE_NAME);
            cookie.unset_domain();
            cookie.set_path("/");
            cookie.set_secure(true);
            cookie.set_http_only(true);
            cookie.set_same_site(SameSite::Lax);
            Some(Some(cookie.to_string()))
        }
        Listener::Tls { https: true } if name == HANDOFF_COOKIE_NAME => None,
        Listener::Loopback { local_host: true } if name == LOOPBACK_SESSION_COOKIE_NAME => None,
        // Anything else Warpgate's own: never sent where it cannot be held.
        _ => Some(None),
    }
}

/// Removals of the old domain-wide session cookie: host-only and for the
/// base domain the cookie used to carry.
fn legacy_expiry(base_domain: Option<&str>) -> Vec<String> {
    let mut removals = vec![format!(
        "{SESSION_COOKIE_NAME}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax"
    )];
    if let Some(domain) = base_domain {
        let domain = domain.trim_start_matches('.');
        removals.push(format!(
            "{SESSION_COOKIE_NAME}=; Domain=.{domain}; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax"
        ));
    }
    removals
}

#[derive(Clone)]
pub struct CookieGateMiddleware {
    plain_http: bool,
    /// The base domain the old session cookie was set for, to expire it.
    legacy_domain: Option<String>,
}

impl CookieGateMiddleware {
    pub const fn new(plain_http: bool, legacy_domain: Option<String>) -> Self {
        Self {
            plain_http,
            legacy_domain,
        }
    }
}

impl<E: Endpoint> Middleware<E> for CookieGateMiddleware {
    type Output = CookieGateEndpoint<E>;

    fn transform(&self, inner: E) -> Self::Output {
        CookieGateEndpoint {
            inner,
            gate: self.clone(),
        }
    }
}

pub struct CookieGateEndpoint<E: Endpoint> {
    inner: E,
    gate: CookieGateMiddleware,
}

impl<E: Endpoint> Endpoint for CookieGateEndpoint<E> {
    type Output = Response;

    async fn call(&self, mut req: Request) -> poem::Result<Self::Output> {
        let ctx = Data::<&UnauthenticatedRequestContext>::from_request_without_body(&req).await?;
        let listener = if self.gate.plain_http {
            Listener::Loopback {
                local_host: ctx
                    .trusted_hostname(&req)
                    .is_some_and(|host| is_localhost_host(&host) || is_ip_literal(&host)),
            }
        } else {
            Listener::Tls {
                https: ctx.trusted_proto(&req) == Scheme::HTTPS,
            }
        };

        // Header values that are not text are dropped: poem's jar skips them,
        // and nothing else may read a Warpgate cookie from them.
        let values: Vec<String> = req
            .headers()
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok().map(str::to_owned))
            .collect();
        let gated = gate_request_cookies(&values, listener);
        if !gated.duplicates.is_empty() || gated.look_alikes > 0 {
            warn!(
                duplicates = ?gated.duplicates,
                look_alikes = gated.look_alikes,
                "Dropped Warpgate cookies sent more than once or under another spelling"
            );
        }
        if let Some(cookies) = &gated.header {
            let headers = req.headers_mut();
            headers.remove(header::COOKIE);
            if !cookies.is_empty()
                && let Ok(value) = HeaderValue::from_str(cookies)
            {
                headers.insert(header::COOKIE, value);
            }
        }

        let mut resp = self.inner.call(req).await?.into_response();

        let set_cookies: Vec<HeaderValue> = resp
            .headers_mut()
            .remove(header::SET_COOKIE)
            .into_iter()
            .collect();
        let mut out = Vec::new();
        for value in set_cookies {
            match value
                .to_str()
                .ok()
                .and_then(|v| gate_set_cookie(v, listener))
            {
                None => out.push(value),
                Some(Some(rewritten)) => {
                    if let Ok(rewritten) = HeaderValue::from_str(&rewritten) {
                        out.push(rewritten);
                    }
                }
                Some(None) => {}
            }
        }
        let headers = resp.headers_mut();
        headers.remove(header::SET_COOKIE);
        for value in out {
            headers.append(header::SET_COOKIE, value);
        }
        if gated.legacy {
            for removal in legacy_expiry(self.gate.legacy_domain.as_deref()) {
                if let Ok(removal) = HeaderValue::from_str(&removal) {
                    headers.append(header::SET_COOKIE, removal);
                }
            }
        }
        Ok(resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HTTPS: Listener = Listener::Tls { https: true };
    const HTTP_BEHIND_PROXY: Listener = Listener::Tls { https: false };
    const LOOPBACK: Listener = Listener::Loopback { local_host: true };
    const LOOPBACK_EXTERNAL: Listener = Listener::Loopback { local_host: false };

    fn gated(header: &str, listener: Listener) -> Gated {
        gate_request_cookies([header], listener)
    }

    #[test]
    fn unit_gate_renames_the_host_cookie_inward() {
        let g = gated("a=1; __Host-warpgate-http-session=S; b=2", HTTPS);
        assert_eq!(
            g.header.as_deref(),
            Some("warpgate-http-session=S; a=1; b=2")
        );
        assert!(!g.legacy && g.duplicates.is_empty());
    }

    #[test]
    fn unit_gate_leaves_other_cookies_alone() {
        assert_eq!(gated("a=1; b=2", HTTPS), Gated::default());
    }

    /// The old domain-wide cookie is never read, only noticed (to expire it).
    #[test]
    fn unit_gate_never_reads_the_legacy_cookie() {
        let g = gated("warpgate-http-session=OLD", HTTPS);
        assert_eq!(g.header.as_deref(), Some(""));
        assert!(g.legacy);
    }

    /// Spellings a sibling host can plant, which poem would decode to a
    /// Warpgate name.
    #[test]
    fn unit_gate_drops_look_alike_names() {
        for planted in [
            "%77arpgate-http-session=A",
            "%5F%5FHost-warpgate-http-session=A",
            "__host-warpgate-http-session=A",
            " __Host-warpgate-http-session =A",
            "__Host-warpgate-http-session%20=A",
            "__Host-Warpgate-Handoff=A",
            "warpgate-loopback-session=A",
        ] {
            let g = gated(&format!("{planted}; __Host-warpgate-http-session=S"), HTTPS);
            assert_eq!(
                g.header.as_deref(),
                Some("warpgate-http-session=S"),
                "{planted}"
            );
        }
    }

    /// A second exact pair (another path's cookie shadowing ours) leaves no
    /// session at all rather than picking one.
    #[test]
    fn unit_gate_two_exact_session_pairs_leave_none() {
        let g = gated(
            "__Host-warpgate-http-session=ATTACKER; __Host-warpgate-http-session=S; a=1",
            HTTPS,
        );
        assert_eq!(g.header.as_deref(), Some("a=1"));
        assert_eq!(g.duplicates, vec![HOST_SESSION_COOKIE_NAME]);
        let g = gate_request_cookies(
            ["__Host-warpgate-handoff=N", "__Host-warpgate-handoff=M"],
            HTTPS,
        );
        assert_eq!(g.header.as_deref(), Some(""));
    }

    #[test]
    fn unit_gate_keeps_the_handoff_cookie_on_https_only() {
        let g = gated("__Host-warpgate-handoff=N", HTTPS);
        assert_eq!(g.header.as_deref(), Some("__Host-warpgate-handoff=N"));
        let g = gated("__Host-warpgate-handoff=N", HTTP_BEHIND_PROXY);
        assert_eq!(g.header.as_deref(), Some(""));
    }

    /// TLS ended at a proxy that Warpgate does not see as HTTPS: no session.
    #[test]
    fn unit_gate_fails_closed_unless_https() {
        let g = gated("__Host-warpgate-http-session=S", HTTP_BEHIND_PROXY);
        assert_eq!(g.header.as_deref(), Some(""));
        let session = "warpgate-http-session=S; Path=/; HttpOnly";
        assert_eq!(gate_set_cookie(session, HTTP_BEHIND_PROXY), Some(None));
    }

    #[test]
    fn unit_gate_loopback_cookie_only_on_a_local_host() {
        let g = gated("warpgate-loopback-session=S", LOOPBACK);
        assert_eq!(g.header.as_deref(), Some("warpgate-loopback-session=S"));
        let g = gated("warpgate-loopback-session=S", LOOPBACK_EXTERNAL);
        assert_eq!(g.header.as_deref(), Some(""));
        let set = "warpgate-loopback-session=S; Path=/; HttpOnly; SameSite=Strict";
        assert_eq!(gate_set_cookie(set, LOOPBACK), None);
        assert_eq!(gate_set_cookie(set, LOOPBACK_EXTERNAL), Some(None));
        // The TLS names are not loopback's.
        let g = gated(
            "__Host-warpgate-http-session=S; warpgate-http-session=T",
            LOOPBACK,
        );
        assert_eq!(g.header.as_deref(), Some(""));
    }

    #[test]
    fn unit_gate_issues_a_host_only_session_cookie() {
        let set = "warpgate-http-session=S; Domain=.warp.example; Path=/@warpgate; SameSite=None; Max-Age=60";
        let out = gate_set_cookie(set, HTTPS).unwrap().unwrap();
        let cookie = Cookie::parse(out).unwrap();
        assert_eq!(cookie.name(), HOST_SESSION_COOKIE_NAME);
        assert_eq!(cookie.value(), "S");
        assert_eq!(cookie.domain(), None);
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.secure(), Some(true));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
        assert_eq!(cookie.max_age(), Some(cookie::time::Duration::seconds(60)));
    }

    #[test]
    fn unit_gate_leaves_other_set_cookies_alone() {
        assert_eq!(gate_set_cookie("a=1; Path=/", HTTPS), None);
        assert_eq!(gate_set_cookie("a=1; Path=/", HTTP_BEHIND_PROXY), None);
    }

    #[test]
    fn unit_gate_expires_the_legacy_cookie_for_its_domain() {
        let removals = legacy_expiry(Some(".warp.example"));
        let cookies: Vec<_> = removals
            .iter()
            .map(|c| Cookie::parse(c.as_str()).unwrap())
            .collect();
        assert!(cookies.iter().all(|c| c.name() == SESSION_COOKIE_NAME
            && c.max_age() == Some(cookie::time::Duration::ZERO)));
        assert_eq!(cookies[0].domain(), None);
        assert_eq!(cookies[1].domain(), Some("warp.example"));
    }

    #[test]
    fn unit_gate_ip_literals() {
        assert!(is_ip_literal("127.0.0.1") && is_ip_literal("[::1]") && is_ip_literal("10.0.0.1"));
        assert!(!is_ip_literal("warp.example"));
    }
}
