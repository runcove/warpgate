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
//! The headers are read as bytes, and the Warpgate pairs kept are passed on
//! in a `Cookie` header of their own, before the others: poem's jar skips a
//! header that is not visible ASCII, so a cookie with a UTF-8 value planted
//! for the parent domain could otherwise hide the session sent beside it.
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

/// The `Cookie` headers the gate passes on in place of the request's.
#[derive(Debug, PartialEq, Eq)]
struct Rewrite {
    /// The Warpgate pairs kept, under their inner names: visible ASCII, so
    /// poem's jar, which skips any header that is not, always reads them.
    ours: String,
    /// Every other pair, as the browser sent it (perhaps not ASCII).
    others: Vec<u8>,
}

impl Rewrite {
    /// The headers to send on, Warpgate's first (poem's jar keeps the first
    /// pair of a name); none for an empty part.
    fn header_values(&self) -> Vec<HeaderValue> {
        let ours = (!self.ours.is_empty())
            .then(|| HeaderValue::from_str(&self.ours).ok())
            .flatten();
        let others = (!self.others.is_empty())
            .then(|| HeaderValue::from_bytes(&self.others).ok())
            .flatten();
        ours.into_iter().chain(others).collect()
    }
}

/// What the gate made of a request's `Cookie` headers.
#[derive(Debug, Default, PartialEq, Eq)]
struct Gated {
    /// The headers to pass on instead (`None`: unchanged).
    rewrite: Option<Rewrite>,
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
/// Works on the header bytes: a header that is not visible ASCII is read
/// too, so that no pair in it can hide the session.
fn gate_request_cookies<S: AsRef<[u8]>>(
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
    let mut others: Vec<&[u8]> = Vec::new();
    let values: Vec<S> = values.into_iter().collect();
    for value in &values {
        for pair in value.as_ref().split(|byte| *byte == b';') {
            let pair = pair.trim_ascii();
            if pair.is_empty() {
                continue;
            }
            // The name, and the value after the first `=` (none without one).
            let mut parts = pair.splitn(2, |byte| *byte == b'=');
            let name = parts.next().unwrap_or_default();
            let cookie_value = parts.next().unwrap_or_default();
            let name = String::from_utf8_lossy(name);
            if !is_warpgate_cookie_name(&name) {
                others.push(pair);
                continue;
            }
            changed = true;
            let kept = kept_name(&name).filter(|_| cookie_value.iter().all(u8::is_ascii_graphic));
            if let Some(kept) = kept {
                ours.push((kept, String::from_utf8_lossy(cookie_value).into_owned()));
            } else if name == SESSION_COOKIE_NAME && matches!(listener, Listener::Tls { .. }) {
                gated.legacy = true;
            } else if !WARPGATE_COOKIE_NAMES.contains(&name.as_ref()) {
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
    gated.rewrite = Some(Rewrite {
        ours: pairs.join("; "),
        others: others.join(&b"; "[..]),
    });
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

        // Read as bytes: poem's jar skips a header that is not visible
        // ASCII, so a planted pair with a UTF-8 value must not take the
        // session in the same header down with it.
        let values: Vec<Vec<u8>> = req
            .headers()
            .get_all(header::COOKIE)
            .iter()
            .map(|value| value.as_bytes().to_owned())
            .collect();
        let gated = gate_request_cookies(&values, listener);
        if !gated.duplicates.is_empty() || gated.look_alikes > 0 {
            warn!(
                duplicates = ?gated.duplicates,
                look_alikes = gated.look_alikes,
                "Dropped Warpgate cookies sent more than once or under another spelling"
            );
        }
        if let Some(rewrite) = &gated.rewrite {
            let headers = req.headers_mut();
            headers.remove(header::COOKIE);
            for value in rewrite.header_values() {
                headers.append(header::COOKIE, value);
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
        gate_request_cookies([header.as_bytes()], listener)
    }

    /// The headers the gate passes on, joined as one, for comparison.
    fn joined(g: &Gated) -> Option<String> {
        let rewrite = g.rewrite.as_ref()?;
        let others = String::from_utf8_lossy(&rewrite.others);
        Some(
            [rewrite.ours.as_str(), &others]
                .into_iter()
                .filter(|part| !part.is_empty())
                .collect::<Vec<_>>()
                .join("; "),
        )
    }

    #[test]
    fn unit_gate_renames_the_host_cookie_inward() {
        let g = gated("a=1; __Host-warpgate-http-session=S; b=2", HTTPS);
        assert_eq!(
            joined(&g).as_deref(),
            Some("warpgate-http-session=S; a=1; b=2")
        );
        assert!(!g.legacy && g.duplicates.is_empty());
    }

    /// A pair splits at its first `=`: the rest, `=` included, is the
    /// value, and a pair without one is a name with an empty value.
    #[test]
    fn unit_gate_splits_a_pair_at_its_first_equals_sign() {
        let g = gated("a=1=2; __Host-warpgate-http-session=S=x; b", HTTPS);
        assert_eq!(
            joined(&g).as_deref(),
            Some("warpgate-http-session=S=x; a=1=2; b")
        );
        let g = gated("__Host-warpgate-http-session; b=2", HTTPS);
        assert_eq!(joined(&g).as_deref(), Some("warpgate-http-session=; b=2"));
    }

    #[test]
    fn unit_gate_leaves_other_cookies_alone() {
        assert_eq!(gated("a=1; b=2", HTTPS), Gated::default());
    }

    /// The old domain-wide cookie is never read, only noticed (to expire it).
    #[test]
    fn unit_gate_never_reads_the_legacy_cookie() {
        let g = gated("warpgate-http-session=OLD", HTTPS);
        assert_eq!(joined(&g).as_deref(), Some(""));
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
                joined(&g).as_deref(),
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
        assert_eq!(joined(&g).as_deref(), Some("a=1"));
        assert_eq!(g.duplicates, vec![HOST_SESSION_COOKIE_NAME]);
        let g = gate_request_cookies(
            [
                b"__Host-warpgate-handoff=N".as_slice(),
                b"__Host-warpgate-handoff=M",
            ],
            HTTPS,
        );
        assert_eq!(joined(&g).as_deref(), Some(""));
    }

    #[test]
    fn unit_gate_keeps_the_handoff_cookie_on_https_only() {
        let g = gated("__Host-warpgate-handoff=N", HTTPS);
        assert_eq!(joined(&g).as_deref(), Some("__Host-warpgate-handoff=N"));
        let g = gated("__Host-warpgate-handoff=N", HTTP_BEHIND_PROXY);
        assert_eq!(joined(&g).as_deref(), Some(""));
    }

    /// TLS ended at a proxy that Warpgate does not see as HTTPS: no session.
    #[test]
    fn unit_gate_fails_closed_unless_https() {
        let g = gated("__Host-warpgate-http-session=S", HTTP_BEHIND_PROXY);
        assert_eq!(joined(&g).as_deref(), Some(""));
        let session = "warpgate-http-session=S; Path=/; HttpOnly";
        assert_eq!(gate_set_cookie(session, HTTP_BEHIND_PROXY), Some(None));
    }

    #[test]
    fn unit_gate_loopback_cookie_only_on_a_local_host() {
        let g = gated("warpgate-loopback-session=S", LOOPBACK);
        assert_eq!(joined(&g).as_deref(), Some("warpgate-loopback-session=S"));
        let g = gated("warpgate-loopback-session=S", LOOPBACK_EXTERNAL);
        assert_eq!(joined(&g).as_deref(), Some(""));
        let set = "warpgate-loopback-session=S; Path=/; HttpOnly; SameSite=Strict";
        assert_eq!(gate_set_cookie(set, LOOPBACK), None);
        assert_eq!(gate_set_cookie(set, LOOPBACK_EXTERNAL), Some(None));
        // The TLS names are not loopback's.
        let g = gated(
            "__Host-warpgate-http-session=S; warpgate-http-session=T",
            LOOPBACK,
        );
        assert_eq!(joined(&g).as_deref(), Some(""));
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

    /// On HTTPS the session cookie leaves `SameSite=Lax` whatever attribute
    /// or `Domain` it was minted with, on every host.
    #[test]
    fn unit_gate_https_session_cookie_is_always_lax() {
        for set in [
            "warpgate-http-session=S; Path=/",
            "warpgate-http-session=S; Path=/; SameSite=None",
            "warpgate-http-session=S; Path=/; SameSite=Strict",
            "warpgate-http-session=S; Path=/; SameSite=Lax",
            "warpgate-http-session=S; Domain=.warp.example; Path=/; SameSite=None",
            "warpgate-http-session=S; Domain=localhost; Path=/",
        ] {
            let out = gate_set_cookie(set, HTTPS).unwrap().unwrap();
            let cookie = Cookie::parse(out).unwrap();
            assert_eq!(cookie.same_site(), Some(SameSite::Lax), "{set}");
        }
    }

    /// The cookie as `ServerSession` mints it, before the gate: `Lax` on
    /// every listener and host.
    #[test]
    fn unit_minted_session_cookie_is_lax() {
        let jar = poem::web::cookie::CookieJar::default();
        crate::common::session_cookie_config().set_cookie_value(&jar, "v");
        let c = jar.get(SESSION_COOKIE_NAME).expect("session cookie set");
        assert_eq!(c.same_site(), Some(SameSite::Lax));
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

    /// A `Cookie` header that is not visible ASCII (a cookie planted for the
    /// parent domain with a UTF-8 value) is skipped whole by poem's jar, so
    /// the session in it would be lost: the gate reads the bytes and passes
    /// Warpgate's pairs on in their own ASCII header, first.
    #[test]
    fn unit_gate_reads_the_session_out_of_a_non_ascii_header() {
        let sent = "pref=caf\u{e9}; __Host-warpgate-http-session=S; b=2";
        let g = gate_request_cookies([sent.as_bytes()], HTTPS);
        let rewrite = g.rewrite.unwrap();
        assert_eq!(rewrite.ours, "warpgate-http-session=S");
        assert_eq!(rewrite.others, "pref=caf\u{e9}; b=2".as_bytes());
        let values = rewrite.header_values();
        assert_eq!(values.len(), 2);
        assert_eq!(values[0].to_str().unwrap(), "warpgate-http-session=S");
    }

    /// A Warpgate pair whose value is not visible ASCII is never ours.
    #[test]
    fn unit_gate_drops_a_session_pair_with_a_non_ascii_value() {
        let sent = "__Host-warpgate-http-session=caf\u{e9}";
        let g = gate_request_cookies([sent.as_bytes()], HTTPS);
        assert_eq!(joined(&g).as_deref(), Some(""));
    }

    #[test]
    fn unit_gate_ip_literals() {
        assert!(is_ip_literal("127.0.0.1") && is_ip_literal("[::1]") && is_ip_literal("10.0.0.1"));
        assert!(!is_ip_literal("warp.example"));
    }
}
