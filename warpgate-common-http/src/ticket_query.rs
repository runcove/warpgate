//! The `warpgate-ticket` query parameter a ticket can be presented in, and
//! keeping its value out of what leaves Warpgate: the headers forwarded to a
//! target and the page to return to after login. Log lines use
//! [`crate::logging::redacted_uri`].

use url::form_urlencoded;

/// The query parameter a target-host handoff token travels in (the HTTP
/// protocol's handoff). Kept out of the same places as a ticket.
pub const HANDOFF_QUERY_PARAM: &str = "warpgate-handoff";

/// The query parameter the handoff challenge travels in to the control
/// plane's handoff start (`/@warpgate/handoff/start`). Elsewhere a parameter
/// of that name is an application's own. Log lines keep its value out as
/// they keep out every query value ([`crate::logging::redacted_uri`]).
pub const HANDOFF_CHALLENGE_QUERY_PARAM: &str = "challenge";

/// Whether a decoded query key carries a credential that must not leave
/// Warpgate: `warpgate-ticket` (the parameter `TicketMiddleware` reads a
/// ticket from) or [`HANDOFF_QUERY_PARAM`].
pub fn is_credential_query_key(key: &str) -> bool {
    key == "warpgate-ticket" || key == HANDOFF_QUERY_PARAM
}

/// True for a `key=value` pair of a query string whose key, once decoded, is
/// a credential's ([`is_credential_query_key`]).
pub fn is_ticket_query_pair(pair: &str) -> bool {
    form_urlencoded::parse(pair.as_bytes())
        .next()
        .is_some_and(|(key, _)| is_credential_query_key(&key))
}

/// `url` with every `warpgate-ticket` pair replaced by `replacement`, or
/// removed when it is `None`. Everything else -- the other parameters, in
/// their order and their original encoding, and any fragment -- is kept
/// exactly as it was, and a URL without the parameter is returned unchanged.
fn replace_ticket_query_pairs(url: &str, replacement: Option<&str>) -> String {
    let (before_fragment, fragment) = match url.split_once('#') {
        Some((before, fragment)) => (before, Some(fragment)),
        None => (url, None),
    };
    let Some((base, query)) = before_fragment.split_once('?') else {
        return url.to_owned();
    };
    if !query.split('&').any(is_ticket_query_pair) {
        return url.to_owned();
    }
    let query = query
        .split('&')
        .filter_map(|pair| {
            if is_ticket_query_pair(pair) {
                replacement
            } else {
                Some(pair)
            }
        })
        .collect::<Vec<_>>()
        .join("&");
    let mut rewritten = base.to_owned();
    if !query.is_empty() {
        rewritten.push('?');
        rewritten.push_str(&query);
    }
    if let Some(fragment) = fragment {
        rewritten.push('#');
        rewritten.push_str(fragment);
    }
    rewritten
}

/// `url` with every `warpgate-ticket` (and handoff token) query parameter
/// removed, the rest kept
/// exactly (see [`replace_ticket_query_pairs`]).
pub fn without_ticket_query_param(url: &str) -> String {
    replace_ticket_query_pairs(url, None)
}

#[cfg(test)]
mod tests {
    use super::without_ticket_query_param;

    const SECRET: &str = "s3cr3t-ticket-value";

    /// A handoff token goes the same way as a ticket.
    #[test]
    fn removing_drops_a_handoff_token_too() {
        assert_eq!(
            without_ticket_query_param("/@warpgate/handoff?warpgate-handoff=tok&a=1"),
            "/@warpgate/handoff?a=1"
        );
        assert_eq!(
            without_ticket_query_param("/x?warpgate%2Dhandoff=tok"),
            "/x"
        );
    }

    /// Every ticket pair goes, however its key is encoded; the other
    /// parameters and the fragment are kept exactly.
    #[test]
    fn removing_keeps_everything_but_the_ticket() {
        let url = format!("https://app.example/p?a=1&warpgate-ticket={SECRET}#frag");
        assert_eq!(
            without_ticket_query_param(&url),
            "https://app.example/p?a=1#frag"
        );
        let url = format!("/app?a=1&warpgate%2Dticket={SECRET}&b=two%20words");
        assert_eq!(without_ticket_query_param(&url), "/app?a=1&b=two%20words");
        assert_eq!(
            without_ticket_query_param("/app?q=warpgate-ticket"),
            "/app?q=warpgate-ticket"
        );
    }
}
