//! The `warpgate-ticket` query parameter a ticket can be presented in, and
//! keeping its value out of what leaves Warpgate: the headers forwarded to a
//! target and the lines written to the log.

use poem::http::Uri;
use url::form_urlencoded;

/// What a logged address shows in place of a ticket's value.
const REDACTED: &str = "warpgate-ticket=[REDACTED]";

/// True for a `key=value` pair of a query string whose key, once decoded, is
/// `warpgate-ticket` -- the parameter `TicketMiddleware` reads a ticket from.
pub fn is_ticket_query_pair(pair: &str) -> bool {
    form_urlencoded::parse(pair.as_bytes())
        .next()
        .is_some_and(|(key, _)| key == "warpgate-ticket")
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

/// `url` with every `warpgate-ticket` query parameter removed, the rest kept
/// exactly (see [`replace_ticket_query_pairs`]).
pub fn without_ticket_query_param(url: &str) -> String {
    replace_ticket_query_pairs(url, None)
}

/// `url` with the value of every `warpgate-ticket` query parameter replaced by
/// a marker, the rest kept exactly: a log line still shows that a ticket was
/// presented, never the ticket.
pub fn with_ticket_query_param_redacted(url: &str) -> String {
    replace_ticket_query_pairs(url, Some(REDACTED))
}

/// A request address as it may be written to the log (see
/// [`with_ticket_query_param_redacted`]).
pub fn loggable_uri(uri: &Uri) -> String {
    with_ticket_query_param_redacted(&uri.to_string())
}

#[cfg(test)]
mod tests {
    use poem::http::Uri;

    use super::{loggable_uri, with_ticket_query_param_redacted, without_ticket_query_param};

    const SECRET: &str = "s3cr3t-ticket-value";

    /// A logged address never contains the ticket's value, wherever the
    /// parameter sits and however its key is encoded, and still shows that a
    /// ticket was presented; the other parameters are kept exactly.
    #[test]
    fn a_logged_uri_never_contains_the_ticket() {
        for (uri, expected) in [
            (
                format!("/?warpgate-ticket={SECRET}"),
                "/?warpgate-ticket=[REDACTED]",
            ),
            (
                format!("/app?a=1&warpgate-ticket={SECRET}&b=two%20words"),
                "/app?a=1&warpgate-ticket=[REDACTED]&b=two%20words",
            ),
            (
                format!("https://app.example:8443/x?warpgate%2Dticket={SECRET}"),
                "https://app.example:8443/x?warpgate-ticket=[REDACTED]",
            ),
            (
                format!("/?warpgate-ticket={SECRET}&warpgate-ticket={SECRET}"),
                "/?warpgate-ticket=[REDACTED]&warpgate-ticket=[REDACTED]",
            ),
        ] {
            let uri: Uri = uri.parse().unwrap();
            let logged = loggable_uri(&uri);
            assert!(!logged.contains(SECRET), "{uri} logged as {logged}");
            assert_eq!(logged, expected, "{uri}");
        }
    }

    /// An address without the parameter is logged exactly as it came in.
    #[test]
    fn a_uri_without_a_ticket_is_logged_unchanged() {
        for uri in [
            "/",
            "/app?a=1&b=two%20words",
            "/app?q=warpgate-ticket",
            "/app?not-warpgate-ticket=1&warpgate-tickets=2",
            "/app?warpgate-target=app",
        ] {
            let parsed: Uri = uri.parse().unwrap();
            assert_eq!(loggable_uri(&parsed), uri);
        }
    }

    /// Removing and redacting agree on what a ticket parameter is.
    #[test]
    fn removing_and_redacting_treat_the_same_pairs_as_tickets() {
        let url = format!("https://app.example/p?a=1&warpgate-ticket={SECRET}#frag");
        assert_eq!(
            without_ticket_query_param(&url),
            "https://app.example/p?a=1#frag"
        );
        assert_eq!(
            with_ticket_query_param_redacted(&url),
            "https://app.example/p?a=1&warpgate-ticket=[REDACTED]#frag"
        );
    }
}
