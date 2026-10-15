//! The page a browser gets, in place of the redirect to the login form, when it
//! opens a target without a session and `http.unauthenticated_message` is set.

use http::{StatusCode, header};
use poem::{Request, Response};
use warpgate_common_http::ext::is_navigation_request;

use crate::catchall::is_warpgate_management_path;

/// The not-signed-in page for an unauthenticated request, or `None` where the
/// request keeps its current answer: no message is configured, or it is not a
/// browser navigation (API calls and websocket upgrades keep their 401), or it
/// is for a Warpgate management path.
///
/// The page shows the operator's message only, never anything from the
/// request, and is answered by Warpgate itself: nothing reaches the target.
pub(crate) fn unauthenticated_page(req: &Request, message: Option<&str>) -> Option<Response> {
    let message = message?;
    let websocket_upgrade = req
        .header(header::UPGRADE)
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"));
    if websocket_upgrade
        || !is_navigation_request(req)
        || is_warpgate_management_path(req.uri().path())
    {
        return None;
    }
    Some(
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .content_type("text/html; charset=utf-8")
            .header(header::CACHE_CONTROL, "no-store")
            .header(header::CONTENT_SECURITY_POLICY, "default-src 'none'")
            .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
            .body(page_html(message)),
    )
}

fn page_html(message: &str) -> String {
    let message = message
        .lines()
        .map(escape_html)
        .collect::<Vec<_>>()
        .join("<br>\n");
    format!(
        "<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>Warpgate</title>\n</head>\n<body>\n<p>{message}</p>\n</body>\n</html>\n"
    )
}

fn escape_html(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#x27;"),
            c => escaped.push(c),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use http::StatusCode;
    use poem::Request;

    use super::unauthenticated_page;

    const BROWSER_ACCEPT: &str = "text/html,application/xhtml+xml,*/*;q=0.8";

    fn navigation(uri: &str) -> Request {
        Request::builder()
            .uri_str(uri)
            .header("accept", BROWSER_ACCEPT)
            .header("sec-fetch-mode", "navigate")
            .finish()
    }

    async fn body(resp: poem::Response) -> String {
        resp.into_body().into_string().await.unwrap()
    }

    #[tokio::test]
    async fn unit_unauthenticated_page_shows_the_message_escaped() {
        let resp = unauthenticated_page(
            &navigation("/app"),
            Some("<script>alert('x')</script> & \"more\"\nSecond line"),
        )
        .expect("a browser navigation gets the page");

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(resp.content_type(), Some("text/html; charset=utf-8"));
        assert_eq!(resp.header("cache-control"), Some("no-store"));
        assert_eq!(
            resp.header("content-security-policy"),
            Some("default-src 'none'")
        );
        let html = body(resp).await;
        assert!(html.contains(
            "&lt;script&gt;alert(&#x27;x&#x27;)&lt;/script&gt; &amp; &quot;more&quot;<br>\nSecond line"
        ));
        assert!(!html.contains("<script>"));
    }

    #[tokio::test]
    async fn unit_unauthenticated_page_reflects_nothing_from_the_request() {
        let resp = unauthenticated_page(
            &navigation("/secret-path?q=%3Cb%3Einjected%3C%2Fb%3E&warpgate-target=prod"),
            Some("Not signed in."),
        )
        .expect("a browser navigation gets the page");

        let html = body(resp).await;
        assert!(html.contains("Not signed in."));
        for leaked in ["secret-path", "injected", "warpgate-target", "prod", "q="] {
            assert!(!html.contains(leaked), "{leaked} reflected");
        }
    }

    #[test]
    fn unit_unauthenticated_page_off_without_a_message() {
        assert!(unauthenticated_page(&navigation("/app"), None).is_none());
    }

    #[test]
    fn unit_unauthenticated_page_not_for_api_requests() {
        let cases = [
            (None, None),
            (Some("*/*"), None),
            (Some("application/json"), Some("cors")),
            (Some(BROWSER_ACCEPT), Some("cors")),
            (Some(BROWSER_ACCEPT), Some("same-origin")),
        ];
        for (accept, mode) in cases {
            let mut req = Request::builder().uri_str("/api/data");
            if let Some(accept) = accept {
                req = req.header("accept", accept);
            }
            if let Some(mode) = mode {
                req = req.header("sec-fetch-mode", mode);
            }
            assert!(
                unauthenticated_page(&req.finish(), Some("Not signed in.")).is_none(),
                "{accept:?} {mode:?}"
            );
        }
    }

    #[test]
    fn unit_unauthenticated_page_not_for_websocket_upgrades() {
        for accept in [None, Some(BROWSER_ACCEPT)] {
            let mut req = Request::builder()
                .uri_str("/socket")
                .header("connection", "Upgrade")
                .header("upgrade", "websocket")
                .header("sec-fetch-mode", "websocket");
            if let Some(accept) = accept {
                req = req.header("accept", accept);
            }
            assert!(
                unauthenticated_page(&req.finish(), Some("Not signed in.")).is_none(),
                "{accept:?}"
            );
        }
        // Even one that would otherwise pass as a navigation.
        let req = Request::builder()
            .uri_str("/socket")
            .header("accept", BROWSER_ACCEPT)
            .header("upgrade", "WebSocket")
            .finish();
        assert!(unauthenticated_page(&req, Some("Not signed in.")).is_none());
    }

    #[test]
    fn unit_unauthenticated_page_not_for_management_paths() {
        for path in ["/@warpgate", "/@warpgate/admin", "/_warpgate/api/info"] {
            assert!(
                unauthenticated_page(&navigation(path), Some("Not signed in.")).is_none(),
                "{path}"
            );
        }
    }
}
