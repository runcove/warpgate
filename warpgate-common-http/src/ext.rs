use poem::FromRequest;
use poem::http::HeaderName;
use poem::http::header::ACCEPT;
use poem::http::uri::{Authority, Scheme};
use poem::web::Data;
use url::Url;
use warpgate_common::WarpgateError;

use crate::auth::UnauthenticatedRequestContext;

pub async fn construct_external_url(
    for_request: Option<&poem::Request>,
    config: &warpgate_common::WarpgateConfig,
    domain_whitelist: Option<&[String]>,
) -> Result<Url, WarpgateError> {
    let ctx = if let Some(for_request) = for_request {
        Some(
            Data::<&UnauthenticatedRequestContext>::from_request_without_body(for_request)
                .await
                .map_err(|e| WarpgateError::Other(Box::new(e)))?,
        )
    } else {
        None
    };

    let Some((Some(scheme), Some(host), port)) = (if let Some(for_request) = for_request {
        let ctx = ctx
            .as_ref()
            .ok_or_else(|| WarpgateError::InconsistentState("no ctx in request".into()))?;
        Some((
            Some(ctx.trusted_proto(for_request)),
            ctx.trusted_hostname(for_request),
            ctx.trusted_port(for_request),
        ))
    } else {
        config.external_host_name().map(|external_host| {
            (
                // The listener's own scheme: plain HTTP only when it serves no TLS.
                Some(if config.store.http.plain_http_on_loopback {
                    Scheme::HTTP
                } else {
                    Scheme::HTTPS
                }),
                Some(external_host),
                config
                    .store
                    .http
                    .external_port
                    .or_else(|| Some(config.store.http.listen.port())),
            )
        })
    }) else {
        return Err(WarpgateError::ExternalHostUnknown);
    };

    if let Some(list) = domain_whitelist
        && !list.contains(&host)
    {
        return Err(WarpgateError::ExternalHostNotWhitelisted(
            host,
            list.to_vec(),
        ));
    }

    origin_url(&scheme, &host, port)
}

/// The URL of the control-plane host, where the `/@warpgate` routes (including
/// the browser approval page) are served: `http.external_host` when set, else
/// the global external host. A port written in `http.external_host` wins over
/// `http.external_port` and the listen port.
pub async fn construct_control_plane_url(
    config: &warpgate_common::WarpgateConfig,
) -> Result<Url, WarpgateError> {
    let Some(authority) = config
        .store
        .http
        .external_host
        .as_deref()
        .and_then(|value| value.parse::<Authority>().ok())
    else {
        return construct_external_url(None, config, None).await;
    };
    let host = config
        .control_plane_host()
        .ok_or(WarpgateError::ExternalHostUnknown)?;
    let scheme = if config.store.http.plain_http_on_loopback {
        Scheme::HTTP
    } else {
        Scheme::HTTPS
    };
    let port = authority
        .port_u16()
        .or(config.store.http.external_port)
        .unwrap_or_else(|| config.store.http.listen.port());
    origin_url(&scheme, &host, Some(port))
}

fn origin_url(scheme: &Scheme, host: &str, port: Option<u16>) -> Result<Url, WarpgateError> {
    let mut url = format!("{scheme}://{host}");
    if let Some(port) = port {
        // can't `match` `Scheme`
        if *scheme == Scheme::HTTP && port != 80 || *scheme == Scheme::HTTPS && port != 443 {
            url = format!("{url}:{port}");
        }
    }
    Url::parse(&url).map_err(WarpgateError::UrlParse)
}

pub fn is_navigation_request(req: &poem::Request) -> bool {
    let headers = req.headers();
    let accepts_html = headers
        .get(ACCEPT)
        .and_then(|accept| accept.to_str().ok())
        .is_some_and(|accept| accept.contains("text/html"));
    let navigates = headers
        .get(HeaderName::from_static("sec-fetch-mode"))
        .is_none_or(|mode| mode == "navigate");
    accepts_html && navigates
}

#[cfg(test)]
mod tests {
    use warpgate_common::{Secret, WarpgateConfig, WarpgateConfigStore};

    use super::*;

    fn test_config(external_host: Option<&str>) -> WarpgateConfig {
        let mut config = WarpgateConfig {
            store: WarpgateConfigStore::default(),
        };
        config.store.external_host = external_host.map(str::to_owned);
        config.store.database_url = Secret::new("sqlite:ext-test".to_owned());
        config
    }

    #[tokio::test]
    async fn construct_external_url_uses_config_external_host_without_request() {
        let config = test_config(Some("config.example"));

        let url = construct_external_url(None, &config, None)
            .await
            .expect("external url");

        assert_eq!(url.as_str(), "https://config.example:8888/");
    }

    #[tokio::test]
    async fn construct_external_url_is_http_on_a_plain_http_listener() {
        let mut config = test_config(Some("localhost"));
        config.store.http.plain_http_on_loopback = true;

        let url = construct_external_url(None, &config, None)
            .await
            .expect("external url");

        assert_eq!(url.as_str(), "http://localhost:8888/");
    }

    fn control_plane_config(http_external_host: Option<&str>) -> WarpgateConfig {
        let mut config = test_config(Some("config.example"));
        config.store.http.external_host = http_external_host.map(str::to_owned);
        config
    }

    #[tokio::test]
    async fn construct_control_plane_url_matches_external_url_without_http_external_host() {
        let config = control_plane_config(None);

        let url = construct_control_plane_url(&config)
            .await
            .expect("control plane url");
        let external = construct_external_url(None, &config, None)
            .await
            .expect("external url");

        assert_eq!(url, external);
    }

    #[tokio::test]
    async fn construct_control_plane_url_uses_http_external_host_without_port() {
        let config = control_plane_config(Some("admin.example"));

        let url = construct_control_plane_url(&config)
            .await
            .expect("control plane url");

        assert_eq!(url.as_str(), "https://admin.example:8888/");
    }

    #[tokio::test]
    async fn construct_control_plane_url_prefers_the_port_in_http_external_host() {
        let mut config = control_plane_config(Some("admin.example:8443"));
        config.store.http.external_port = Some(9443);

        let url = construct_control_plane_url(&config)
            .await
            .expect("control plane url");

        assert_eq!(url.as_str(), "https://admin.example:8443/");
    }

    #[tokio::test]
    async fn construct_control_plane_url_keeps_the_brackets_of_an_ipv6_http_external_host() {
        let config = control_plane_config(Some("[::1]:8443"));

        let url = construct_control_plane_url(&config)
            .await
            .expect("control plane url");

        assert_eq!(url.as_str(), "https://[::1]:8443/");
    }

    #[tokio::test]
    async fn construct_control_plane_url_falls_back_to_external_port() {
        let mut config = control_plane_config(Some("admin.example"));
        config.store.http.external_port = Some(9443);

        let url = construct_control_plane_url(&config)
            .await
            .expect("control plane url");

        assert_eq!(url.as_str(), "https://admin.example:9443/");
    }

    #[tokio::test]
    async fn construct_control_plane_url_needs_the_global_external_host() {
        let mut config = test_config(None);
        config.store.http.external_host = Some("admin.example".to_owned());

        let err = construct_control_plane_url(&config)
            .await
            .expect_err("no global external host");

        assert!(matches!(err, WarpgateError::ExternalHostUnknown));
    }

    #[tokio::test]
    async fn construct_control_plane_url_omits_the_default_port() {
        let config = control_plane_config(Some("admin.example:443"));

        let url = construct_control_plane_url(&config)
            .await
            .expect("control plane url");

        assert_eq!(url.as_str(), "https://admin.example/");
    }

    #[tokio::test]
    async fn construct_control_plane_url_is_http_on_a_plain_http_listener() {
        let mut config = control_plane_config(Some("admin.example"));
        config.store.http.plain_http_on_loopback = true;

        let url = construct_control_plane_url(&config)
            .await
            .expect("control plane url");

        assert_eq!(url.as_str(), "http://admin.example:8888/");
    }
}
