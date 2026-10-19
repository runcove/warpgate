use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::redirect::Policy;
use warpgate_common::TargetHTTPOptions;
use warpgate_common_cache::Cache;
use warpgate_tls::TlsMode;

const HTTP_CLIENT_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(90);

const HTTP_CLIENT_POOL_MAX_IDLE_PER_HOST: usize = 16;

/// Key = target name
pub type HttpClientCache = Cache<String, TargetHTTPOptions, reqwest::Client>;

pub fn build_client(options: &TargetHTTPOptions) -> Result<reqwest::Client> {
    let tls_mode = options.tls.mode;
    let mut client = reqwest::Client::builder()
        .gzip(false) // do not decode
        .connection_verbose(true)
        .pool_idle_timeout(HTTP_CLIENT_POOL_IDLE_TIMEOUT)
        .pool_max_idle_per_host(HTTP_CLIENT_POOL_MAX_IDLE_PER_HOST)
        .redirect(Policy::custom(move |attempt| {
            let started_with_http = attempt
                .previous()
                .first()
                .is_some_and(|url| url.scheme() == "http");

            if tls_mode == TlsMode::Preferred
                && started_with_http
                && attempt.url().scheme() == "https"
            {
                tracing::debug!("Following HTTP->HTTPS redirect");
                attempt.follow()
            } else {
                attempt.stop()
            }
        }));

    if options.tls.mode == TlsMode::Required {
        client = client.https_only(true);
    }

    if !options.tls.verify {
        client = client.danger_accept_invalid_certs(true);
    }

    if let Some(path) = &options.unix_socket {
        #[cfg(unix)]
        {
            client = client.unix_socket(std::path::PathBuf::from(path));
        }
        #[cfg(not(unix))]
        {
            anyhow::bail!("Unix socket {path} is not supported on this platform");
        }
    }

    client.build().context("Could not build HTTP target client")
}

/// Kept from 70bdadb7 and 54b1928f against v0.30.0's cache: a target's client
/// is reused while its options are unchanged and rebuilt when they change,
/// `unix_socket` included, so a client built for one socket never serves
/// another.
#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn install_crypto_provider() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }

    fn make_options(url: &str) -> TargetHTTPOptions {
        TargetHTTPOptions {
            url: url.to_string(),
            tls: Default::default(),
            headers: Default::default(),
            external_host: None,
            public: false,
            unix_socket: None,
        }
    }

    /// How many clients the cache built for `target` over `options`, in order.
    async fn builds(cache: &HttpClientCache, options: &[TargetHTTPOptions]) -> usize {
        let built = AtomicUsize::new(0);
        for options in options {
            cache
                .get_or_build(&"target".to_owned(), options, || async {
                    built.fetch_add(1, Ordering::SeqCst);
                    build_client(options)
                })
                .await
                .unwrap();
        }
        built.load(Ordering::SeqCst)
    }

    #[tokio::test]
    async fn reuses_client_for_unchanged_target() {
        install_crypto_provider();
        let cache = HttpClientCache::new(Duration::MAX);
        let options = make_options("https://example.com");
        assert_eq!(builds(&cache, &[options.clone(), options]).await, 1);
    }

    #[tokio::test]
    async fn rebuilds_client_when_target_configuration_changes() {
        install_crypto_provider();
        let cache = HttpClientCache::new(Duration::MAX);
        let options = [
            make_options("https://example.com"),
            make_options("https://example.org"),
        ];
        assert_eq!(builds(&cache, &options).await, 2);
    }

    #[tokio::test]
    async fn rebuilds_client_when_unix_socket_changes() {
        install_crypto_provider();
        let cache = HttpClientCache::new(Duration::MAX);
        let with_socket = |path: Option<&str>| TargetHTTPOptions {
            unix_socket: path.map(str::to_owned),
            ..make_options("http://app.local")
        };
        let options = [
            with_socket(None),
            with_socket(Some("/run/a/app.sock")),
            with_socket(Some("/run/a/app.sock")),
            with_socket(Some("/run/b/app.sock")),
        ];
        assert_eq!(builds(&cache, &options).await, 3);
    }
}
