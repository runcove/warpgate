pub mod api;
mod approval_gate;
mod catchall;
mod client_cache;
mod common;
mod health;
mod loopback_owner;
mod middleware;
pub mod proxy;
mod session;
mod session_handle;
mod session_storage;
mod sso_request_store;
mod step_up;
#[cfg(test)]
mod test_db;
mod unauthenticated_page;
mod unix_socket;

use std::fmt::Debug;
use std::sync::Arc;

use anyhow::{Context, Result};
use common::inject_request_authorization;
pub use common::{PROTOCOL_NAME, SsoLoginState};
use futures::FutureExt;
use futures::future::BoxFuture;
use http::HeaderValue;
use poem::endpoint::{EmbeddedFileEndpoint, EmbeddedFilesEndpoint};
use poem::listener::{AcceptorExt, BoxAcceptor};
use poem::middleware::SetHeader;
use poem::session::ServerSession;
use poem::web::Data;
use poem::{Endpoint, EndpointExt, FromRequest, IntoEndpoint, IntoResponse, Route, Server};
use poem_openapi::OpenApiService;
use tokio::sync::Mutex;
use tracing::{Instrument, warn};
use warpgate_admin::admin_api_app;
use warpgate_common::ListenEndpoint;
use warpgate_common::helpers::proxy_protocol::MaybeProxyProtocolAcceptor;
use warpgate_common_http::auth::UnauthenticatedRequestContext;
use warpgate_common_http::cluster_tls::{ClusterTlsConfigs, cluster_aware_tls_acceptor};
use warpgate_common_http::errors::render_errors;
use warpgate_common_http::ext::construct_external_url;
use warpgate_common_http::logging::{
    get_client_ip, log_request_error, log_request_result, span_for_request,
};
use warpgate_common_http::{
    PlainHttpListener, WARPGATE_PLAYGROUND_CSP, cluster_peer_extension,
    warpgate_csp_with_connect_src,
};
use warpgate_core::{ProtocolServer, Services};
use warpgate_db_entities::Parameters::RecordingsStorageConfig;
use warpgate_tls::TlsCertificateAndPrivateKey;
use warpgate_version::warpgate_version;
use warpgate_web::Assets;
use warpgate_web_desktop::WebDesktopClientManager;
use warpgate_web_desktop::api::ws_handler as desktop_web_client_ws_handler;
use warpgate_web_ssh::WebSshClientManager;
use warpgate_web_ssh::api::ws_handler as ssh_web_client_ws_handler;

use crate::api::common::forward_ws_to_session_owner;
use crate::client_cache::HttpClientCache;
use crate::common::{endpoint_auth, page_auth};
use crate::middleware::{
    CookieHostMiddleware, LOOPBACK_SESSION_COOKIE_MAX_AGE_CAP, LoopbackHostMiddleware,
    LoopbackSessionCookieMiddleware, OriginCheckMiddleware, SecurityHeadersMiddleware,
    TargetOriginCheckMiddleware, TicketMiddleware,
};
use crate::session::SessionStore;
use crate::session_handle::warpgate_server_handle_for_request;
use crate::session_storage::SharedSessionStorage;

pub struct HTTPProtocolServer {
    services: Services,
}

impl HTTPProtocolServer {
    pub fn new(services: &Services) -> Self {
        Self {
            services: services.clone(),
        }
    }
}

/// The S3 bucket origin to allow-list in the admin document CSP, or `None` when
/// recordings are on disk (or the config can't be read). Read live so a storage
/// config change takes effect on the next admin page load.
async fn recordings_s3_browser_origin(ctx: &UnauthenticatedRequestContext) -> Option<String> {
    match ctx
        .parameters()
        .await
        .ok()?
        .recordings_storage_config()
        .ok()?
    {
        RecordingsStorageConfig::S3(s3) => s3.browser_origin(),
        RecordingsStorageConfig::Disk(_) => None,
    }
}

/// The acceptor of a plain-HTTP loopback listener on `address`, for a
/// process whose effective uid is `euid`: refused, before anything is bound,
/// when that is root's; otherwise only connections whose client socket
/// `lookup` finds owned by `euid` come out of it. Wrapped inside the PROXY
/// protocol reader, so the owner checked is the one of the actual TCP peer.
async fn loopback_acceptor(
    address: &ListenEndpoint,
    proxy_protocol: bool,
    lookup: Arc<dyn loopback_owner::SocketOwnerLookup>,
    euid: u32,
) -> Result<BoxAcceptor> {
    let our_uid = loopback_owner::serving_uid(euid)?;
    let acceptor = address.poem_acceptor().await?;
    let acceptor = loopback_owner::same_account_acceptor(acceptor, lookup, our_uid);
    Ok(MaybeProxyProtocolAcceptor::new(acceptor, proxy_protocol).boxed())
}

impl ProtocolServer for HTTPProtocolServer {
    async fn bind(
        self,
        address: ListenEndpoint,
        proxy_protocol: bool,
        tls: Vec<TlsCertificateAndPrivateKey>,
    ) -> Result<BoxFuture<'static, Result<()>>> {
        let plain_http = self
            .services
            .config
            .lock()
            .await
            .store
            .http
            .plain_http_on_loopback;
        // The config check refuses this already; checked again on the address
        // actually bound, so plain HTTP is never served off loopback.
        if plain_http && !address.is_loopback() {
            anyhow::bail!(
                "`http.plain_http_on_loopback` is set, but {address:?} is not a loopback address; refusing to serve plain HTTP"
            );
        }

        // A plain-HTTP loopback listener needs no certificate and serves no TLS
        let tls_configs = if plain_http {
            None
        } else {
            if tls.is_empty() {
                anyhow::bail!("HTTP requires a TLS certificate and key");
            }
            // Public certificates by SNI; the cluster identity (with mandatory
            // client auth) under its own SNI name
            Some(
                ClusterTlsConfigs::new(tls, &self.services.cluster.tls_identity)
                    .context("rustls setup")?,
            )
        };

        let session_storage = SharedSessionStorage::new(self.services.db.clone());
        let session_store = SessionStore::new();
        let http_client_cache = HttpClientCache::new(std::time::Duration::MAX);
        let sso_request_store: crate::sso_request_store::SsoRequestStore =
            crate::sso_request_store::SsoRequestStore::new();

        let cache_bust = || {
            SetHeader::new().overriding(
                http::header::CACHE_CONTROL,
                HeaderValue::from_static("must-revalidate,no-cache,no-store"),
            )
        };

        let cache_static = || {
            SetHeader::new().overriding(
                http::header::CACHE_CONTROL,
                HeaderValue::from_static("max-age=86400"),
            )
        };

        let (cookie_max_age, session_max_age) = {
            let config = self.services.config.lock().await;
            (
                config.store.http.cookie_max_age,
                config.store.http.session_max_age,
            )
        };
        // The session cookie's lifetime: capped on a plain-HTTP loopback listener.
        let session_cookie_max_age = if plain_http {
            cookie_max_age.min(LOOPBACK_SESSION_COOKIE_MAX_AGE_CAP)
        } else {
            cookie_max_age
        };

        // Set cookie domain to base host (e.g., ".warp.tavahealth.com") so it works for
        // the base host and all its subdomains (e.g., "foo.warp.tavahealth.com").
        // This is more restrictive than using the parent domain and ensures cookies only
        // work for the base host and its subdomains, not sibling domains.
        let base_cookie_domain: Option<String> = {
            let config = self.services.config.lock().await;
            match construct_external_url(None, &config, None).await {
                Ok(url) => {
                    if let Some(host) = url.host_str() {
                        // Use the base host directly with a leading dot (e.g., ".warp.tavahealth.com")
                        // This allows cookies to work for:
                        // - warp.tavahealth.com (exact match)
                        // - foo.warp.tavahealth.com (subdomain)
                        // - bar.warp.tavahealth.com (subdomain)
                        // But NOT for:
                        // - tavahealth.com (parent domain)
                        // - reporting.tavahealth.com (sibling domain)
                        let domain = format!(".{host}");
                        tracing::info!(
                            "Cookie domain configured: {} (base host: {}) - cookies will work for {} and all its subdomains",
                            domain,
                            host,
                            host
                        );
                        Some(domain)
                    } else {
                        tracing::warn!(
                            "Failed to determine cookie domain - external_host may not be configured. Cookies will be scoped to request host, which may prevent cross-subdomain authentication."
                        );
                        None
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to construct external URL for cookie domain: {:?}. Cookies will be scoped to request host.",
                        e
                    );
                    None
                }
            }
        };

        // /@warpgate/ routes
        let web_ssh_manager = Arc::new(WebSshClientManager::new());
        let web_desktop_manager = Arc::new(WebDesktopClientManager::new());
        let at_warpgate_endpoints = || {
            let services = self.services.clone();
            let web_ssh_manager = web_ssh_manager.clone();
            let web_desktop_manager = web_desktop_manager.clone();
            let api_service = {
                OpenApiService::new(crate::api::get(), "Warpgate user API", warpgate_version())
                    .server("/@warpgate/api")
            };
            let openapi_ui_route = api_service.stoplight_elements();
            let openapi_spec_route = api_service.spec_endpoint();
            let admin_api_app = admin_api_app().into_endpoint();

            Route::new()
                .nest(
                    "/api/playground",
                    openapi_ui_route.with(SetHeader::new().overriding(
                        http::header::CONTENT_SECURITY_POLICY,
                        WARPGATE_PLAYGROUND_CSP,
                    )),
                )
                .nest("/api", api_service.with(cache_bust()))
                .nest("/api/openapi.json", openapi_spec_route)
                .nest_no_strip(
                    "/assets",
                    EmbeddedFilesEndpoint::<Assets>::new().with(cache_static()),
                )
                .nest(
                    "/admin/api",
                    endpoint_auth(admin_api_app).with(cache_bust()),
                )
                .at(
                    // Served unauthenticated like the gateway shell: the admin API is
                    // auth-gated, and the SPA redirects to login client-side so the login
                    // `next` can include its hash route (a server redirect can't see it).
                    "/admin",
                    EmbeddedFileEndpoint::<Assets>::new("src/admin/index.html")
                        .with(cache_bust())
                        .around(move |ep, req| async move {
                            // The recording player fetches S3-backed recordings directly
                            // via presigned URLs, so the bucket origin must be allow-listed
                            // in this document's CSP.
                            let origin = match Data::<&UnauthenticatedRequestContext>::from_request_without_body(&req).await {
                                Ok(ctx) => recordings_s3_browser_origin(ctx.0).await,
                                Err(_) => None,
                            };
                            let mut resp = ep.call(req).await?.into_response();
                            let csp = warpgate_csp_with_connect_src(origin.as_deref());
                            if let Ok(value) = HeaderValue::from_str(&csp) {
                                resp.headers_mut()
                                    .insert(http::header::CONTENT_SECURITY_POLICY, value);
                            }
                            Ok(resp)
                        }),
                )
                .at("/api/logo", poem::get(api::logo::api_get_logo))
                // Liveness, from memory only; see health.rs.
                .at("/api/health", health::health_endpoint)
                .at(
                    "/api/auth/web-auth-requests/stream",
                    endpoint_auth(api::auth::api_get_web_auth_requests_stream),
                )
                .at(
                    "/api/web-ssh/sessions/:session_id/stream",
                    endpoint_auth(forward_ws_to_session_owner(ssh_web_client_ws_handler)),
                )
                .at(
                    "/api/web-desktop/sessions/:session_id/stream",
                    endpoint_auth(forward_ws_to_session_owner(desktop_web_client_ws_handler)),
                )
                .at(
                    "",
                    EmbeddedFileEndpoint::<Assets>::new("src/gateway/index.html")
                        .with(cache_bust()),
                )
                // Inside the request log, so refused requests are logged too.
                .with(OriginCheckMiddleware)
                .around({
                    let services = services;
                    move |ep, req| {
                        let services = services.clone();
                        async move {
                            let method = req.method().clone();
                            let url = req.original_uri().clone();
                            let client_ip = get_client_ip(&req, &services).await;

                            let response = ep.call(req).await.inspect_err(|e| {
                                log_request_error(&method, &url, client_ip.as_deref(), e);
                            })?;

                            log_request_result(
                                &method,
                                &url,
                                client_ip.as_deref(),
                                response.status(),
                            );
                            Ok(response)
                        }
                    }
                })
                .data(web_ssh_manager)
                .data(web_desktop_manager)
                .with(SecurityHeadersMiddleware)
        };

        let app = Route::new()
            .nest("/@warpgate", at_warpgate_endpoints())
            .nest("/_warpgate", at_warpgate_endpoints())
            .nest_no_strip(
                "/",
                // On a loopback listener, a state-changing request to a target
                // must come from Warpgate's own origin; refused before auth.
                page_auth(catchall::catchall_endpoint)
                    .with(TargetOriginCheckMiddleware)
                    .around(render_errors),
            )
            .around(inject_request_authorization)
            .around(move |ep, req| async move {
                let ctx = Data::<&UnauthenticatedRequestContext>::from_request_without_body(&req)
                    .await?
                    .clone();
                let sm = Data::<&Arc<Mutex<SessionStore>>>::from_request_without_body(&req)
                    .await?
                    .clone();

                let req = { sm.lock().await.process_request(req).await? };
                let handle = warpgate_server_handle_for_request(&req).await.ok();
                let span = match handle {
                    Some(ref handle) => {
                        let handle = handle.lock().await;
                        span_for_request(&req, ctx.services(), Some(&*handle)).await?
                    }
                    None => span_for_request(&req, ctx.services(), None).await?,
                };

                ep.call(req).instrument(span).await
            })
            // Each `with_if` wraps a boxed endpoint: its `EitherEndpoint` holds
            // the stack twice, which otherwise nests too deep to compile.
            .boxed()
            // No HSTS from a listener that serves no TLS.
            .with_if(
                !plain_http,
                SetHeader::new()
                    .overriding(http::header::STRICT_TRANSPORT_SECURITY, "max-age=31536000"),
            )
            .with(TicketMiddleware::new())
            .with(ServerSession::new(
                crate::common::session_cookie_config().max_age(session_cookie_max_age),
                session_storage.clone(),
            ))
            .with(CookieHostMiddleware::new(base_cookie_domain))
            .with(cluster_peer_extension())
            .boxed()
            .with_if(
                plain_http,
                LoopbackSessionCookieMiddleware::new(session_cookie_max_age),
            )
            .data(PlainHttpListener(plain_http))
            .data(UnauthenticatedRequestContext::new(self.services.clone()).await)
            .data(http_client_cache.clone())
            .data(session_store.clone())
            .data(sso_request_store.clone())
            .data(session_storage.clone())
            // Outermost on purpose: session loading and header parsing run
            // before routing and fail the same way a handler does.
            .around(render_errors)
            .boxed()
            // Outside even that: on a plain-HTTP loopback listener, a request
            // for any other host is answered 421 before anything else runs.
            .with_if(
                plain_http,
                LoopbackHostMiddleware::new(address.port(), self.services.config.clone()),
            )
            .boxed();

        tokio::spawn(async move {
            loop {
                let live = {
                    let mut store = session_store.lock().await;
                    store.vacuum(session_max_age);
                    store.live_session_ids()
                };
                // Before the sweep below, so a session whose only traffic is a
                // long-lived connection doesn't age out of its stored row.
                if let Err(error) = session_storage.touch(&live).await {
                    warn!(%error, "Failed to refresh active HTTP sessions");
                }
                if let Err(error) = session_storage.gc(cookie_max_age).await {
                    warn!(%error, "Failed to expire stored HTTP sessions");
                }
                sso_request_store.vacuum().await;
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            }
        });

        let Some(tls_configs) = tls_configs else {
            // Other OS accounts on this machine can reach loopback too: only
            // connections opened by this process's account are served.
            let acceptor = loopback_acceptor(
                &address,
                proxy_protocol,
                Arc::new(loopback_owner::KernelSocketTable),
                loopback_owner::effective_uid()?,
            )
            .await?;
            warn!(
                ?address,
                "Serving HTTP without TLS (`http.plain_http_on_loopback`)"
            );
            return Ok(async move {
                Server::new_with_acceptor(acceptor).run(app).await?;
                Ok(())
            }
            .boxed());
        };

        // Bind the socket now (errors here are non-fatal to the supervisor); the
        // returned future drives the accept loop (errors there restart the listener).
        let acceptor = address.poem_acceptor().await?;
        let acceptor = cluster_aware_tls_acceptor(
            MaybeProxyProtocolAcceptor::new(acceptor, proxy_protocol),
            tls_configs,
            self.services.cluster.clone(),
        );

        Ok(async move {
            Server::new_with_acceptor(acceptor).run(app).await?;
            Ok(())
        }
        .boxed())
    }

    fn name(&self) -> &'static str {
        "HTTP"
    }
}

impl Debug for HTTPProtocolServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HTTPProtocolServer")
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Duration;

    use poem::listener::Acceptor;
    use tokio::io::AsyncReadExt;

    use super::*;
    use crate::loopback_owner::SocketOwnerLookup;

    /// A socket table in which every socket is owned by one uid.
    struct OwnedBy(u32);

    impl SocketOwnerLookup for OwnedBy {
        fn owner_uid(
            &self,
            _local: SocketAddr,
            _remote: SocketAddr,
        ) -> anyhow::Result<Option<u32>> {
            Ok(Some(self.0))
        }
    }

    /// Connects once to a loopback listener built as `bind` builds it, for
    /// Warpgate running as 501 and a client socket owned by `owner`: whether
    /// the connection came out of the acceptor, and what the client read when
    /// it did not.
    async fn connect_to_loopback_listener(owner: u32) -> (bool, Vec<u8>) {
        let address = ListenEndpoint::from("127.0.0.1:0".parse::<SocketAddr>().unwrap());
        let mut acceptor = loopback_acceptor(&address, false, Arc::new(OwnedBy(owner)), 501)
            .await
            .unwrap();
        let bound = *acceptor
            .local_addr()
            .first()
            .unwrap()
            .as_socket_addr()
            .unwrap();

        let mut client = tokio::net::TcpStream::connect(bound).await.unwrap();
        let accepted = tokio::time::timeout(Duration::from_millis(500), acceptor.accept()).await;
        let mut received = Vec::new();
        if accepted.is_err() {
            // Refused: the connection is closed without a byte.
            let _ = tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut received))
                .await
                .unwrap();
        }
        (accepted.is_ok_and(|accepted| accepted.is_ok()), received)
    }

    #[tokio::test]
    async fn loopback_listener_refuses_to_start_as_root() {
        let address = ListenEndpoint::from("127.0.0.1:0".parse::<SocketAddr>().unwrap());
        let Err(error) = loopback_acceptor(&address, false, Arc::new(OwnedBy(0)), 0).await else {
            panic!("a loopback listener started for root");
        };
        assert!(error.to_string().contains("root"), "{error}");
    }

    #[tokio::test]
    async fn loopback_listener_serves_its_own_account() {
        let (accepted, _) = connect_to_loopback_listener(501).await;
        assert!(accepted);
    }

    #[tokio::test]
    async fn loopback_listener_closes_another_accounts_connections() {
        let (accepted, received) = connect_to_loopback_listener(502).await;
        assert!(!accepted);
        assert!(received.is_empty());
    }
}
