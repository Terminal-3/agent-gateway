//! Shared reqwest client factory.
//!
//! All outbound HTTP calls to external / user-supplied endpoints must go through
//! one of these builders so that security-relevant defaults (redirect policy,
//! timeout) are applied consistently.
//!
//! ## Builders
//!
//! | Function | Timeout | Redirect | Typical use |
//! |---|---|---|---|
//! | [`external`] | 30 s | `none` | OAuth token exchange, webhooks, integrations |
//! | [`with_short_timeout`] | 10 s | `none` | JWKS fetch, low-latency probes |
//! | [`with_timeout`] | caller-supplied | `none` | Pipe executors with per-target timeouts |
//! | [`proxy_with_timeout`] | caller-supplied | `none` | Internal proxy hop with connection pooling |
//!
//! Every builder starts from [`builder`], so all clients share one rustls
//! configuration built once at start-up by [`init_tls`], each with its own TLS
//! session cache.

use std::sync::{Arc, LazyLock};
use std::time::Duration;

use anyhow::{Context, Result};
use rustls::ClientConfig;
use rustls::client::Resumption;
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::CryptoProvider;

pub const EXTERNAL_TIMEOUT_SECS: u64 = 30;
pub const SHORT_TIMEOUT_SECS: u64 = 10;

/// The TLS configuration every client starts from. Building it loads the
/// platform CA store, which on Linux reads and parses the system bundle.
static TLS: LazyLock<Result<ClientConfig, String>> =
    LazyLock::new(|| shared_tls_config().map_err(|error| error.to_string()));

/// Builds the shared TLS configuration and one client from it.
///
/// Called once at start-up, after the rustls crypto provider is installed. An
/// error here (no CA store, or a rustls version reqwest does not accept as a
/// preconfigured backend) fails start-up rather than every later request.
pub fn init_tls() -> Result<()> {
    if let Err(error) = &*TLS {
        anyhow::bail!("Failed to build the shared TLS configuration: {error}");
    }
    builder()
        .build()
        .context("Failed to build an HTTP client from the shared TLS configuration")?;
    Ok(())
}

/// `reqwest::Client::builder()` preconfigured with a clone of the shared TLS
/// configuration and its own session cache, so no TLS session is resumed
/// across clients.
///
/// The TLS configuration is fixed, so the builder's TLS settings
/// (`add_root_certificate`, `danger_accept_invalid_certs`, `min_tls_version`,
/// `tls_sni`, `http1_only`, `http2_prior_knowledge` and similar) have no effect
/// on the handshake. A caller that needs any of them uses
/// `reqwest::Client::builder()` instead.
///
/// If the shared configuration failed to build, this returns a plain
/// `reqwest::Client::builder()`; [`init_tls`] has already failed start-up in
/// that case.
pub fn builder() -> reqwest::ClientBuilder {
    match &*TLS {
        Ok(config) => builder_from(config),
        Err(_) => reqwest::Client::builder(),
    }
}

fn builder_from(config: &ClientConfig) -> reqwest::ClientBuilder {
    reqwest::Client::builder().tls_backend_preconfigured(fresh(config))
}

/// The installed default crypto provider, else ring (the provider `main`
/// installs).
fn provider() -> Arc<CryptoProvider> {
    CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()))
}

/// The settings reqwest applies on its own rustls path when no TLS option is
/// set on the builder: TLS 1.2 and 1.3, the given verifier, no client
/// certificate, and ALPN offering `h2` then `http/1.1`. SNI, key logging and
/// early data keep the rustls defaults, which match reqwest's.
fn tls_config(
    provider: Arc<CryptoProvider>,
    verifier: Arc<dyn ServerCertVerifier>,
) -> Result<ClientConfig, rustls::Error> {
    // The platform verifier checks the chain and the hostname.
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(rustls::ALL_VERSIONS)?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
}

fn shared_tls_config() -> Result<ClientConfig, rustls::Error> {
    let provider = provider();
    let verifier = rustls_platform_verifier::Verifier::new(provider.clone())?;
    tls_config(provider, Arc::new(verifier))
}

/// A clone of `config` with its own, empty session cache.
fn fresh(config: &ClientConfig) -> ClientConfig {
    let mut config = config.clone();
    config.resumption = Resumption::default();
    config
}

/// Standard client for outbound calls to external / user-supplied endpoints.
///
/// - 30-second request timeout
/// - Redirects disabled (SSRF guard — a redirect to an internal address would
///   bypass the URL validation performed before the first request)
pub fn external() -> Result<reqwest::Client> {
    with_timeout(Duration::from_secs(EXTERNAL_TIMEOUT_SECS))
}

/// Short-timeout client for fast probes (JWKS fetch, low-latency calls).
///
/// - 10-second request timeout
/// - Redirects disabled
pub fn with_short_timeout() -> Result<reqwest::Client> {
    with_timeout(Duration::from_secs(SHORT_TIMEOUT_SECS))
}

/// Client with a caller-supplied timeout, redirects disabled.
///
/// - Caller-supplied request timeout
/// - Redirects disabled
///
/// Use when the timeout is determined at runtime (e.g. per-pipe target config).
pub fn with_timeout(timeout: Duration) -> Result<reqwest::Client> {
    builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("Failed to build HTTP client")
}

/// Connection-pooled client for the Fabric receive forward and agent-card hops.
///
/// - Caller-supplied request timeout
/// - Redirects disabled: a 3xx from a target is returned, never followed, so a
///   target cannot redirect the gateway to another address
/// - Connection pool tuned for sustained agent-to-agent traffic
pub fn proxy_with_timeout(timeout: Duration) -> Result<reqwest::Client> {
    builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .pool_max_idle_per_host(10)
        .pool_idle_timeout(Duration::from_secs(30))
        .tcp_keepalive(Duration::from_secs(60))
        .user_agent("Affinidi-Fabric-Agent-Gateway/1.0")
        .build()
        .context("Failed to build proxy HTTP client")
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
    use rustls::ServerConfig;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::TlsAcceptor;

    /// A CA and a leaf certificate it issued for `localhost`.
    struct Pki {
        ca: CertificateDer<'static>,
        leaf: CertificateDer<'static>,
        leaf_key: PrivateKeyDer<'static>,
    }

    fn pki() -> Pki {
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().unwrap();
        let ca = ca_params
            .clone()
            .self_signed(&ca_key)
            .unwrap();
        let issuer = Issuer::new(ca_params, ca_key);
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .signed_by(&leaf_key, &issuer)
            .unwrap();
        Pki {
            ca: ca.der().clone(),
            leaf: leaf.der().clone(),
            leaf_key: PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into(),
        }
    }

    fn server_config(
        pki: &Pki,
        alpn: &[&[u8]],
    ) -> ServerConfig {
        let mut config = ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![pki.leaf.clone()], pki.leaf_key.clone_key())
            .unwrap();
        config.alpn_protocols = alpn
            .iter()
            .map(|protocol| protocol.to_vec())
            .collect();
        config
    }

    /// The shared configuration's construction, trusting `ca` on top of the
    /// platform roots.
    fn config_trusting(ca: CertificateDer<'static>) -> rustls::ClientConfig {
        let provider = super::provider();
        let verifier = rustls_platform_verifier::Verifier::new_with_extra_roots([ca], provider.clone()).unwrap();
        super::tls_config(provider, Arc::new(verifier)).unwrap()
    }

    /// Serves HTTPS over a raw TLS acceptor, recording each handshake's kind
    /// and answering every request with a fixed `200` that closes the
    /// connection.
    async fn recording_server(config: ServerConfig) -> (SocketAddr, Arc<Mutex<Vec<rustls::HandshakeKind>>>) {
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let kinds = Arc::new(Mutex::new(Vec::new()));
        let recorded = kinds.clone();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let recorded = recorded.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    if let Some(kind) = tls.get_ref().1.handshake_kind() {
                        recorded.lock().unwrap().push(kind);
                    }
                    let mut request = Vec::new();
                    let mut chunk = [0u8; 1024];
                    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                        match tls.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(read) => request.extend_from_slice(&chunk[..read]),
                        }
                    }
                    let _ = tls
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                        .await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        (address, kinds)
    }

    /// Every `std::error::Error::source` in `error`'s chain, joined.
    fn error_chain(error: &(dyn std::error::Error + 'static)) -> String {
        let mut chain = error.to_string();
        let mut source = error.source();
        while let Some(cause) = source {
            chain.push_str(": ");
            chain.push_str(&cause.to_string());
            source = cause.source();
        }
        chain
    }

    /// The shared configuration carries the settings reqwest applies on its
    /// own rustls path, which it does not add to a preconfigured backend.
    #[test]
    fn the_shared_tls_configuration_matches_reqwest_defaults() {
        super::init_tls().unwrap();
        let config = super::TLS
            .as_ref()
            .unwrap();
        assert_eq!(config.alpn_protocols, [b"h2".to_vec(), b"http/1.1".to_vec()]);
        assert!(config.enable_sni);
        assert!(!config.client_auth_cert_resolver.has_certs());
    }

    #[test]
    fn a_client_builds_from_the_shared_tls_configuration() {
        super::init_tls().unwrap();
        super::builder().build().unwrap();
    }

    #[tokio::test]
    async fn https_negotiates_http2() {
        let pki = pki();
        let config = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(server_config(
            &pki,
            &[b"h2", b"http/1.1"],
        )));
        let handle = axum_server::Handle::new();
        let server = axum_server::bind_rustls("127.0.0.1:0".parse::<SocketAddr>().unwrap(), config)
            .handle(handle.clone())
            .serve(axum::Router::new().route("/", axum::routing::get(|| async { "ok" })).into_make_service());
        tokio::spawn(server);
        let address = handle.listening().await.unwrap();

        let response = super::builder_from(&config_trusting(pki.ca))
            .build()
            .unwrap()
            .get(format!("https://localhost:{}/", address.port()))
            .send()
            .await
            .unwrap();
        assert_eq!(response.version(), reqwest::Version::HTTP_2);
    }

    #[tokio::test]
    async fn a_certificate_from_an_untrusted_issuer_is_rejected() {
        let pki = pki();
        let (address, _) = recording_server(server_config(&pki, &[b"http/1.1"])).await;

        let error = super::builder()
            .build()
            .unwrap()
            .get(format!("https://localhost:{}/", address.port()))
            .send()
            .await
            .unwrap_err();
        let chain = error_chain(&error).to_lowercase();
        assert!(chain.contains("certificate"), "got {chain}");

        let url = format!("https://127.0.0.1:{}/", address.port());
        let (client, _) = crate::egress::pinned_forward_client(&url, Duration::from_secs(5)).unwrap();
        let error = client
            .get(&url)
            .send()
            .await
            .unwrap_err();
        let chain = error_chain(&error).to_lowercase();
        assert!(chain.contains("certificate"), "got {chain}");
    }

    #[tokio::test]
    async fn a_certificate_for_another_host_is_rejected() {
        let pki = pki();
        let (address, _) = recording_server(server_config(&pki, &[b"http/1.1"])).await;
        let config = config_trusting(pki.ca);

        let error = super::builder_from(&config)
            .resolve("wrong.test", address)
            .build()
            .unwrap()
            .get(format!("https://wrong.test:{}/", address.port()))
            .send()
            .await
            .unwrap_err();
        let chain = error_chain(&error).to_lowercase();
        assert!(chain.contains("certificate"), "got {chain}");

        let response = super::builder_from(&config)
            .build()
            .unwrap()
            .get(format!("https://localhost:{}/", address.port()))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
    }

    #[tokio::test]
    async fn no_tls_session_is_resumed_across_clients() {
        let pki = pki();
        let (address, kinds) = recording_server(server_config(&pki, &[b"http/1.1"])).await;
        let config = config_trusting(pki.ca);
        let url = format!("https://localhost:{}/", address.port());
        let fetch = |client: reqwest::Client| {
            let url = url.clone();
            async move {
                client
                    .get(url)
                    .send()
                    .await
                    .unwrap()
                    .text()
                    .await
                    .unwrap()
            }
        };

        // One client resumes its own session, so the server can tell.
        let client = super::builder_from(&config)
            .build()
            .unwrap();
        fetch(client.clone()).await;
        fetch(client).await;
        assert_eq!(
            kinds.lock().unwrap().drain(..).collect::<Vec<_>>(),
            [rustls::HandshakeKind::Full, rustls::HandshakeKind::Resumed]
        );

        // Two clients from the same shared configuration each do a full handshake.
        fetch(
            super::builder_from(&config)
                .build()
                .unwrap(),
        )
        .await;
        fetch(
            super::builder_from(&config)
                .build()
                .unwrap(),
        )
        .await;
        assert_eq!(
            kinds.lock().unwrap().drain(..).collect::<Vec<_>>(),
            [rustls::HandshakeKind::Full, rustls::HandshakeKind::Full]
        );
    }

    /// Times client builds without and with the shared TLS configuration. The
    /// difference shows on Linux, where the platform verifier reads the system
    /// CA bundle on every build.
    #[test]
    #[ignore = "timing probe; run with --ignored --nocapture"]
    fn client_build_cost() {
        super::init_tls().unwrap();
        let time = |build: &dyn Fn() -> reqwest::ClientBuilder| {
            let started = Instant::now();
            for _ in 0..50 {
                build().build().unwrap();
            }
            started.elapsed() / 50
        };
        let plain = time(&reqwest::Client::builder);
        let shared = time(&super::builder);
        println!("per build: plain {plain:?}, shared TLS configuration {shared:?}");
    }

    #[tokio::test]
    async fn the_proxy_client_returns_a_redirect_instead_of_following_it() {
        let followed = Arc::new(AtomicUsize::new(0));
        let hits = followed.clone();
        let app = axum::Router::new()
            .route(
                "/start",
                axum::routing::get(|| async {
                    (axum::http::StatusCode::FOUND, [(axum::http::header::LOCATION, "/internal")])
                }),
            )
            .route(
                "/internal",
                axum::routing::get(move || {
                    hits.fetch_add(1, Ordering::SeqCst);
                    async { "internal" }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await });

        let response = super::proxy_with_timeout(std::time::Duration::from_secs(5))
            .unwrap()
            .get(format!("http://{address}/start"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::FOUND);
        assert_eq!(followed.load(Ordering::SeqCst), 0, "the redirect target was fetched");
    }
}
