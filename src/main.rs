pub mod cache;
pub mod config;
pub mod connect;
pub mod context;
pub mod error;
pub mod protocol;
pub mod protocols;
pub mod server;

use std::{error::Error, fs::File, io::BufReader, sync::Arc, time::Duration};

use tokio::net::TcpListener;
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        ServerConfig,
        pki_types::PrivateKeyDer,
        version::{TLS12, TLS13},
    },
};

use crate::{cache::DnsCache, config::AppConfig};

fn create_tls_acceptor(
    cert_path: &str,
    key_path: &str,
) -> Result<TlsAcceptor, Box<dyn Error + Send + Sync>> {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();

    let cert_file = File::open(cert_path)?;
    let key_file = File::open(key_path)?;

    let certs =
        rustls_pemfile::certs(&mut BufReader::new(cert_file)).collect::<Result<Vec<_>, _>>()?;

    if certs.is_empty() {
        return Err("No certificates found in certs/cert.pem".into());
    }

    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut BufReader::new(key_file))?
        .ok_or("No private key found in certs/key.pem")?;

    // Enable TLS 1.3 only.
    let config = ServerConfig::builder_with_protocol_versions(&[&TLS13, &TLS12])
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    let config = AppConfig::from_env();
    config.apply_credentials_to_env();

    let dns_cache = Arc::new(DnsCache::new(
        Duration::from_secs(config.cache_duration_secs),
        config.cache_entry_limit,
    ));

    // Load the certificate and private key before accepting connections.
    let acceptor = create_tls_acceptor(&config.cert_path, &config.key_path)?;

    // TLS-wrapped SOCKS5 server.
    let socks5_listener = TcpListener::bind(&config.socks5_port).await?;

    let socks5_task = {
        let dns_cache = Arc::clone(&dns_cache);
        let port = config.socks5_port.clone();

        tokio::spawn(async move {
            tracing::info!(
                service = "socks5",
                event = "tls_server_started",
                port = %port
            );

            server::run(socks5_listener, acceptor, dns_cache).await;
        })
    };

    let result = socks5_task.await;

    if let Err(err) = result {
        tracing::error!(service = "socks5", result = ?err, "SOCKS5 task stopped");
    }

    Ok(())
}
