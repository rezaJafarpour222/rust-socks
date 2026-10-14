pub mod cache;
pub mod connection;
pub mod metrics;
pub mod protocol;
pub mod socsk5;
pub mod websocket;

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

use crate::{cache::DnsCache, metrics::Metrics};

const CACHE_DURATION: u64 = 24 * 60 * 60;
const CACHE_ENTRY_LIMIT: usize = 10_000;
const WEBSOCKET_PORT: &str = "0.0.0.0:3001";
const SOCKS5_PORT: &str = "0.0.0.0:3000";

fn create_tls_acceptor() -> Result<TlsAcceptor, Box<dyn Error + Send + Sync>> {
    let cert_file = File::open("certs/cert.pem")?;
    let key_file = File::open("certs/key.pem")?;

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
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let dns_cache = Arc::new(DnsCache::new(
        Duration::from_secs(CACHE_DURATION),
        CACHE_ENTRY_LIMIT,
    ));

    let metrics = Arc::new(Metrics::new());

    // Load the certificate and private key before accepting connections.
    let acceptor = create_tls_acceptor()?;

    // WebSocket server remains unchanged.
    let websocket_listener = TcpListener::bind(WEBSOCKET_PORT).await?;

    let websocket_task = {
        let metrics = Arc::clone(&metrics);

        tokio::spawn(async move {
            tracing::info!(
                service = "websocket",
                event = "server_started",
                port = WEBSOCKET_PORT
            );

            websocket::run(websocket_listener, metrics).await;
        })
    };

    // TLS-wrapped SOCKS5 server.
    let socks5_listener = TcpListener::bind(SOCKS5_PORT).await?;

    let socks5_task = {
        let dns_cache = Arc::clone(&dns_cache);
        let metrics = Arc::clone(&metrics);

        tokio::spawn(async move {
            tracing::info!(
                service = "socks5",
                event = "tls_server_started",
                port = SOCKS5_PORT
            );

            socsk5::run(socks5_listener, acceptor, dns_cache, metrics).await;
        })
    };

    tokio::select! {
        result = websocket_task => {
            tracing::error!(
                service = "websocket",
                result = ?result,
                "WebSocket task stopped"
            );
        }
        result = socks5_task => {
            tracing::error!(
                service = "socks5",
                result = ?result,
                "SOCKS5 task stopped"
            );
        }
    }

    Ok(())
}
