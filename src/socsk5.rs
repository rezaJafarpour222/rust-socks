use std::sync::Arc;

use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::{cache::DnsCache, connection::proxy, metrics::Metrics};

pub async fn run(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    dns_cache: Arc<DnsCache>,
    metrics: Arc<Metrics>,
) {
    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(value) => value,
            Err(err) => {
                tracing::error!(
                    service = "socks5",
                    error = ?err
                );
                continue;
            }
        };

        let acceptor = acceptor.clone();
        let dns_cache = Arc::clone(&dns_cache);
        let metrics = Arc::clone(&metrics);

        tokio::spawn(async move {
            // Perform TLS before reading SOCKS5 protocol data.
            let mut tls_stream = match tokio::time::timeout(
                std::time::Duration::from_secs(10),
                acceptor.accept(stream),
            )
            .await
            {
                Ok(Ok(stream)) => stream,
                Ok(Err(err)) => {
                    tracing::warn!(
                        service = "socks5",
                        event = "tls_handshake_failed",
                        peer = %peer_addr,
                        error = ?err
                    );
                    return;
                }
                Err(_) => {
                    tracing::warn!(
                        service = "socks5",
                        event = "tls_handshake_timeout",
                        peer = %peer_addr
                    );
                    return;
                }
            };

            metrics.add_connection();

            let result = proxy(&mut tls_stream, &dns_cache, &metrics).await;

            metrics.remove_connection();

            if let Err(err) = result {
                tracing::warn!(
                    service = "socks5",
                    peer = %peer_addr,
                    error = ?err
                );
            }
        });
    }
}
