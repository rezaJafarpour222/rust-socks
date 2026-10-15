use std::sync::Arc;

use tokio::io::AsyncBufReadExt;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::{
    cache::DnsCache,
    context::ProxyContext,
    protocols::{ClientStream, ProtocolRegistry, ProxyProtocol},
};

pub async fn run(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    dns_cache: Arc<DnsCache>,
) {
    let registry = std::sync::Arc::new(ProtocolRegistry::default_registry());

    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(value) => value,
            Err(err) => {
                tracing::error!(service = "proxy", error = ?err);
                continue;
            }
        };

        let acceptor = acceptor.clone();
        let dns_cache = Arc::clone(&dns_cache);
        let registry = std::sync::Arc::clone(&registry);

        tokio::spawn(async move {
            let tls_stream = match tokio::time::timeout(
                std::time::Duration::from_secs(10),
                acceptor.accept(stream),
            )
            .await
            {
                Ok(Ok(stream)) => stream,
                Ok(Err(err)) => {
                    tracing::warn!(
                        service = "proxy",
                        event = "tls_handshake_failed",
                        peer = %peer_addr,
                        error = ?err
                    );
                    return;
                }
                Err(_) => {
                    tracing::warn!(
                        service = "proxy",
                        event = "tls_handshake_timeout",
                        peer = %peer_addr
                    );
                    return;
                }
            };

            let ctx = ProxyContext {
                dns_cache: Arc::clone(&dns_cache),
            };

            let mut stream: ClientStream = tokio::io::BufReader::new(tls_stream);

            let protocol = {
                let peek = match stream.fill_buf().await {
                    Ok(peek) => peek,
                    Err(err) => {
                        tracing::warn!(peer = %peer_addr, error = ?err, "peek failed");
                        return;
                    }
                };

                if peek.is_empty() {
                    return;
                }

                match registry.detect(peek) {
                    Some(protocol) => protocol,
                    None => {
                        tracing::warn!(
                            service = "proxy",
                            event = "unknown_protocol",
                            peer = %peer_addr,
                            prefix = ?&peek[..peek.len().min(8)]
                        );
                        return;
                    }
                }
            };

            let result = protocol.handle(&mut stream, ctx).await;

            if let Err(err) = result {
                tracing::warn!(
                    service = "proxy",
                    peer = %peer_addr,
                    protocol = protocol.name(),
                    error = ?err
                );
            }
        });
    }
}

/// Runs one protocol on its own TLS-wrapped endpoint.
pub async fn run_protocol<P>(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    protocol: std::sync::Arc<P>,
    dns_cache: std::sync::Arc<DnsCache>,
) where
    P: ProxyProtocol + 'static,
{
    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(value) => value,
            Err(err) => {
                tracing::error!(service = "proxy", error = ?err);
                continue;
            }
        };

        let acceptor = acceptor.clone();
        let protocol = std::sync::Arc::clone(&protocol);
        let dns_cache = std::sync::Arc::clone(&dns_cache);

        tokio::spawn(async move {
            let tls_stream = match tokio::time::timeout(
                std::time::Duration::from_secs(10),
                acceptor.accept(stream),
            )
            .await
            {
                Ok(Ok(stream)) => stream,
                Ok(Err(err)) => {
                    tracing::warn!(peer = %peer_addr, error = ?err, "tls handshake failed");
                    return;
                }
                Err(_) => {
                    tracing::warn!(peer = %peer_addr, "tls handshake timeout");
                    return;
                }
            };

            let ctx = ProxyContext {
                dns_cache: std::sync::Arc::clone(&dns_cache),
            };

            let mut stream: ClientStream = tokio::io::BufReader::new(tls_stream);

            let result = protocol.handle(&mut stream, ctx).await;

            if let Err(err) = result {
                tracing::warn!(
                    service = "proxy",
                    peer = %peer_addr,
                    protocol = protocol.name(),
                    error = ?err
                );
            }
        });
    }
}