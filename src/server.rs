use tokio::io::AsyncBufReadExt;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::{
    context::ProxyContext,
    protocols::{ClientStream, ProtocolRegistry},
};

pub async fn run(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    context: ProxyContext,
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
        let context = context.clone();
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

            let ctx = context.clone();

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

