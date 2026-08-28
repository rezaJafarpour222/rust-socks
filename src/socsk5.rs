use std::sync::Arc;

use tokio::net::TcpListener;

use crate::{cache::DnsCache, connection::proxy, metrics::Metrics};

pub async fn run(listener: TcpListener, dns_cache: Arc<DnsCache>, metrics: Arc<Metrics>) {
    loop {
        let dns_cache = Arc::clone(&dns_cache);
        let metrics = Arc::clone(&metrics);
        let (mut stream, _) = match listener.accept().await {
            Ok(value) => value,
            Err(err) => {
                tracing::error!(service = "socks5", error = ?err);
                continue;
            }
        };
        tokio::spawn(async move {
            if let Err(err) = proxy(&mut stream, &dns_cache, &metrics).await {
                tracing::error!(service = "socks5", error = ?err);
            }
        });
    }
}
