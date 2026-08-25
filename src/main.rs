pub mod cache;
pub mod protocol;

use std::{sync::Arc, time::Duration};

use tokio::net::TcpListener;

use crate::{cache::DnsCache, protocol::handler::proxy};
const CACHE_DURATION: u64 = 24 * 60 * 60;
const CACHE_ENTRY_LIMIT: usize = 10_000;
#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    tracing::info!("proxy is running...");
    let listener = TcpListener::bind("127.0.0.1:3000").await.unwrap();
    let dns_cache = Arc::new(DnsCache::new(
        Duration::from_secs(CACHE_DURATION),
        CACHE_ENTRY_LIMIT,
    ));
    loop {
        let (mut stream, _) = listener.accept().await.unwrap();
        let dns_cache = Arc::clone(&dns_cache);
        tokio::spawn(async move {
            if let Err(err) = proxy(&mut stream, &dns_cache).await {
                tracing::error!("{:?}", err)
            }
        });
    }
}
