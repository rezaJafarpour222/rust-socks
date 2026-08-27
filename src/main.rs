pub mod cache;
pub mod connection;
pub mod metrics;
pub mod protocol;

use std::{sync::Arc, time::Duration};

use tokio::net::TcpListener;

use crate::{
    cache::DnsCache,
    connection::proxy,
    metrics::{Metrics, update_rates},
};
const CACHE_DURATION: u64 = 24 * 60 * 60;
const CACHE_ENTRY_LIMIT: usize = 10_000;
#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::ERROR)
        .init();
    tracing::info!("proxy is running...");

    let dns_cache = Arc::new(DnsCache::new(
        Duration::from_secs(CACHE_DURATION),
        CACHE_ENTRY_LIMIT,
    ));
    let metrics = Arc::new(Metrics::new());
    let listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();
    //begin metric calculator background service
    let metric_clone = Arc::clone(&metrics);
    tokio::spawn(async move {
        update_rates(metric_clone).await;
    });
    //end metric calcualtor background service
    loop {
        let (mut stream, _) = listener.accept().await.unwrap();
        let dns_cache = Arc::clone(&dns_cache);
        let metrics = Arc::clone(&metrics);
        tokio::spawn(async move {
            if let Err(err) = proxy(&mut stream, &dns_cache, &metrics).await {
                tracing::error!("{:?}", err)
            }
        });
    }
}
