pub mod cache;
pub mod connection;
pub mod metrics;
pub mod protocol;
pub mod socsk5;
pub mod websocket;

use std::{sync::Arc, time::Duration};

use tokio::net::TcpListener;

use crate::{cache::DnsCache, metrics::Metrics};

const CACHE_DURATION: u64 = 24 * 60 * 60;
const CACHE_ENTRY_LIMIT: usize = 10_000;
const WEBSOCKET_PORT: &str = "0.0.0.0:3001";
const SOCKS5_PORT: &str = "0.0.0.0:3000";

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let dns_cache = Arc::new(DnsCache::new(
        Duration::from_secs(CACHE_DURATION),
        CACHE_ENTRY_LIMIT,
    ));

    let metrics = Arc::new(Metrics::new());

    // // Metrics background task
    // let metric_task = {
    //     let metrics = Arc::clone(&metrics);
    //
    //     tokio::spawn(async move {
    //         print_metrics(metrics).await;
    //     })
    // };

    // WebSocket server
    let websocket_listener = TcpListener::bind(WEBSOCKET_PORT).await.unwrap();

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

    // SOCKS5 server
    let socks5_listener = TcpListener::bind(SOCKS5_PORT).await.unwrap();

    let socks5_task = {
        let dns_cache = Arc::clone(&dns_cache);
        let metrics = Arc::clone(&metrics);

        tokio::spawn(async move {
            tracing::info!(
                service = "socks5",
                event = "server_started",
                port = SOCKS5_PORT
            );
            socsk5::run(socks5_listener, dns_cache, metrics).await;
        })
    };

    // Keep the application running.
    tokio::select! {
        // _ = metric_task => {
        //     tracing::error!("metrics task stopped");
        // }

        _ = websocket_task => {
            tracing::error!("websocket server stopped");
        }

        _ = socks5_task => {
            tracing::error!("SOCKS5 server stopped");
        }
    }
}
