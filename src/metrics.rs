use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use std::sync::Arc;
use tokio::time::{Duration, interval};
pub struct Metrics {
    active_connections: AtomicUsize,
    total_connections: AtomicUsize,

    bytes_uploaded: AtomicU64,
    bytes_downloaded: AtomicU64,

    upload_rate: AtomicU64,
    download_rate: AtomicU64,
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            active_connections: AtomicUsize::new(0),
            total_connections: AtomicUsize::new(0),

            bytes_uploaded: AtomicU64::new(0),
            bytes_downloaded: AtomicU64::new(0),

            upload_rate: AtomicU64::new(0),
            download_rate: AtomicU64::new(0),
        }
    }

    pub fn add_uploaded(&self, bytes: u64) {
        self.bytes_uploaded.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn add_downloaded(&self, bytes: u64) {
        self.bytes_downloaded.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn uploaded(&self) -> u64 {
        self.bytes_uploaded.load(Ordering::Relaxed)
    }

    pub fn downloaded(&self) -> u64 {
        self.bytes_downloaded.load(Ordering::Relaxed)
    }

    pub fn set_upload_rate(&self, rate: u64) {
        self.upload_rate.store(rate, Ordering::Relaxed);
    }

    pub fn set_download_rate(&self, rate: u64) {
        self.download_rate.store(rate, Ordering::Relaxed);
    }

    pub fn upload_rate(&self) -> u64 {
        self.upload_rate.load(Ordering::Relaxed)
    }

    pub fn download_rate(&self) -> u64 {
        self.download_rate.load(Ordering::Relaxed)
    }
    pub fn add_connection(&self) {
        self.total_connections.fetch_add(1, Ordering::Relaxed);
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn remove_connection(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn active_connection(&self) -> usize {
        self.active_connections.load(Ordering::Relaxed)
    }

    pub fn total_connection(&self) -> usize {
        self.total_connections.load(Ordering::Relaxed)
    }
}

pub async fn update_rates(metrics: Arc<Metrics>) {
    let mut timer = interval(Duration::from_secs(1));

    let mut last_uploaded = 0;
    let mut last_downloaded = 0;

    loop {
        timer.tick().await;

        let uploaded = metrics.uploaded();
        let downloaded = metrics.downloaded();

        let upload_rate = uploaded - last_uploaded;
        let download_rate = downloaded - last_downloaded;

        metrics.set_upload_rate(upload_rate);
        metrics.set_download_rate(download_rate);

        println!(
            "Upload: {:.2} MB/s | Download: {:.2} MB/s| Active Connections: {} | TotalConnection: {} | Total Upload: {:.2} MB/s |Total Download: {:.2} MB/s",
            upload_rate as f64 / 1024.0 / 1024.0,
            download_rate as f64 / 1024.0 / 1024.0,
            metrics.active_connection(),
            metrics.total_connection(),
            metrics.uploaded() as f64 / 1024.0 / 1024.0,
            metrics.downloaded() as f64 / 1024.0 / 1024.0
        );

        use std::io::{self, Write};
        io::stdout().flush().unwrap();

        last_uploaded = uploaded;
        last_downloaded = downloaded;
    }
}
