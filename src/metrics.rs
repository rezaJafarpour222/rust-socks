use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use std::sync::Arc;
use tokio::time::{Duration, interval};
pub struct Metrics {
    active_connections: AtomicUsize,
    total_connections: AtomicUsize,

    bytes_uploaded: AtomicU64,
    bytes_downloaded: AtomicU64,
    dns_cache_hit: AtomicU64,
    dns_cache_miss: AtomicU64,
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            active_connections: AtomicUsize::new(0),
            total_connections: AtomicUsize::new(0),

            bytes_uploaded: AtomicU64::new(0),
            bytes_downloaded: AtomicU64::new(0),
            dns_cache_hit: AtomicU64::new(0),
            dns_cache_miss: AtomicU64::new(0),
        }
    }

    pub fn add_uploaded(&self, bytes: u64) {
        self.bytes_uploaded.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn add_downloaded(&self, bytes: u64) {
        self.bytes_downloaded.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn add_dns_cache_hit(&self) {
        self.dns_cache_hit.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_dns_cache_miss(&self) {
        self.dns_cache_miss.fetch_add(1, Ordering::Relaxed);
    }

    pub fn uploaded(&self) -> u64 {
        self.bytes_uploaded.load(Ordering::Relaxed)
    }

    pub fn downloaded(&self) -> u64 {
        self.bytes_downloaded.load(Ordering::Relaxed)
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

    pub fn total_dns_cache_hit(&self) -> u64 {
        self.dns_cache_hit.load(Ordering::Relaxed)
    }

    pub fn total_dns_cache_miss(&self) -> u64 {
        self.dns_cache_miss.load(Ordering::Relaxed)
    }
}
