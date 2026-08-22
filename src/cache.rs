use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::RwLock,
    time::{Duration, Instant},
};

pub struct CacheEntry {
    adressess: Vec<SocketAddr>,
    expires_at: Instant,
}
pub struct DnsCache {
    entries: RwLock<HashMap<String, CacheEntry>>,
    ttl: Duration,
}
impl DnsCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            ttl,
        }
    }
    pub fn get(&self, domain: &str) -> Option<Vec<SocketAddr>> {
        let entries = self.entries.read().unwrap();
        let entry = entries.get(domain)?;
        if entry.expires_at <= Instant::now() {
            return None;
        }
        Some(entry.adressess.clone())
    }
    pub fn insert(&self, domain: String, adressess: Vec<SocketAddr>) {
        let entry = CacheEntry {
            adressess,
            expires_at: Instant::now() + self.ttl,
        };
        let mut entries = self.entries.write().unwrap();
        entries.insert(domain, entry);
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    #[test]
    fn cache_miss() {
        let cache = DnsCache::new(Duration::from_secs(60));

        assert!(cache.get("example.com").is_none());
    }
    #[test]
    fn cache_hit() {
        let cache = DnsCache::new(Duration::from_secs(60));

        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443);

        cache.insert("example.com".to_string(), vec![address]);

        let result = cache.get("example.com");

        assert_eq!(result, Some(vec![address]));
    }
    #[test]
    fn cache_expires() {
        let cache = DnsCache::new(Duration::from_millis(10));

        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443);

        cache.insert("example.com".to_string(), vec![address]);

        assert!(cache.get("example.com").is_some());

        std::thread::sleep(Duration::from_millis(20));

        assert!(cache.get("example.com").is_none());
    }
}
