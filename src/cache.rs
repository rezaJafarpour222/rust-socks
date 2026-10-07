use std::{
    collections::HashMap,
    net::IpAddr,
    sync::RwLock,
    time::{Duration, Instant},
};

pub struct CacheEntry {
    addresses: Vec<IpAddr>,
    expires_at: Instant,
}
pub struct DnsCache {
    entries: RwLock<HashMap<String, CacheEntry>>,
    ttl: Duration,
    max_entries: usize,
}
impl DnsCache {
    pub fn new(ttl: Duration, max_entries: usize) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            ttl,
            max_entries,
        }
    }
    pub fn get(&self, domain: &str) -> Option<Vec<IpAddr>> {
        let now = Instant::now();

        let entries = self.entries.read().unwrap();

        let entry = entries.get(domain)?;

        if entry.expires_at > now {
            return Some(entry.addresses.clone());
        }

        let mut entries = self.entries.write().unwrap();

        match entries.get(domain) {
            Some(entry) if entry.expires_at <= Instant::now() => {
                entries.remove(domain);
                None
            }
            Some(entry) => Some(entry.addresses.clone()),
            None => None,
        }
    }
    pub fn insert(&self, domain: String, addresses: Vec<IpAddr>) {
        let entry = CacheEntry {
            addresses,
            expires_at: Instant::now() + self.ttl,
        };

        let mut entries = self.entries.write().unwrap();

        if entries.len() >= self.max_entries {
            if let Some(key) = entries.keys().next().cloned() {
                entries.remove(&key);
            }
        }

        entries.insert(domain, entry);
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    #[test]
    fn cache_miss() {
        let cache = DnsCache::new(Duration::from_secs(60), 10_000);

        assert!(cache.get("example.com").is_none());
    }

    #[test]
    fn cache_hit() {
        let cache = DnsCache::new(Duration::from_secs(60), 10_000);

        let address = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));

        cache.insert("example.com".to_string(), vec![address]);

        let result = cache.get("example.com");

        assert_eq!(result, Some(vec![address]));
    }

    #[test]
    fn cache_expires() {
        let cache = DnsCache::new(Duration::from_millis(10), 10_000);

        let address = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));

        cache.insert("example.com".to_string(), vec![address]);

        assert!(cache.get("example.com").is_some());

        std::thread::sleep(Duration::from_millis(20));

        assert!(cache.get("example.com").is_none());
    }
    #[test]
    fn cache_shared() {
        let cache = DnsCache::new(Duration::from_secs(60), 10_000);

        let addresses = vec![
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
        ];

        cache.insert("example.com".to_string(), addresses.clone());

        assert_eq!(cache.get("example.com"), Some(addresses.clone()));
        assert_eq!(cache.get("example.com"), Some(addresses));
    }
}
