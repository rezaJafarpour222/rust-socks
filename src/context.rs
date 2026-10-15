use std::sync::{Arc, Mutex};

use crate::cache::DnsCache;

#[derive(Clone)]
pub struct ProxyContext {
    pub dns_cache: Arc<DnsCache>,
    pub udp_relay_ports: Arc<Mutex<Vec<u16>>>,
    pub udp_relay_host: Option<String>,
}