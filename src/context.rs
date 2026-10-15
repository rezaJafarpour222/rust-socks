use std::sync::Arc;

use crate::cache::DnsCache;

#[derive(Clone)]
pub struct ProxyContext {
    pub dns_cache: Arc<DnsCache>,
}