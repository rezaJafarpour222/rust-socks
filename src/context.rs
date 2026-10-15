use std::sync::Arc;

use crate::{cache::DnsCache, metrics::Metrics};

#[derive(Clone)]
pub struct ProxyContext {
    pub dns_cache: Arc<DnsCache>,
    pub metrics: Arc<Metrics>,
}