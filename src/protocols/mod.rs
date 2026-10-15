use std::{
    future::Future,
    pin::Pin,
};

use tokio::io::BufReader;
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;

use crate::{context::ProxyContext, error::ProxyError};

pub mod socks5;

pub type ClientStream = BufReader<TlsStream<TcpStream>>;

pub trait ProxyProtocol: Send + Sync {
    fn name(&self) -> &'static str;
    fn supports(&self, peek: &[u8]) -> bool;
    fn handle<'a>(
        &'a self,
        stream: &'a mut ClientStream,
        ctx: ProxyContext,
    ) -> Pin<Box<dyn Future<Output = Result<(), ProxyError>> + Send + 'a>>;
}

#[derive(Default)]
pub struct ProtocolRegistry {
    protocols: Vec<Box<dyn ProxyProtocol>>,
}

impl ProtocolRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_protocol(mut self, protocol: Box<dyn ProxyProtocol>) -> Self {
        self.protocols.push(protocol);
        self
    }

    pub fn detect(&self, peek: &[u8]) -> Option<&dyn ProxyProtocol> {
        self.protocols.iter().find(|p| p.supports(peek)).map(|p| p.as_ref())
    }

    pub fn default_registry() -> Self {
        Self {
            protocols: vec![Box::new(crate::protocols::socks5::Socks5Protocol)],
        }
    }
}