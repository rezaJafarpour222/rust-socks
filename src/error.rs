use std::io;

#[derive(Debug)]
pub enum ProxyError {
    Io(io::Error),
    UnknownProtocol,
    Protocol(String),
}

impl From<io::Error> for ProxyError {
    fn from(value: io::Error) -> Self {
        ProxyError::Io(value)
    }
}

impl From<crate::protocol::socks_error::SocksError> for ProxyError {
    fn from(value: crate::protocol::socks_error::SocksError) -> Self {
        match value {
            crate::protocol::socks_error::SocksError::Io(err) => ProxyError::Io(err),
            other => ProxyError::Protocol(format!("{other:?}")),
        }
    }
}

impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}