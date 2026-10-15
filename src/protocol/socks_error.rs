#[derive(Debug)]
pub enum SocksError {
    Io(std::io::Error),
    InvalidVersion(u8),
    UnsupportedCommand(u8),
    InvalidReserved(u8),
    UnsupportedAddressType(u8),
    InvalidDomain,
    ConnectFailed,
    AuthenticationFailed,
    NoAcceptableMethod,
    TimeOut,
    InvalidUdpHeader,
}
impl From<std::io::Error> for SocksError {
    fn from(value: std::io::Error) -> Self {
        SocksError::Io(value)
    }
}
