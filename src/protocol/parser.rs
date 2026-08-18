use std::net::{Ipv4Addr, Ipv6Addr};

use tokio::{io::AsyncReadExt, net::TcpStream};

use crate::protocol::{
    socks::{Address, AddressKind},
    socks_error::SocksError,
};

pub async fn read_address(
    stream: &mut TcpStream,
    kind: AddressKind,
) -> Result<Address, SocksError> {
    match kind {
        AddressKind::Ipv4 => {
            let mut bytes = [0u8; 4];
            stream.read_exact(&mut bytes).await?;
            Ok(Address::Ipv4(Ipv4Addr::from(bytes)))
        }
        AddressKind::Domain => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await?;
            let mut bytes = vec![0u8; length[0] as usize];
            stream.read_exact(&mut bytes).await?;
            let domain = String::from_utf8(bytes).map_err(|_| SocksError::InvalidDomain)?;
            Ok(Address::Domain(domain))
        }
        AddressKind::Ipv6 => {
            let mut bytes = [0u8; 16];
            stream.read_exact(&mut bytes).await?;
            Ok(Address::Ipv6(Ipv6Addr::from(bytes)))
        }
    }
}
