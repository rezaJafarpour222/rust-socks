//NOTE: SOCKS5 Handshake
//Client
// +----+----------+----------+
// |VER | NMETHODS | METHODS  |
// +----+----------+----------+
// | 1  |    1     | 1..255   |
// +----+----------+----------+
// 05 02 00 02 => Version 5(05),2 authentication method(02) methods:[no authentication (00),USERNAME_PASSWORD(02)]
// -------------------------------------------------------------------------------------------------------------------
// Server
// +----+--------+
// |VER | METHOD |
// +----+--------+
// | 1  |   1    |
// +----+--------+
// 05 02 => Version 5(05),USERNAME_PASSWORD authentication(02)

//NOTE: SOCKS5 Authentication
// Client
// +----+------+----------+------+----------+
// |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
// +----+------+----------+------+----------+
// | 1  |  1   | 1..255   |  1   | 1..255   |
// +----+------+----------+------+----------+
// 01 05 alice 08 secret => auth version(01), username_length(05), username(alice), pass_length(08), password(secret)
// -------------------------------------------------------------------------------------------------------------------
// Server
// +----+--------+
// |VER | STATUS |
// +----+--------+
// | 1  |   1    |
// +----+--------+
// Success: 01 00, Failure: 01 01

//NOTE:SOCKS Reqeust
// Client
// +----+-----+-------+------+----------+------+
// |VER | CMD |  RSV  | ATYP | DST.ADDR | PORT |
// +----+-----+-------+------+----------+------+
// | 1  |  1  |  1    |  1   | Variable |  2   |
// +----+-----+-------+------+----------+------+
// Ver:05, ,RSV: reserved,must be 00
// CMD:command[Connect:01]
// ATYP:address_type(ipv4,ipv6,domain)
// DST.ADDR:destination address
// PORT:destination port
// -------------------------------------------------------------------------------------------------------------------
// Server
// +----+-----+-------+------+----------+------+
// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
// +----+-----+-------+------+----------+------+
// | 1  |  1  |  1    |  1   | Variable |  2   |
// +----+-----+-------+------+----------+------+
// rep:SOCKS server failue [00:succeded,01..08:errors]

//NOTE:SOCKS5 ATYP Interperetation
// ATYP = 04
// +----+----------+
// |ATYP| IPv6     |
// +----+----------+
// | 04 | 16 bytes |
// +----+----------+
// -------------------------------------------------------------------------------------------------------------------
// ATYP = 01
// +----+----------+
// |ATYP| IPv4     |
// +----+----------+
// | 01 | 4 bytes  |
// +----+----------+
// -------------------------------------------------------------------------------------------------------------------
// ATYP = 03
//
// +----+------+----------+
// |ATYP| LEN  | DOMAIN   |
// +----+------+----------+
// | 03 |  1   | Variable |
// +----+------+----------+

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, lookup_host};

use crate::protocol::constants;
use crate::{cache::DnsCache, protocol::socks_error::SocksError};

#[derive(Debug)]
pub enum Command {
    Connect,
}

#[derive(Debug)]
pub enum Address {
    Ipv4(Ipv4Addr),
    Domain(String),
    Ipv6(Ipv6Addr),
}

#[derive(Debug)]

pub enum AddressKind {
    Ipv4,
    Domain,
    Ipv6,
}

#[derive(Debug)]
pub struct Destination {
    pub address: Address,
    pub port: u16,
}

#[derive(Debug)]
pub struct Request {
    pub destination: Destination,
    pub command: Command,
}

fn parse_command(value: u8) -> Result<Command, SocksError> {
    const CONNECT_COMMAND: u8 = 0x01;
    match value {
        CONNECT_COMMAND => Ok(Command::Connect),
        value => Err(SocksError::UnsupportedCommand(value)),
    }
}

fn parse_version(value: u8) -> Result<(), SocksError> {
    match value {
        constants::SOCKS5_VERSION => Ok(()),
        value => Err(SocksError::InvalidVersion(value)),
    }
}
fn parse_reserved(value: u8) -> Result<(), SocksError> {
    match value {
        constants::RESERVED => Ok(()),
        value => Err(SocksError::InvalidReserved(value)),
    }
}
fn parse_address_kind(value: u8) -> Result<AddressKind, SocksError> {
    match value {
        constants::ADDRESS_TYPE_IPV4 => Ok(AddressKind::Ipv4),
        constants::ADDRESS_TYPE_DOMAIN => Ok(AddressKind::Domain),
        constants::ADDRESS_TYPE_IPV6 => Ok(AddressKind::Ipv6),
        value => Err(SocksError::UnsupportedAddressType(value)),
    }
}
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
pub async fn read_request(stream: &mut TcpStream) -> Result<Request, SocksError> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    parse_version(header[0])?;
    let command = parse_command(header[1])?;
    parse_reserved(header[2])?;
    let kind = parse_address_kind(header[3])?;
    let address = read_address(stream, kind).await?;
    let mut port_bytes = [0u8; 2];
    stream.read_exact(&mut port_bytes).await?;
    let port = u16::from_be_bytes(port_bytes);

    Ok(Request {
        command,
        destination: Destination { address, port },
    })
}

pub async fn connect_destination(
    destination: &Destination,
    dns_cache: &DnsCache,
) -> Result<TcpStream, SocksError> {
    match &destination.address {
        Address::Domain(domain) => {
            let started = Instant::now();

            let addresses = match dns_cache.get(domain) {
                Some(addresses) => addresses,
                None => {
                    let addresses: Vec<IpAddr> = lookup_host((domain.as_str(), destination.port))
                        .await?
                        .map(|address| address.ip())
                        .collect();
                    dns_cache.insert(domain.clone(), addresses.clone());
                    addresses
                }
            };
            tracing::info!(
                event = "dns_lookup_time",
                time = started.elapsed().as_secs_f64() * 1000.0
            );

            for address in addresses {
                let socket_address = SocketAddr::new(address, destination.port);

                match TcpStream::connect(socket_address).await {
                    Ok(stream) => return Ok(stream),
                    Err(_) => continue,
                }
            }

            Err(SocksError::ConnectFailed)
        }
        Address::Ipv4(address) => {
            tracing::info!(
                event = "address_type",
                address=%address
            );
            let v4_address = SocketAddr::new(std::net::IpAddr::V4(*address), destination.port);
            match TcpStream::connect(v4_address).await {
                Ok(stream) => Ok(stream),
                Err(_) => Err(SocksError::ConnectFailed),
            }
        }
        Address::Ipv6(address) => {
            tracing::info!(
                event = "address_type",
                address=%address
            );
            let v6_address = SocketAddr::new(std::net::IpAddr::V6(*address), destination.port);
            match TcpStream::connect(v6_address).await {
                Ok(stream) => Ok(stream),
                Err(_) => Err(SocksError::ConnectFailed),
            }
        }
    }
}

const SUCCESS_REPLY: [u8; 10] = [
    constants::SOCKS5_VERSION,
    constants::REPLY_SUCCEEDED,
    constants::RESERVED,
    constants::ADDRESS_TYPE_IPV4,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
];
pub async fn send_success(stream: &mut TcpStream) -> Result<(), SocksError> {
    stream.write_all(&SUCCESS_REPLY).await?;
    Ok(())
}
pub async fn send_failure(stream: &mut TcpStream, reply: u8) -> Result<(), SocksError> {
    let response = [
        constants::SOCKS5_VERSION,
        reply,
        constants::RESERVED,
        constants::ADDRESS_TYPE_IPV4,
        constants::EMPTY_IPV4[0],
        constants::EMPTY_IPV4[1],
        constants::EMPTY_IPV4[2],
        constants::EMPTY_IPV4[3],
        constants::EMPTY_PORT[0],
        constants::EMPTY_PORT[1],
    ];

    stream.write_all(&response).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_version() {
        assert!(parse_version(constants::SOCKS5_VERSION).is_ok());
    }

    #[test]
    fn parse_invalid_version() {
        let result = parse_version(0x04);

        assert!(matches!(result, Err(SocksError::InvalidVersion(0x04))));
    }

    #[test]
    fn parse_connect_command() {
        assert!(matches!(parse_command(0x01), Ok(Command::Connect)));
    }

    #[test]
    fn parse_unsupported_command() {
        let result = parse_command(0x02);

        assert!(matches!(result, Err(SocksError::UnsupportedCommand(0x02))));
    }

    #[test]
    fn parse_valid_reserved_byte() {
        assert!(parse_reserved(0x00).is_ok());
    }

    #[test]
    fn parse_invalid_reserved_byte() {
        let result = parse_reserved(0x01);

        assert!(matches!(result, Err(SocksError::InvalidReserved(0x01))));
    }

    #[test]
    fn parse_ipv4_address_kind() {
        assert!(matches!(parse_address_kind(0x01), Ok(AddressKind::Ipv4)));
    }

    #[test]
    fn parse_domain_address_kind() {
        assert!(matches!(parse_address_kind(0x03), Ok(AddressKind::Domain)));
    }

    #[test]
    fn parse_ipv6_address_kind() {
        assert!(matches!(parse_address_kind(0x04), Ok(AddressKind::Ipv6)));
    }
}
