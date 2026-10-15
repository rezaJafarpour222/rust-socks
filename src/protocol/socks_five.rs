use std::net::{Ipv4Addr, Ipv6Addr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::protocol::constants;
use crate::protocol::socks_error::SocksError;

#[derive(Debug)]
pub enum Command {
    Connect,
    UdpAssociate,
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

#[derive(Debug)]
pub struct UdpPacket {
    pub fragment: u8,
    pub destination: Destination,
    pub payload_offset: usize,
}

fn parse_command(value: u8) -> Result<Command, SocksError> {
    match value {
        constants::COMMAND_CONNECT => Ok(Command::Connect),
        constants::COMMAND_UDP_ASSOCIATE => Ok(Command::UdpAssociate),
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

pub async fn read_address<S>(stream: &mut S, kind: AddressKind) -> Result<Address, SocksError>
where
    S: AsyncRead + Unpin,
{
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

pub async fn read_request<S>(stream: &mut S) -> Result<Request, SocksError>
where
    S: AsyncRead + Unpin,
{
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

pub async fn send_success<S>(stream: &mut S) -> Result<(), SocksError>
where
    S: AsyncWrite + Unpin,
{
    stream.write_all(&SUCCESS_REPLY).await?;
    stream.flush().await?;

    Ok(())
}

pub async fn send_failure<S>(stream: &mut S, reply: u8) -> Result<(), SocksError>
where
    S: AsyncWrite + Unpin,
{
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
    stream.flush().await?;

    Ok(())
}

pub async fn send_udp_success<S>(stream: &mut S, bind_addr: std::net::SocketAddr) -> Result<(), SocksError>
where
    S: AsyncWrite + Unpin,
{
    use std::net::IpAddr;

    let mut response = Vec::with_capacity(22);

    response.push(constants::SOCKS5_VERSION);
    response.push(constants::REPLY_SUCCEEDED);
    response.push(constants::RESERVED);

    match bind_addr.ip() {
        IpAddr::V4(ip) => {
            response.push(constants::ADDRESS_TYPE_IPV4);
            response.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            response.push(constants::ADDRESS_TYPE_IPV6);
            response.extend_from_slice(&ip.octets());
        }
    }

    response.extend_from_slice(&bind_addr.port().to_be_bytes());

    stream.write_all(&response).await?;
    stream.flush().await?;

    Ok(())
}

pub fn parse_udp_packet(data: &[u8]) -> Result<UdpPacket, SocksError> {
    if data.len() < 4 {
        return Err(SocksError::InvalidUdpHeader);
    }

    // RSV must be zero.
    if data[0] != 0 || data[1] != 0 {
        return Err(SocksError::InvalidReserved(data[0]));
    }

    let fragment = data[2];

    let kind = parse_address_kind(data[3])?;

    let mut offset = 4usize;

    let address = match kind {
        AddressKind::Ipv4 => {
            if offset + 4 + 2 > data.len() {
                return Err(SocksError::InvalidUdpHeader);
            }

            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&data[offset..offset + 4]);
            offset += 4;

            Address::Ipv4(std::net::Ipv4Addr::from(bytes))
        }

        AddressKind::Domain => {
            if offset + 1 > data.len() {
                return Err(SocksError::InvalidUdpHeader);
            }

            let length = data[offset] as usize;
            offset += 1;

            if offset + length + 2 > data.len() {
                return Err(SocksError::InvalidUdpHeader);
            }

            let domain = String::from_utf8(data[offset..offset + length].to_vec())
                .map_err(|_| SocksError::InvalidDomain)?;
            offset += length;

            Address::Domain(domain)
        }

        AddressKind::Ipv6 => {
            if offset + 16 + 2 > data.len() {
                return Err(SocksError::InvalidUdpHeader);
            }

            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&data[offset..offset + 16]);
            offset += 16;

            Address::Ipv6(std::net::Ipv6Addr::from(bytes))
        }
    };

    if offset + 2 > data.len() {
        return Err(SocksError::InvalidUdpHeader);
    }

    let port = u16::from_be_bytes([data[offset], data[offset + 1]]);
    offset += 2;

    Ok(UdpPacket {
        fragment,
        destination: Destination { address, port },
        payload_offset: offset,
    })
}

pub fn parse_udp_header(data: &[u8]) -> Result<UdpPacket, SocksError> {
    parse_udp_packet(data)
}

pub fn parse_udp_request(data: &[u8]) -> Result<UdpPacket, SocksError> {
    parse_udp_packet(data)
}

pub fn build_udp_response(source: std::net::SocketAddr, payload: &[u8]) -> Vec<u8> {
    build_udp_packet(source, 0, payload)
}

pub fn build_udp_packet(
    source: std::net::SocketAddr,
    fragment: u8,
    payload: &[u8],
) -> Vec<u8> {
    use std::net::IpAddr;

    let mut packet = Vec::with_capacity(payload.len() + 10);

    packet.push(0x00);
    packet.push(0x00);
    packet.push(fragment);

    match source.ip() {
        IpAddr::V4(ip) => {
            packet.push(constants::ADDRESS_TYPE_IPV4);
            packet.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            packet.push(constants::ADDRESS_TYPE_IPV6);
            packet.extend_from_slice(&ip.octets());
        }
    }

    packet.extend_from_slice(&source.port().to_be_bytes());
    packet.extend_from_slice(payload);

    packet
}

pub fn build_udp_datagram(
    source: std::net::SocketAddr,
    fragment: u8,
    payload: &[u8],
) -> Vec<u8> {
    build_udp_packet(source, fragment, payload)
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

    #[test]
    fn parse_udp_ipv4_packet() {
        let data = [0x00, 0x00, 0x00, 0x01, 192, 0, 2, 1, 0, 80, 1, 2, 3];
        let packet = parse_udp_packet(&data).unwrap();
        assert_eq!(packet.fragment, 0);
        assert_eq!(packet.payload_offset, 10);
        assert!(matches!(packet.destination.address, Address::Ipv4(_)));
    }

    #[test]
    fn parse_udp_domain_packet() {
        let mut data = vec![0x00, 0x00, 0x00, 0x03, 0x0b];
        data.extend_from_slice(b"example.com");
        data.extend_from_slice(&[0x01, 0xbb]);
        data.extend_from_slice(b"payload");
        let packet = parse_udp_packet(&data).unwrap();
        assert_eq!(packet.payload_offset, 4 + 1 + 11 + 2);
        assert_eq!(&data[packet.payload_offset..], b"payload");
    }

    #[test]
    fn build_udp_response_round_trips_payload() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 53);
        let packet = build_udp_response(addr, b"hello");
        assert_eq!(packet[0], 0x00);
        assert_eq!(packet[1], 0x00);
        assert_eq!(packet[2], 0x00);
        assert_eq!(packet[3], constants::ADDRESS_TYPE_IPV4);
        assert_eq!(&packet[10..], b"hello");
    }
}
