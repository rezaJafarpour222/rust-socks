use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use tokio::net::{TcpStream, lookup_host};

use crate::protocol::socks_error::SocksError;
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
    match value {
        0x01 => Ok(Command::Connect),
        value => Err(SocksError::UnsupportedCommand(value)),
    }
}

fn parse_version(value: u8) -> Result<(), SocksError> {
    match value {
        0x05 => Ok(()),
        value => Err(SocksError::InvalidVersion(value)),
    }
}
fn parse_reserved(value: u8) -> Result<(), SocksError> {
    match value {
        0x00 => Ok(()),
        value => Err(SocksError::InvalidReserved(value)),
    }
}
fn parse_address_kind(value: u8) -> Result<AddressKind, SocksError> {
    match value {
        0x01 => Ok(AddressKind::Ipv4),
        0x03 => Ok(AddressKind::Domain),
        0x04 => Ok(AddressKind::Ipv6),
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

pub async fn connect_destination(destination: &Destination) -> Result<TcpStream, SocksError> {
    match &destination.address {
        Address::Domain(domain) => {
            let addresses = lookup_host((domain.as_str(), destination.port)).await?;

            for address in addresses {
                match TcpStream::connect(address).await {
                    Ok(stream) => return Ok(stream),
                    Err(_) => continue,
                }
            }
            Err(SocksError::ConnectFailed)
        }

        _ => {
            todo!("IPv4 and IPv6 later")
        }
    }
}

pub async fn send_success(stream: &mut TcpStream) -> Result<(), SocksError> {
    stream
        .write_all(&[
            0x05, // VER
            0x00, // REP = succeeded
            0x00, // RSV
            0x01, // ATYP = IPv4
            0x00, 0x00, 0x00, 0x00, // BND.ADDR
            0x00, 0x00, // BND.PORT
        ])
        .await?;
    Ok(())
}
pub async fn send_failure(stream: &mut TcpStream, reply: u8) -> Result<(), SocksError> {
    stream
        .write_all(&[0x05, reply, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        .await?;

    Ok(())
}
