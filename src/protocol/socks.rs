use std::net::{Ipv4Addr, Ipv6Addr};

use crate::protocol::socks_error::SocksError;

pub enum Command {
    Connect,
}
pub enum Address {
    Ipv4(Ipv4Addr),
    Domain(String),
    Ipv6(Ipv6Addr),
}

pub enum AddressKind {
    Ipv4,
    Domain,
    Ipv6,
}
pub struct Destination {
    address: Address,
    port: u16,
}
pub struct Request {
    destination: Destination,
    command: Command,
}

pub fn parse_command(value: u8) -> Result<Command, SocksError> {
    match value {
        0x01 => Ok(Command::Connect),
        value => Err(SocksError::UnsupportedCommand(value)),
    }
}

pub fn parse_version(value: u8) -> Result<(), SocksError> {
    match value {
        0x05 => Ok(()),
        value => Err(SocksError::InvalidVersion(value)),
    }
}
pub fn parse_reserved(value: u8) -> Result<(), SocksError> {
    match value {
        0x00 => Ok(()),
        value => Err(SocksError::InvalidReserved(value)),
    }
}
pub fn parse_address_kind(value: u8) -> Result<AddressKind, SocksError> {
    match value {
        0x01 => Ok(AddressKind::Ipv4),
        0x03 => Ok(AddressKind::Domain),
        0x04 => Ok(AddressKind::Ipv6),
        value => Err(SocksError::UnsupportedAddressType(value)),
    }
}
