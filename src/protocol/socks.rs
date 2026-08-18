use std::net::{Ipv4Addr, Ipv6Addr};

use crate::protocol::socks_error::SocksError;

enum Command {
    Connect,
}
enum Address {
    Ipv4(Ipv4Addr),
    Domain(String),
    Ipv6(Ipv6Addr),
}
struct Destination {
    address: Address,
    port: u16,
}
struct Request {
    destination: Destination,
    command: Command,
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
