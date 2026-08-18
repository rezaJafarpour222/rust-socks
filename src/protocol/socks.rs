use std::net::{Ipv4Addr, Ipv6Addr};

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
    pub address: Address,
    pub port: u16,
}
pub struct Request {
    pub destination: Destination,
    pub command: Command,
}
