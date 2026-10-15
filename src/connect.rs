use std::{
    io::Error,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use tokio::{
    net::{TcpStream, UdpSocket, lookup_host},
    task::JoinSet,
    time::{sleep, timeout},
};

use crate::{
    cache::DnsCache,
    protocol::socks_five::{Address, Destination},
};

pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(1);
pub const HAPPY_EYEBALLS_DELAY: Duration = Duration::from_millis(50);

pub async fn connect_destination(
    destination: &Destination,
    dns_cache: &DnsCache,
) -> Result<TcpStream, crate::protocol::socks_error::SocksError> {
    match &destination.address {
        Address::Domain(domain) => {
            let addresses = dns_lookup(domain, destination.port, dns_cache).await?;

            happy_eyeballs(addresses, destination.port).await
        }

        Address::Ipv4(address) => {
            let socket_addr = SocketAddr::new(IpAddr::V4(*address), destination.port);

            connect_with_timeout(socket_addr).await
        }

        Address::Ipv6(address) => {
            let socket_addr = SocketAddr::new(IpAddr::V6(*address), destination.port);

            connect_with_timeout(socket_addr).await
        }
    }
}

pub async fn connect_with_timeout(
    address: SocketAddr,
) -> Result<TcpStream, crate::protocol::socks_error::SocksError> {
    match timeout(CONNECTION_TIMEOUT, TcpStream::connect(address)).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(_)) => Err(crate::protocol::socks_error::SocksError::ConnectFailed),
        Err(_) => Err(crate::protocol::socks_error::SocksError::TimeOut),
    }
}

pub async fn dns_lookup(
    domain: &str,
    port: u16,
    dns_cache: &DnsCache,
) -> Result<Vec<IpAddr>, Error> {
    let addresses = match dns_cache.get(domain) {
        Some(addresses) => addresses,

        None => {
            let addresses: Vec<IpAddr> = lookup_host((domain, port))
                .await?
                .map(|address| address.ip())
                .collect();

            dns_cache.insert(domain.to_string(), addresses.clone());

            addresses
        }
    };

    Ok(addresses)
}

pub async fn happy_eyeballs(
    addresses: Vec<IpAddr>,
    port: u16,
) -> Result<TcpStream, crate::protocol::socks_error::SocksError> {
    let mut attempts = JoinSet::new();

    for (index, address) in addresses.into_iter().enumerate() {
        let delay = HAPPY_EYEBALLS_DELAY * index as u32;

        attempts.spawn(async move {
            if delay > Duration::ZERO {
                sleep(delay).await;
            }

            let socket_addr = SocketAddr::new(address, port);

            connect_with_timeout(socket_addr).await
        });
    }

    while let Some(result) = attempts.join_next().await {
        match result {
            Ok(Ok(stream)) => {
                attempts.abort_all();
                return Ok(stream);
            }

            Ok(Err(_)) => {}

            Err(_) => {}
        }
    }

    Err(crate::protocol::socks_error::SocksError::ConnectFailed)
}

pub async fn detect_local_ip() -> std::net::IpAddr {
    if let Ok(socket) = UdpSocket::bind("0.0.0.0:0").await
        && socket.connect("8.8.8.8:80").await.is_ok()
        && let Ok(address) = socket.local_addr()
    {
        let ip = address.ip();

        if !ip.is_loopback() && !ip.is_unspecified() {
            return ip;
        }
    }

    std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
}