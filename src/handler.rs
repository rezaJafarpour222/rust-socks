use std::{
    io::{self, Error},
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _, copy_bidirectional_with_sizes},
    net::{TcpStream, lookup_host},
    task::JoinSet,
};

use crate::{
    cache::DnsCache,
    protocol::{
        constants,
        socks_error::SocksError,
        socks_five::{Address, Destination, read_request, send_failure, send_success},
    },
};
use tokio::time::sleep;
pub async fn proxy(stream: &mut TcpStream, dns_cache: &DnsCache) -> Result<(), SocksError> {
    negotiate(stream).await?;
    const BUFFER_SIZE: usize = 64 * 1024;
    let request = read_request(stream).await?;

    let mut remote_stream = match connect_destination(&request.destination, dns_cache).await {
        Ok(stream) => stream,
        Err(_) => {
            send_failure(stream, constants::REPLY_GENERAL_FAILURE).await?;
            return Ok(());
        }
    };

    send_success(stream).await?;
    stream.set_nodelay(true)?;
    remote_stream.set_nodelay(true)?;
    let (_, _) =
        copy_bidirectional_with_sizes(stream, &mut remote_stream, BUFFER_SIZE, BUFFER_SIZE).await?;

    Ok(())
}

async fn negotiate(stream: &mut TcpStream) -> Result<(), SocksError> {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await?;

    let version = header[0];
    let method_count = header[1];

    if version != constants::SOCKS5_VERSION {
        return Err(SocksError::InvalidVersion(version));
    }

    let mut methods = vec![0u8; method_count as usize];
    stream.read_exact(&mut methods).await?;
    tracing::info!(event = "socks_handshake", methods = ?methods);

    if methods.contains(&constants::USERNAME_PASSWORD) {
        stream
            .write_all(&[constants::SOCKS5_VERSION, constants::USERNAME_PASSWORD])
            .await?;

        return authenticate(stream).await;
    }

    stream
        .write_all(&[constants::SOCKS5_VERSION, constants::NO_ACCEPTABLE_METHOD])
        .await?;

    Err(SocksError::NoAcceptableMethod)
}

async fn authenticate(stream: &mut TcpStream) -> Result<(), SocksError> {
    let mut version = [0u8; 1];
    stream.read_exact(&mut version).await?;
    if version[0] != constants::AUTH_VERSION {
        stream
            .write_all(&[constants::AUTH_VERSION, constants::AUTH_FAILURE])
            .await?;
        return Err(SocksError::AuthenticationFailed);
    }

    let mut username_len = [0u8; 1];
    stream.read_exact(&mut username_len).await?;
    let mut username = vec![0u8; username_len[0] as usize];
    stream.read_exact(&mut username).await?;

    let mut password_len = [0u8; 1];
    stream.read_exact(&mut password_len).await?;
    let mut password = vec![0u8; password_len[0] as usize];
    stream.read_exact(&mut password).await?;

    let username = String::from_utf8_lossy(&username);
    let password = String::from_utf8_lossy(&password);

    let valid = check_user(&username, &password);
    if valid {
        stream
            .write_all(&[constants::AUTH_VERSION, constants::AUTH_SUCCESS])
            .await?;
        tracing::info!(event = "AUTH_SUCCESS", username = ?username);
        return Ok(());
    }

    stream
        .write_all(&[constants::AUTH_VERSION, constants::AUTH_FAILURE])
        .await?;

    Err(SocksError::AuthenticationFailed)
}

pub fn check_user(username: &str, password: &str) -> bool {
    if username == "reza" && password == "SDSEWwew4SckkjSA_%" {
        return true;
    }
    false
}

pub async fn connect_destination(
    destination: &Destination,
    dns_cache: &DnsCache,
) -> Result<TcpStream, SocksError> {
    match &destination.address {
        Address::Domain(domain) => {
            let started = Instant::now();

            let addresses = dns_lookup(domain, destination.port, dns_cache).await?;
            tracing::info!(
                event = "dns_lookup_time",
                time = started.elapsed().as_secs_f64() * 1000.0
            );

            match happy_eyeballs(addresses, destination.port).await {
                Ok(stream) => Ok(stream),
                Err(_) => Err(SocksError::ConnectFailed),
            }
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
async fn dns_lookup(
    domain: &String,
    port: u16,
    dns_cache: &DnsCache,
) -> Result<Vec<IpAddr>, Error> {
    let addresses = match dns_cache.get(domain) {
        Some(addresses) => addresses,
        None => {
            let addresses: Vec<IpAddr> = lookup_host((domain.as_str(), port))
                .await?
                .map(|address| address.ip())
                .collect();
            dns_cache.insert(domain.clone(), addresses.clone());
            addresses
        }
    };
    Ok(addresses)
}
pub async fn happy_eyeballs(addresses: Vec<IpAddr>, port: u16) -> Result<TcpStream, Error> {
    let mut attempts = JoinSet::new();

    for (index, address) in addresses.into_iter().enumerate() {
        let delay = Duration::from_millis(index as u64 * 50);

        attempts.spawn(async move {
            if delay > Duration::ZERO {
                sleep(delay).await;
            }
            tracing::info!(event = "happy_eyeball", address = ?address,time=?delay);
            TcpStream::connect((address, port)).await
        });
    }
    while let Some(result) = attempts.join_next().await {
        match result {
            Ok(Ok(stream)) => {
                attempts.abort_all();
                tracing::info!(event = "happy_eyeball", address = ?stream);
                return Ok(stream);
            }
            Ok(Err(_)) => {}
            Err(_) => {}
        }
    }
    Err(std::io::Error::other("all connection attempts failed"))
}
