use std::{
    io::Error,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _, copy_bidirectional_with_sizes},
    net::{TcpStream, lookup_host},
    task::JoinSet,
    time::sleep,
};

use crate::{
    cache::DnsCache,
    metrics::Metrics,
    protocol::{
        constants,
        socks_error::SocksError,
        socks_five::{Address, Destination, read_request, send_failure, send_success},
    },
};

const BUFFER_SIZE: usize = 64 * 1024;
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(1);
const HAPPY_EYEBALLS_DELAY: Duration = Duration::from_millis(50);

pub async fn proxy(
    stream: &mut TcpStream,
    dns_cache: &DnsCache,
    metrics: &Metrics,
) -> Result<(), SocksError> {
    negotiate(stream).await?;

    let request = read_request(stream).await?;

    let mut remote_stream =
        match connect_destination(&request.destination, dns_cache, metrics).await {
            Ok(stream) => stream,

            Err(err) => {
                tracing::error!(service = "socks5", error = ?err);

                send_failure(stream, constants::REPLY_GENERAL_FAILURE).await?;

                return Ok(());
            }
        };

    send_success(stream).await?;

    metrics.add_connection();

    stream.set_nodelay(true)?;
    remote_stream.set_nodelay(true)?;

    let (from_client, from_server) =
        copy_bidirectional_with_sizes(stream, &mut remote_stream, BUFFER_SIZE, BUFFER_SIZE).await?;

    // tracing::debug!(
    //     service = "socks",
    //     event = "request_finished",
    //     from_client = from_client,
    //     from_server = from_server,
    // );
    metrics.add_uploaded(from_server);
    metrics.add_downloaded(from_client);

    metrics.remove_connection();

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

    // tracing::debug!(
    //     service="socks5",
    //     event = "socks_handshake",
    //     methods = ?methods,
    // );

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

        // tracing::info!(
        //     service="socks5",
        //     event = "auth_success",
        //     username = %username,
        // );

        return Ok(());
    }

    stream
        .write_all(&[constants::AUTH_VERSION, constants::AUTH_FAILURE])
        .await?;

    Err(SocksError::AuthenticationFailed)
}

pub fn check_user(username: &str, password: &str) -> bool {
    username == "reza" && password == "SDSEWwew4SckkjSA_%"
}

pub async fn connect_destination(
    destination: &Destination,
    dns_cache: &DnsCache,
    metrics: &Metrics,
) -> Result<TcpStream, SocksError> {
    match &destination.address {
        Address::Domain(domain) => {
            // let started = Instant::now();

            let addresses = dns_lookup(domain, destination.port, dns_cache, &metrics).await?;

            // tracing::debug!(
            //     service="socks5",
            //     event = "dns_lookup_time",
            //     time_ms = started.elapsed().as_secs_f64() * 1000.0,
            // );

            happy_eyeballs(addresses, destination.port).await
        }

        Address::Ipv4(address) => {
            // tracing::debug!(
            //     service="socks5",
            //     event = "address_type",
            //     address = %address,
            // );

            let socket_addr = SocketAddr::new(IpAddr::V4(*address), destination.port);

            connect_with_timeout(socket_addr).await
        }

        Address::Ipv6(address) => {
            // tracing::debug!(
            //     service="socks5",
            //     event = "address_type",
            //     address = %address,
            // );

            let socket_addr = SocketAddr::new(IpAddr::V6(*address), destination.port);

            connect_with_timeout(socket_addr).await
        }
    }
}

async fn connect_with_timeout(address: SocketAddr) -> Result<TcpStream, SocksError> {
    // tracing::debug!(
    //     service="socks5",
    //     event = "connection_attempt",
    //     address = %address,
    // );

    match tokio::time::timeout(CONNECTION_TIMEOUT, TcpStream::connect(address)).await {
        Ok(Ok(stream)) => {
            // tracing::info!(
            //     service="socks5",
            //     event = "connection_success",
            //     address = %address,
            // );

            Ok(stream)
        }

        Ok(Err(_)) => {
            // tracing::warn!(
            //     service="socks5",
            //     event = "connection_failed",
            //     address = %address,
            //     error = %err,
            // );

            Err(SocksError::ConnectFailed)
        }

        Err(_) => {
            // tracing::warn!(
            //     service="socks5",
            //     event = "connection_timeout",
            //     address = %address,
            //     timeout_ms = CONNECTION_TIMEOUT.as_millis(),
            // );

            Err(SocksError::TimeOut)
        }
    }
}

async fn dns_lookup(
    domain: &String,
    port: u16,
    dns_cache: &DnsCache,
    metrics: &Metrics,
) -> Result<Vec<IpAddr>, Error> {
    let addresses = match dns_cache.get(domain) {
        Some(addresses) => {
            metrics.add_dns_cache_hit();
            addresses
        }

        None => {
            metrics.add_dns_cache_miss();
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

pub async fn happy_eyeballs(addresses: Vec<IpAddr>, port: u16) -> Result<TcpStream, SocksError> {
    let mut attempts = JoinSet::new();

    for (index, address) in addresses.into_iter().enumerate() {
        let delay = HAPPY_EYEBALLS_DELAY * index as u32;

        attempts.spawn(async move {
            if delay > Duration::ZERO {
                sleep(delay).await;
            }

            let socket_addr = SocketAddr::new(address, port);

            // tracing::debug!(
            //     service="socks5",
            //     event = "happy_eyeballs_attempt",
            //     delay_ms = delay.as_millis(),
            // );

            connect_with_timeout(socket_addr).await
        });
    }

    while let Some(result) = attempts.join_next().await {
        match result {
            Ok(Ok(stream)) => {
                attempts.abort_all();

                return Ok(stream);
            }

            Ok(Err(_)) => {
                // tracing::debug!(
                //     service="socks5",
                //     event = "happy_eyeballs_failed",
                //     error = ?err,
                // );
            }

            Err(_) => {
                // tracing::debug!(
                //     service="socks5",
                //     event = "happy_eyeballs_task_failed",
                //     error = %err,
                // );
            }
        }
    }

    Err(SocksError::ConnectFailed)
}
