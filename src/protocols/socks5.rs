use std::{future::Future, pin::Pin};

use tokio::{
    io::{
        AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, copy_bidirectional_with_sizes,
    },
    net::UdpSocket,
};

use crate::{
    cache::DnsCache,
    context::ProxyContext,
    error::ProxyError,
    protocol::{
        constants,
        socks_error::SocksError,
        socks_five::{
            self, Address, Command, Destination, read_request, send_failure, send_success,
        },
    },
    protocols::{ClientStream, ProxyProtocol},
};

const BUFFER_SIZE: usize = 64 * 1024;

#[derive(Clone, Copy)]
pub struct Socks5Protocol;

impl ProxyProtocol for Socks5Protocol {
    fn name(&self) -> &'static str {
        "socks5"
    }

    fn supports(&self, peek: &[u8]) -> bool {
        peek.first().copied() == Some(constants::SOCKS5_VERSION)
    }

    fn handle<'a>(
        &'a self,
        stream: &'a mut ClientStream,
        ctx: ProxyContext,
    ) -> Pin<Box<dyn Future<Output = Result<(), ProxyError>> + Send + 'a>> {
        Box::pin(async move {
            proxy(stream, ctx.dns_cache.as_ref())
                .await
                .map_err(Into::into)
        })
    }
}

pub async fn proxy<S>(stream: &mut S, dns_cache: &DnsCache) -> Result<(), SocksError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    negotiate(stream).await?;

    let request = read_request(stream).await?;

    match request.command {
        Command::Connect => {
            tracing::debug!(
                service = "socks5",
                connection_type = "connect",
                "connection started"
            );
            let mut remote_stream =
                match crate::connect::connect_destination(&request.destination, dns_cache).await {
                    Ok(stream) => stream,
                    Err(err) => {
                        tracing::error!(service = "socks5", error = ?err);

                        send_failure(stream, constants::REPLY_GENERAL_FAILURE).await?;

                        return Ok(());
                    }
                };

            send_success(stream).await?;

            remote_stream.set_nodelay(true)?;

            let (_from_client, _from_server) =
                copy_bidirectional_with_sizes(stream, &mut remote_stream, BUFFER_SIZE, BUFFER_SIZE)
                    .await?;

            Ok(())
        }
        Command::UdpAssociate => {
            tracing::debug!(
                service = "socks5",
                connection_type = "udp_associate",
                "connection started"
            );
            udp_associate(stream, &request, dns_cache).await
        }
    }
}

async fn negotiate<S>(stream: &mut S) -> Result<(), SocksError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut header = [0u8; 2];

    stream.read_exact(&mut header).await?;

    let version = header[0];
    let method_count = header[1];

    if version != constants::SOCKS5_VERSION {
        return Err(SocksError::InvalidVersion(version));
    }

    let mut methods = vec![0u8; method_count as usize];

    stream.read_exact(&mut methods).await?;

    if methods.contains(&constants::USERNAME_PASSWORD) {
        stream
            .write_all(&[constants::SOCKS5_VERSION, constants::USERNAME_PASSWORD])
            .await?;
        stream.flush().await?;

        return authenticate(stream).await;
    }

    stream
        .write_all(&[constants::SOCKS5_VERSION, constants::NO_ACCEPTABLE_METHOD])
        .await?;
    stream.flush().await?;

    Err(SocksError::NoAcceptableMethod)
}

async fn authenticate<S>(stream: &mut S) -> Result<(), SocksError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut version = [0u8; 1];

    stream.read_exact(&mut version).await?;

    if version[0] != constants::AUTH_VERSION {
        stream
            .write_all(&[constants::AUTH_VERSION, constants::AUTH_FAILURE])
            .await?;
        stream.flush().await?;

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
        stream.flush().await?;

        return Ok(());
    }

    stream
        .write_all(&[constants::AUTH_VERSION, constants::AUTH_FAILURE])
        .await?;
    stream.flush().await?;

    Err(SocksError::AuthenticationFailed)
}

pub fn check_user(username: &str, password: &str) -> bool {
    match (std::env::var("PROXY_USERNAME"), std::env::var("PROXY_PASSWORD")) {
        (Ok(expected_user), Ok(expected_pass)) => {
            username == expected_user && password == expected_pass
        }
        _ => false,
    }
}

async fn udp_associate<S>(
    stream: &mut S,
    _request: &crate::protocol::socks_five::Request,
    dns_cache: &DnsCache,
) -> Result<(), SocksError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let socket = UdpSocket::bind(std::net::SocketAddr::from(([0, 0, 0, 0], 0))).await?;

    let local_port = socket.local_addr()?.port();
    let bind_addr = std::net::SocketAddr::new(crate::connect::detect_local_ip().await, local_port);

    socks_five::send_udp_success(stream, bind_addr).await?;
    stream.flush().await?;

    let mut client: Option<std::net::SocketAddr> = None;
    let mut buffer = vec![0u8; 65535];
    let mut tcp_probe = [0u8; 1];

    loop {
        tokio::select! {
            read_result = stream.read(&mut tcp_probe) => {
                match read_result {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }

            receive_result = socket.recv_from(&mut buffer) => {
                let (received, source) = receive_result?;

                if client.is_none() {
                    client = Some(source);
                }

                let Some(client_addr) = client else {
                    continue;
                };

                if source == client_addr {
                    let packet = match socks_five::parse_udp_packet(&buffer[..received]) {
                        Ok(packet) => packet,
                        Err(_) => continue,
                    };

                    if packet.fragment != 0 {
                        continue;
                    }

                    let payload = &buffer[packet.payload_offset..received];

                    let destination = match resolve_udp_destination(&packet.destination, dns_cache).await {
                        Ok(destination) => destination,
                        Err(_) => continue,
                    };

                    if socket.send_to(payload, destination).await.is_ok() {}
                } else {
                    let relayed = socks_five::build_udp_response(source, &buffer[..received]);
                    let _ = socket.send_to(&relayed, client_addr).await;
                }
            }
        }
    }

    Ok(())
}

async fn resolve_udp_destination(
    destination: &Destination,
    dns_cache: &DnsCache,
) -> Result<std::net::SocketAddr, SocksError> {
    match &destination.address {
        Address::Domain(domain) => {
            let addresses =
                crate::connect::dns_lookup(domain.as_str(), destination.port, dns_cache).await?;

            let ip = addresses
                .into_iter()
                .next()
                .ok_or(SocksError::ConnectFailed)?;

            Ok(std::net::SocketAddr::new(ip, destination.port))
        }

        Address::Ipv4(address) => Ok(std::net::SocketAddr::new(
            std::net::IpAddr::V4(*address),
            destination.port,
        )),

        Address::Ipv6(address) => Ok(std::net::SocketAddr::new(
            std::net::IpAddr::V6(*address),
            destination.port,
        )),
    }
}
