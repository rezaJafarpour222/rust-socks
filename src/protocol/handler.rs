use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _, copy_bidirectional_with_sizes},
    net::TcpStream,
};

use crate::{
    cache::DnsCache,
    protocol::{
        constants,
        socks_error::SocksError,
        socks_five::{self, connect_destination, read_request, send_failure, send_success},
    },
};
pub async fn proxy(stream: &mut TcpStream, dns_cache: &DnsCache) -> Result<(), SocksError> {
    negotiate(stream).await?;

    let request = read_request(stream).await?;

    tracing::info!(
        event = "request_begin",
        "{:?}:{:?}",
        request.destination.address,
        request.destination.port
    );

    let mut remote_stream = match connect_destination(&request.destination, dns_cache).await {
        Ok(stream) => stream,
        Err(err) => {
            tracing::info!(event = "connection_failed", "{:?}", err);
            send_failure(stream, constants::REPLY_GENERAL_FAILURE).await?;
            return Ok(());
        }
    };

    send_success(stream).await?;
    stream.set_nodelay(true)?;
    remote_stream.set_nodelay(true)?;
    let (from_client, from_server) =
        copy_bidirectional_with_sizes(stream, &mut remote_stream, 64 * 1024, 64 * 1024).await?;

    tracing::info!(
        event = "request_finished",
        from_client = from_client,
        from_server = from_server
    );

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

    let valid = username == "admin" && password == "password";
    if valid {
        stream
            .write_all(&[constants::AUTH_VERSION, constants::AUTH_SUCCESS])
            .await?;
        return Ok(());
    }

    stream
        .write_all(&[constants::AUTH_VERSION, constants::AUTH_FAILURE])
        .await?;

    Err(SocksError::AuthenticationFailed)
}
