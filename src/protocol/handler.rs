use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _, copy_bidirectional},
    net::TcpStream,
};

use crate::{
    cache::DnsCache,
    protocol::{
        socks_error::SocksError,
        socks_five::{connect_destination, read_request, send_failure, send_success},
    },
};
pub async fn proxy(stream: &mut TcpStream, dns_cache: &DnsCache) -> Result<(), SocksError> {
    negotiate(stream).await?;

    let request = read_request(stream).await?;

    println!("received SOCKS5 {request:?}");

    let mut remote_stream = match connect_destination(&request.destination, dns_cache).await {
        Ok(stream) => stream,
        Err(err) => {
            println!("connection failed: {err:?}");
            send_failure(stream, 0x01).await?;
            return Ok(());
        }
    };

    send_success(stream).await?;

    let (from_client, from_server) = copy_bidirectional(stream, &mut remote_stream).await?;

    println!(
        "connection closed: client->server={} bytes, server->client={} bytes",
        from_client, from_server
    );

    Ok(())
}

const SOCKS5_VERSION: u8 = 0x05;
const NO_AUTH: u8 = 0x00;
const NO_ACCEPTABLE_METHOD: u8 = 0xff;
async fn negotiate(stream: &mut TcpStream) -> Result<(), SocksError> {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await?;

    let version = header[0];
    let method_count = header[1];

    if version != SOCKS5_VERSION {
        return Err(SocksError::InvalidVersion(version));
    }

    let mut methods = vec![0u8; method_count as usize];
    stream.read_exact(&mut methods).await?;

    if methods.contains(&NO_AUTH) {
        stream.write_all(&[SOCKS5_VERSION, NO_AUTH]).await?;

        return Ok(());
    }

    stream
        .write_all(&[SOCKS5_VERSION, NO_ACCEPTABLE_METHOD])
        .await?;

    Err(SocksError::NoAcceptableMethod)
}
