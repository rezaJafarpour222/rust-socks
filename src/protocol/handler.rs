use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _, copy_bidirectional},
    net::TcpStream,
};

use crate::protocol::{
    socks_error::SocksError,
    socks_five::{connect_destination, read_request, send_failure, send_success},
};

pub async fn proxy(stream: &mut TcpStream) -> Result<(), SocksError> {
    negotiate(stream).await?;

    let request = read_request(stream).await?;

    println!("received SOCKS5 {request:?}");

    let mut remote_stream = match connect_destination(&request.destination).await {
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

async fn negotiate(stream: &mut TcpStream) -> Result<(), SocksError> {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await.unwrap();
    if header[0] != 0x05 {
        println!("not a SOCKS5 client");
        return Err(SocksError::InvalidVersion(header[0]));
    }
    let mut methods = vec![0u8; header[1] as usize];
    stream.read_exact(&mut methods).await.unwrap();
    if methods.contains(&0x00) {
        stream.write_all(&[0x05, 0x00]).await?;
    } else {
        stream.write_all(&[0x05, 0xff]).await?;
        return Err(SocksError::NoAcceptableMethod);
    }
    Ok(())
}
