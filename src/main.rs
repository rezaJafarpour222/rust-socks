pub mod protocol;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional},
    net::TcpListener,
};

use crate::protocol::socks_five::{connect_destination, read_request, send_failure, send_success};

#[tokio::main]
async fn main() {
    let listener = TcpListener::bind("127.0.0.1:1080").await.unwrap();
    loop {
        let (mut stream, _) = listener.accept().await.unwrap();
        tokio::spawn(async move {
            let mut header = [0u8; 2];
            stream.read_exact(&mut header).await.unwrap();

            if header[0] != 0x05 {
                println!("not a SOCKS5 client");
                return;
            }
            let mut methods = vec![0u8; header[1] as usize];
            stream.read_exact(&mut methods).await.unwrap();
            if methods.contains(&0x00) {
                stream.write_all(&[0x05, 0x00]).await.unwrap();
            } else {
                stream.write_all(&[0x05, 0xff]).await.unwrap();
            }
            match read_request(&mut stream).await {
                Ok(request) => {
                    println!("received Socks 5 {request:?}");
                    match connect_destination(&request.destination).await {
                        Ok(mut remote_stream) => {
                            send_success(&mut stream).await.unwrap();
                            match copy_bidirectional(&mut stream, &mut remote_stream).await {
                                Ok((from_client, from_server)) => {
                                    println!(
                                        "connection closed: client->server={} bytes, server->client={} bytes",
                                        from_client, from_server
                                    );
                                }
                                Err(err) => {
                                    println!("proxy error:{err}")
                                }
                            }
                        }
                        Err(err) => send_failure(&mut stream, 0x01).await.unwrap(),
                    }
                }
                Err(err) => {
                    println!("Socks5 error{:?}", err);
                }
            }
        });
    }
}
