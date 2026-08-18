pub mod protocol;

use tokio::net::TcpListener;

use crate::protocol::handler::proxy;

#[tokio::main]
async fn main() {
    let listener = TcpListener::bind("127.0.0.1:1080").await.unwrap();
    loop {
        let (mut stream, _) = listener.accept().await.unwrap();
        tokio::spawn(async move {
            if let Err(err) = proxy(&mut stream).await {
                println!("proxy error: {err:?}");
            }
        });
    }
}
