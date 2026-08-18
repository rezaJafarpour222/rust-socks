use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

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
            println!("version:{}", header[0]);
            println!("nmethods:{}", header[1]);
            println!("methods:{:02x?}", methods);
            if methods.contains(&0x00) {
                stream.write_all(&[0x05, 0x00]).await.unwrap();
            } else {
                stream.write_all(&[0x05, 0xff]).await.unwrap();
            }
        });
    }
}
