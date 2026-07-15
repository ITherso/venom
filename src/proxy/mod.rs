use crate::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Clone)]
pub struct ProxyConfig {
    pub listen_addr: SocketAddr,
}

pub struct MitmProxy {
    config: ProxyConfig,
    listener: Arc<tokio::sync::Mutex<Option<TcpListener>>>,
}

impl MitmProxy {
    pub async fn new(host: &str, port: u16) -> Result<Self> {
        let addr = format!("{}:{}", host, port)
            .parse::<SocketAddr>()
            .map_err(|_| crate::Error::ProxyError("Invalid address".into()))?;

        Ok(Self {
            config: ProxyConfig {
                listen_addr: addr,
            },
            listener: Arc::new(tokio::sync::Mutex::new(None)),
        })
    }

    pub async fn start(&self) -> Result<()> {
        let listener = TcpListener::bind(self.config.listen_addr)
            .await
            .map_err(|e| crate::Error::ProxyError(e.to_string()))?;

        println!("[+] MITM Proxy listening on {}", self.config.listen_addr);

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    println!("[*] New connection from {}", addr);
                    tokio::spawn(handle_connection(stream));
                }
                Err(e) => {
                    eprintln!("[!] Accept error: {}", e);
                }
            }
        }
    }
}

async fn handle_connection(mut stream: TcpStream) {
    let mut buffer = [0u8; 4096];

    match stream.read(&mut buffer).await {
        Ok(n) if n > 0 => {
            let request = String::from_utf8_lossy(&buffer[..n]);
            println!("[*] Received request:\n{}", request);

            let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
            let _ = stream.write_all(response).await;
        }
        _ => {}
    }
}
