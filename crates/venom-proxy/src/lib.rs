// VENOM Proxy - MITM, CA management, TLS interception
pub mod mitm;

pub use mitm::{AsyncMitmProxy, CertCache};

pub struct ProxyServer {
    addr: String,
    port: u16,
}

impl ProxyServer {
    pub fn new(addr: String, port: u16) -> Self {
        Self { addr, port }
    }

    pub async fn start(&self) -> Result<()> {
        let listen_addr = format!("{}:{}", self.addr, self.port);
        let proxy = AsyncMitmProxy::new(&listen_addr, "127.0.0.1:80".to_string()).await?;
        proxy.start().await
    }
}

type Result<T> = std::io::Result<T>;
