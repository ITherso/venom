// VENOM Proxy - MITM, CA management, TLS interception
use venom_core::Result;

pub struct ProxyServer {
    addr: String,
    port: u16,
}

impl ProxyServer {
    pub fn new(addr: String, port: u16) -> Self {
        Self { addr, port }
    }

    pub async fn start(&self) -> Result<()> {
        println!("Proxy starting on {}:{}", self.addr, self.port);
        Ok(())
    }
}
