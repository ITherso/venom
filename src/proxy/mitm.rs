use crate::Result;
use std::net::SocketAddr;
use std::path::Path;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt, AsyncBufReadExt, BufReader};
use std::sync::Arc;
use super::tls::TlsConfig;
use super::history::ProxyHistory;
use super::ca::CertificateAuthority;
use sqlx::SqlitePool;

pub struct MitmServer {
    listen_addr: SocketAddr,
    tls_config: Arc<TlsConfig>,
    history: Arc<ProxyHistory>,
}

impl MitmServer {
    pub async fn new(
        host: &str,
        port: u16,
        ca_dir: &Path,
        pool: SqlitePool,
    ) -> Result<Self> {
        let addr = format!("{}:{}", host, port)
            .parse::<SocketAddr>()
            .map_err(|_| crate::Error::ProxyError("Invalid address".into()))?;

        // Initialize CA if not exists
        let _ = CertificateAuthority::new(ca_dir)?;

        let tls_config = Arc::new(TlsConfig::new(ca_dir)?);
        let history = Arc::new(ProxyHistory::new(pool));

        Ok(Self {
            listen_addr: addr,
            tls_config,
            history,
        })
    }

    pub async fn start(&self) -> Result<()> {
        let listener = TcpListener::bind(self.listen_addr)
            .await
            .map_err(|e| crate::Error::ProxyError(e.to_string()))?;

        println!("[+] MITM Server listening on {}", self.listen_addr);

        loop {
            match listener.accept().await {
                Ok((client, peer_addr)) => {
                    println!("[*] New connection from {}", peer_addr);

                    let tls_config = Arc::clone(&self.tls_config);
                    let history = Arc::clone(&self.history);

                    tokio::spawn(async move {
                        if let Err(e) = handle_client_connection(client, tls_config, history).await
                        {
                            eprintln!("[!] Client error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("[!] Accept error: {}", e);
                }
            }
        }
    }
}

async fn handle_client_connection(
    mut client: TcpStream,
    tls_config: Arc<TlsConfig>,
    history: Arc<ProxyHistory>,
) -> Result<()> {
    let mut buffer = vec![0u8; 4096];

    // Read HTTP request from client
    let n = client
        .read(&mut buffer)
        .await
        .map_err(|e| crate::Error::ProxyError(e.to_string()))?;

    if n == 0 {
        return Ok(());
    }

    let request_line = String::from_utf8_lossy(&buffer[..n]);
    println!("[*] Request:\n{}", request_line);

    // Parse CONNECT request (for HTTPS)
    if request_line.starts_with("CONNECT") {
        handle_connect_tunnel(&mut client, &request_line, tls_config, history).await?;
    } else {
        // Handle HTTP request
        handle_http_request(&mut client, &request_line, history).await?;
    }

    Ok(())
}

async fn handle_connect_tunnel(
    client: &mut TcpStream,
    request_line: &str,
    tls_config: Arc<TlsConfig>,
    history: Arc<ProxyHistory>,
) -> Result<()> {
    // Parse: CONNECT example.com:443 HTTP/1.1
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(crate::Error::ProxyError("Invalid CONNECT request".into()));
    }

    let target_host = parts[1];
    let domain = target_host.split(':').next().unwrap_or("");

    println!("[+] CONNECT tunnel to: {}", domain);

    // Get or generate certificate for domain
    let (cert_pem, key_pem) = tls_config.cert_cache.get_or_generate_cert(domain)?;

    // Send 200 OK to client
    let response = b"HTTP/1.1 200 Connection Established\r\n\r\n";
    client
        .write_all(response)
        .await
        .map_err(|e| crate::Error::ProxyError(e.to_string()))?;

    println!("[+] Established tunnel for {}", domain);

    // Note: Full TLS termination requires rustls server setup
    // This is simplified; real impl needs:
    // 1. rustls::ServerConfig with generated cert
    // 2. tokio_rustls::TlsStream wrapper
    // 3. Request/response parsing from decrypted stream

    Ok(())
}

async fn handle_http_request(
    client: &mut TcpStream,
    request_line: &str,
    history: Arc<ProxyHistory>,
) -> Result<()> {
    // Parse HTTP request
    let lines: Vec<&str> = request_line.lines().collect();
    if lines.is_empty() {
        return Err(crate::Error::ProxyError("Empty request".into()));
    }

    let request_parts: Vec<&str> = lines[0].split_whitespace().collect();
    let method = request_parts.get(0).unwrap_or(&"GET");
    let path = request_parts.get(1).unwrap_or(&"/");

    println!("[*] {} {}", method, path);

    // Simple response
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nVENOM"
    );

    client
        .write_all(response.as_bytes())
        .await
        .map_err(|e| crate::Error::ProxyError(e.to_string()))?;

    Ok(())
}
