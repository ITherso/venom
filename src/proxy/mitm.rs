use crate::Result;
use std::net::SocketAddr;
use std::path::Path;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt, AsyncRead, AsyncWrite};
use std::sync::Arc;
use super::tls::TlsConfig;
use super::history::ProxyHistory;
use super::ca::CertificateAuthority;
use super::tls_server::TlsServer;
use super::http_parser::{HttpParser, HttpRequest, HttpResponse};
use super::interceptor::RequestInterceptor;
use crate::scanner::VulnerabilityDetector;
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
        let tls_server = TlsServer::new(Arc::clone(&tls_config.cert_cache));
        handle_connect_tunnel(client, &request_line, tls_server, history).await?;
    } else {
        // Handle HTTP request
        handle_http_request(&mut client, &request_line, history).await?;
    }

    Ok(())
}

async fn handle_connect_tunnel(
    mut client: TcpStream,
    request_line: &str,
    tls_server: TlsServer,
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

    // Send 200 OK to client (establish tunnel)
    let response = b"HTTP/1.1 200 Connection Established\r\n\r\n";
    client
        .write_all(response)
        .await
        .map_err(|e| crate::Error::ProxyError(e.to_string()))?;

    println!("[+] Sent 200 OK to client");

    // Accept TLS from client using generated cert
    println!("[*] Accepting TLS from client...");
    let client_tls = match tls_server.accept_client_tls(client, domain).await {
        Ok(s) => {
            println!("[+] Client TLS handshake complete");
            s
        }
        Err(e) => {
            eprintln!("[!] Client TLS failed: {}", e);
            return Err(e);
        }
    };

    // Connect to target server with TLS
    println!("[*] Connecting to target: {}", target_host);
    let target_raw = match TcpStream::connect(target_host).await {
        Ok(s) => {
            println!("[+] Connected to target");
            s
        }
        Err(e) => {
            eprintln!("[!] Target connection failed: {}", e);
            return Err(crate::Error::ProxyError(format!("Target connect failed: {}", e)));
        }
    };

    // Establish TLS with target server
    println!("[*] Establishing TLS with target...");
    let target_tls = match tls_server.connect_server_tls(target_raw, domain).await {
        Ok(s) => {
            println!("[+] Target TLS established");
            s
        }
        Err(e) => {
            eprintln!("[!] Target TLS failed: {}", e);
            return Err(e);
        }
    };

    println!("[✓] HTTPS tunnel ready (TLS decryption active)");

    // Create interceptor (can add rules via CLI/API in future)
    let interceptor = Arc::new(RequestInterceptor::new());

    // Relay decrypted traffic
    relay_https_traffic(client_tls, target_tls, history, interceptor).await?;

    Ok(())
}

async fn relay_https_traffic<C, S>(
    client_tls: C,
    server_tls: S,
    history: Arc<ProxyHistory>,
    interceptor: Arc<RequestInterceptor>,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    println!("[*] Relaying decrypted HTTPS traffic with interception...");

    let (mut client_read, mut client_write) = tokio::io::split(client_tls);
    let (mut server_read, mut server_write) = tokio::io::split(server_tls);

    // Request forwarding: client → server
    let c2s = async {
        let mut buf = vec![0u8; 16384];
        loop {
            match client_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    // Try to parse HTTP request
                    let mut forward = true;
                    if let Ok((mut req, _)) = HttpParser::parse_request(&buf[..n]) {
                        println!("[+] Request: {} {}", req.method, req.path);

                        // Scan for vulnerabilities
                        let vulns = VulnerabilityDetector::scan_request(&req);
                        if !vulns.is_empty() {
                            println!("[!] Vulnerabilities found: {}", vulns.len());
                            for v in &vulns {
                                println!("    - {}: {}", v.vuln_type, v.evidence);
                            }
                        }

                        // Apply interception rules
                        if interceptor.should_intercept_request(&req) {
                            println!("[*] Interception rule matched");
                            if let Err(_) = interceptor.apply_request_modifications(&mut req) {
                                println!("[!] Request dropped by interception rule");
                                forward = false;
                            } else {
                                // Re-serialize modified request
                                let modified_bytes = HttpParser::serialize_request(&req);
                                let _ = server_write.write_all(&modified_bytes).await;
                                forward = false;
                            }
                        }

                        // Log request to database
                        let _ = history.log_request(&req).await;
                    }

                    // Forward original request if not intercepted
                    if forward {
                        let _ = server_write.write_all(&buf[..n]).await;
                    }
                }
                Err(_) => break,
            }
        }
    };

    // Response forwarding: server → client
    let s2c = async {
        let mut buf = vec![0u8; 16384];
        loop {
            match server_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    // Try to parse HTTP response
                    let mut forward = true;
                    if let Ok((mut res, _)) = HttpParser::parse_response(&buf[..n]) {
                        println!("[+] Response: {} {}", res.status_code, res.reason);

                        // Apply interception rules to response
                        if interceptor.should_intercept_response(&res) {
                            println!("[*] Response interception rule matched");
                            if let Err(_) = interceptor.apply_response_modifications(&mut res) {
                                println!("[!] Response dropped by interception rule");
                                forward = false;
                            } else {
                                // Re-serialize modified response
                                let modified_bytes = HttpParser::serialize_response(&res);
                                let _ = client_write.write_all(&modified_bytes).await;
                                forward = false;
                            }
                        }

                        // Log response to database
                        let _ = history.log_response(&res).await;
                    }

                    // Forward original response if not intercepted
                    if forward {
                        let _ = client_write.write_all(&buf[..n]).await;
                    }
                }
                Err(_) => break,
            }
        }
    };

    tokio::select! {
        _ = c2s => {},
        _ = s2c => {},
    }

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
