use crate::Result;
use rustls::pki_types::{PrivateKeyDer, ServerName};
use rustls::{ServerConfig, ClientConfig};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use super::tls::CertCache;

pub struct TlsServer {
    cert_cache: Arc<CertCache>,
}

impl TlsServer {
    pub fn new(cert_cache: Arc<CertCache>) -> Self {
        Self { cert_cache }
    }

    pub async fn accept_client_tls(
        &self,
        stream: TcpStream,
        domain: &str,
    ) -> Result<tokio_rustls::server::TlsStream<TcpStream>> {
        let (cert_pem, key_pem) = self.cert_cache.get_or_generate_cert(domain)?;

        let mut cert_reader = std::io::Cursor::new(&cert_pem);
        let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| crate::Error::ProxyError(format!("Failed to parse cert: {}", e)))?;

        let mut key_reader = std::io::Cursor::new(&key_pem);
        let key = rustls_pemfile::pkcs8_private_keys(&mut key_reader)
            .find_map(|result| result.ok())
            .map(PrivateKeyDer::Pkcs8)
            .ok_or_else(|| crate::Error::ProxyError("No valid key found".into()))?;

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| crate::Error::ProxyError(e.to_string()))?;

        let acceptor = TlsAcceptor::from(Arc::new(config));
        let tls_stream = acceptor
            .accept(stream)
            .await
            .map_err(|e| crate::Error::ProxyError(format!("TLS accept error: {}", e)))?;

        Ok(tls_stream)
    }

    pub async fn connect_server_tls(
        &self,
        stream: TcpStream,
        domain: &str,
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let server_name = ServerName::try_from(domain.to_string())
            .map_err(|_| crate::Error::ProxyError("Invalid domain".into()))?;

        let root_store = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect(),
        };

        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(config));
        let tls_stream = connector
            .connect(server_name, stream)
            .await
            .map_err(|e| crate::Error::ProxyError(format!("Server TLS error: {}", e)))?;

        Ok(tls_stream)
    }
}
