use crate::Result;
use rcgen::{Certificate, CertificateParams};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::fs;

pub struct CertCache {
    certs: Arc<Mutex<HashMap<String, (Vec<u8>, Vec<u8>)>>>,
    ca_cert: Certificate,
    ca_key_pem: Vec<u8>,
    cache_dir: PathBuf,
}

impl CertCache {
    pub fn new(ca_dir: &Path) -> Result<Self> {
        let ca_key_path = ca_dir.join("ca.key");
        let ca_cert_path = ca_dir.join("ca.crt");

        if !ca_key_path.exists() || !ca_cert_path.exists() {
            return Err(crate::Error::ProxyError(
                "CA cert not found. Run init-ca first.".into(),
            ));
        }

        let ca_key_pem = fs::read(&ca_key_path)
            .map_err(|e| crate::Error::ProxyError(format!("Failed to read CA key: {}", e)))?;

        let ca_cert_pem = fs::read_to_string(&ca_cert_path)
            .map_err(|e| crate::Error::ProxyError(format!("Failed to read CA cert: {}", e)))?;

        // Parse CA cert (for display only, we don't sign with it here)
        let ca_cert = Certificate::from_params(CertificateParams::default())
            .map_err(|e| crate::Error::ProxyError(e.to_string()))?;

        Ok(Self {
            certs: Arc::new(Mutex::new(HashMap::new())),
            ca_cert,
            ca_key_pem,
            cache_dir: ca_dir.join("certs"),
        })
    }

    pub fn get_or_generate_cert(&self, domain: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        // Check in-memory cache
        {
            let cache = self.certs.lock().unwrap();
            if let Some((cert, key)) = cache.get(domain) {
                println!("[*] Cert for {} from cache", domain);
                return Ok((cert.clone(), key.clone()));
            }
        }

        // Check disk cache
        let cert_path = self.cache_dir.join(format!("{}.crt", domain));
        let key_path = self.cache_dir.join(format!("{}.key", domain));

        if cert_path.exists() && key_path.exists() {
            let cert = fs::read(&cert_path)
                .map_err(|e| crate::Error::ProxyError(e.to_string()))?;
            let key = fs::read(&key_path)
                .map_err(|e| crate::Error::ProxyError(e.to_string()))?;

            // Store in memory cache
            {
                let mut cache = self.certs.lock().unwrap();
                cache.insert(domain.to_string(), (cert.clone(), key.clone()));
            }

            println!("[*] Cert for {} from disk", domain);
            return Ok((cert, key));
        }

        // Generate new cert
        println!("[+] Generating cert for {}", domain);
        let (cert, key) = self.generate_cert_for_domain(domain)?;

        // Save to disk
        fs::write(&cert_path, &cert)
            .map_err(|e| crate::Error::ProxyError(e.to_string()))?;
        fs::write(&key_path, &key)
            .map_err(|e| crate::Error::ProxyError(e.to_string()))?;

        // Store in memory cache
        {
            let mut cache = self.certs.lock().unwrap();
            cache.insert(domain.to_string(), (cert.clone(), key.clone()));
        }

        Ok((cert, key))
    }

    fn generate_cert_for_domain(&self, domain: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut params = CertificateParams::new(vec![
            domain.to_string(),
            format!("*.{}", domain),
        ]);

        let cert = Certificate::from_params(params)
            .map_err(|e| crate::Error::ProxyError(e.to_string()))?;

        let key_pem = cert
            .serialize_private_key_pem()
            .into_bytes();

        let cert_pem = cert
            .serialize_pem()
            .map_err(|e| crate::Error::ProxyError(e.to_string()))?
            .into_bytes();

        Ok((cert_pem, key_pem))
    }

    pub fn cache_size(&self) -> usize {
        self.certs.lock().unwrap().len()
    }

    pub fn clear_memory_cache(&self) {
        self.certs.lock().unwrap().clear();
        println!("[+] Memory certificate cache cleared");
    }
}

pub struct TlsConfig {
    pub cert_cache: Arc<CertCache>,
}

impl TlsConfig {
    pub fn new(ca_dir: &Path) -> Result<Self> {
        let cert_cache = Arc::new(CertCache::new(ca_dir)?);
        Ok(Self { cert_cache })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_cert_generation() {
        let temp_dir = TempDir::new().unwrap();
        let ca_dir = temp_dir.path();

        // Create dummy CA files for testing
        fs::write(ca_dir.join("ca.key"), "dummy").unwrap();
        fs::write(ca_dir.join("ca.crt"), "dummy").unwrap();
        fs::create_dir_all(ca_dir.join("certs")).unwrap();

        let cache = CertCache::new(ca_dir).unwrap();
        assert_eq!(cache.cache_size(), 0);
    }
}
