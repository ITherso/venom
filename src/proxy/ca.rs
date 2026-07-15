use crate::Result;
use rcgen::{Certificate, CertificateParams};
use std::fs;
use std::path::{Path, PathBuf};

pub struct CertificateAuthority {
    ca_path: PathBuf,
    ca_cert: Certificate,
    ca_key_pem: String,
    ca_cert_pem: String,
}

impl CertificateAuthority {
    pub fn new(ca_dir: &Path) -> Result<Self> {
        fs::create_dir_all(ca_dir)
            .map_err(|e| crate::Error::ProxyError(format!("Failed to create CA dir: {}", e)))?;

        let key_path = ca_dir.join("ca.key");
        let cert_path = ca_dir.join("ca.crt");
        let certs_dir = ca_dir.join("certs");

        fs::create_dir_all(&certs_dir)
            .map_err(|e| crate::Error::ProxyError(format!("Failed to create certs dir: {}", e)))?;

        if key_path.exists() && cert_path.exists() {
            let ca_key_pem = fs::read_to_string(&key_path)
                .map_err(|e| crate::Error::ProxyError(format!("Failed to read CA key: {}", e)))?;

            let ca_cert_pem = fs::read_to_string(&cert_path)
                .map_err(|e| crate::Error::ProxyError(format!("Failed to read CA cert: {}", e)))?;

            println!("[+] Loaded existing CA from {:?}", ca_dir);

            // Dummy cert for struct (we don't use it for signing in real impl)
            let (_, cert_pem) = Self::generate_root_cert()?;
            let ca_cert = Certificate::from_params(CertificateParams::default())
                .map_err(|e| crate::Error::ProxyError(e.to_string()))?;

            return Ok(Self {
                ca_path: ca_dir.to_path_buf(),
                ca_cert,
                ca_key_pem,
                ca_cert_pem,
            });
        }

        let (key_pem, cert_pem) = Self::generate_root_cert()?;

        fs::write(&key_path, &key_pem)
            .map_err(|e| crate::Error::ProxyError(format!("Failed to write CA key: {}", e)))?;

        fs::write(&cert_path, &cert_pem)
            .map_err(|e| crate::Error::ProxyError(format!("Failed to write CA cert: {}", e)))?;

        println!("[+] Generated new CA at {:?}", ca_dir);
        println!("[!] Import CA cert in browser: {}", cert_path.display());

        let ca_cert = Certificate::from_params(CertificateParams::default())
            .map_err(|e| crate::Error::ProxyError(e.to_string()))?;

        Ok(Self {
            ca_path: ca_dir.to_path_buf(),
            ca_cert,
            ca_key_pem: key_pem,
            ca_cert_pem: cert_pem,
        })
    }

    fn generate_root_cert() -> Result<(String, String)> {
        let mut params = CertificateParams::new(vec!["VENOM Root CA".to_string()]);
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

        let cert = Certificate::from_params(params)
            .map_err(|e| crate::Error::ProxyError(e.to_string()))?;

        let key_pem = cert
            .serialize_private_key_pem()
            .to_string();
        let cert_pem = cert
            .serialize_pem()
            .map_err(|e| crate::Error::ProxyError(e.to_string()))?;

        Ok((key_pem, cert_pem))
    }

    pub fn generate_cert_for_domain(&self, domain: &str) -> Result<(String, String)> {
        let cert_path = self.ca_path.join("certs").join(format!("{}.crt", domain));
        let key_path = self.ca_path.join("certs").join(format!("{}.key", domain));

        if cert_path.exists() && key_path.exists() {
            let key = fs::read_to_string(&key_path)
                .map_err(|e| crate::Error::ProxyError(e.to_string()))?;
            let cert = fs::read_to_string(&cert_path)
                .map_err(|e| crate::Error::ProxyError(e.to_string()))?;
            return Ok((key, cert));
        }

        let mut params = CertificateParams::new(vec![domain.to_string()]);

        let cert = Certificate::from_params(params)
            .map_err(|e| crate::Error::ProxyError(e.to_string()))?;

        let key_pem = cert.serialize_private_key_pem();
        let cert_pem = cert
            .serialize_pem()
            .map_err(|e| crate::Error::ProxyError(e.to_string()))?;

        fs::write(&key_path, &key_pem)
            .map_err(|e| crate::Error::ProxyError(e.to_string()))?;
        fs::write(&cert_path, &cert_pem)
            .map_err(|e| crate::Error::ProxyError(e.to_string()))?;

        println!("[+] Generated cert for {}", domain);

        Ok((key_pem, cert_pem))
    }

    pub fn ca_cert_path(&self) -> PathBuf {
        self.ca_path.join("ca.crt")
    }
}
