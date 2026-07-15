use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SourceType {
    ExploitDB,
    MITRE,
    NVD,
    GitHub,
    SecurityAdvisories,
    Metasploit,
    PacketStorm,
    ZeroDayInitiative,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataSource {
    pub name: String,
    pub source_type: SourceType,
    pub endpoint: String,
    pub api_key: Option<String>,
    pub rate_limit: usize,
    pub timeout_seconds: u64,
}

impl DataSource {
    /// ExploitDB source
    pub fn exploitdb() -> Self {
        Self {
            name: "ExploitDB".to_string(),
            source_type: SourceType::ExploitDB,
            endpoint: "https://www.exploit-db.com/api".to_string(),
            api_key: None,
            rate_limit: 1000,
            timeout_seconds: 30,
        }
    }

    /// MITRE CVE source
    pub fn mitre() -> Self {
        Self {
            name: "MITRE CVE".to_string(),
            source_type: SourceType::MITRE,
            endpoint: "https://cve.mitre.org/api".to_string(),
            api_key: None,
            rate_limit: 500,
            timeout_seconds: 30,
        }
    }

    /// NIST NVD source
    pub fn nvd() -> Self {
        Self {
            name: "NIST NVD".to_string(),
            source_type: SourceType::NVD,
            endpoint: "https://services.nvd.nist.gov/rest/json/cves".to_string(),
            api_key: None,
            rate_limit: 500,
            timeout_seconds: 30,
        }
    }

    /// GitHub security advisories
    pub fn github() -> Self {
        Self {
            name: "GitHub Security".to_string(),
            source_type: SourceType::GitHub,
            endpoint: "https://api.github.com/graphql".to_string(),
            api_key: None,
            rate_limit: 5000,
            timeout_seconds: 30,
        }
    }

    /// Metasploit module source
    pub fn metasploit() -> Self {
        Self {
            name: "Metasploit".to_string(),
            source_type: SourceType::Metasploit,
            endpoint: "https://www.metasploit.com/api".to_string(),
            api_key: None,
            rate_limit: 1000,
            timeout_seconds: 30,
        }
    }

    /// Packet Storm source
    pub fn packetstorm() -> Self {
        Self {
            name: "Packet Storm".to_string(),
            source_type: SourceType::PacketStorm,
            endpoint: "https://packetstormsecurity.com/api".to_string(),
            api_key: None,
            rate_limit: 500,
            timeout_seconds: 30,
        }
    }

    /// Zero Day Initiative source
    pub fn zdi() -> Self {
        Self {
            name: "Zero Day Initiative".to_string(),
            source_type: SourceType::ZeroDayInitiative,
            endpoint: "https://zerodayinitiative.com/api".to_string(),
            api_key: None,
            rate_limit: 100,
            timeout_seconds: 30,
        }
    }

    /// Custom source
    pub fn custom(name: String, endpoint: String) -> Self {
        Self {
            name,
            source_type: SourceType::Custom,
            endpoint,
            api_key: None,
            rate_limit: 1000,
            timeout_seconds: 30,
        }
    }

    pub fn with_api_key(mut self, key: String) -> Self {
        self.api_key = Some(key);
        self
    }

    pub fn with_rate_limit(mut self, limit: usize) -> Self {
        self.rate_limit = limit;
        self
    }

    pub fn with_timeout(mut self, seconds: u64) -> Self {
        self.timeout_seconds = seconds;
        self
    }

    pub fn get_url_format(&self) -> String {
        match self.source_type {
            SourceType::ExploitDB => {
                format!("{}/search?q={{query}}&type={{type}}", self.endpoint)
            }
            SourceType::MITRE => {
                format!("{}/cves/{{cve_id}}", self.endpoint)
            }
            SourceType::NVD => {
                format!("{}/{{version}}/{{keyword}}", self.endpoint)
            }
            SourceType::GitHub => {
                format!("{}/repositories/{{owner}}/security/advisories", self.endpoint)
            }
            SourceType::SecurityAdvisories => {
                format!("{}/advisories/{{query}}", self.endpoint)
            }
            SourceType::Metasploit => {
                format!("{}/modules/search/{{query}}", self.endpoint)
            }
            SourceType::PacketStorm => {
                format!("{}/search/{{query}}", self.endpoint)
            }
            SourceType::ZeroDayInitiative => {
                format!("{}/exploits/{{cve_id}}", self.endpoint)
            }
            SourceType::Custom => self.endpoint.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceManager {
    sources: std::collections::HashMap<String, DataSource>,
}

impl SourceManager {
    pub fn new() -> Self {
        Self {
            sources: std::collections::HashMap::new(),
        }
    }

    pub fn with_defaults() -> Self {
        let mut manager = Self::new();

        manager.add_source("exploitdb", DataSource::exploitdb());
        manager.add_source("mitre", DataSource::mitre());
        manager.add_source("nvd", DataSource::nvd());
        manager.add_source("github", DataSource::github());
        manager.add_source("metasploit", DataSource::metasploit());
        manager.add_source("packetstorm", DataSource::packetstorm());
        manager.add_source("zdi", DataSource::zdi());

        manager
    }

    pub fn add_source(&mut self, key: &str, source: DataSource) {
        self.sources.insert(key.to_string(), source);
    }

    pub fn get_source(&self, key: &str) -> Option<&DataSource> {
        self.sources.get(key)
    }

    pub fn remove_source(&mut self, key: &str) -> Option<DataSource> {
        self.sources.remove(key)
    }

    pub fn list_sources(&self) -> Vec<&DataSource> {
        self.sources.values().collect()
    }

    pub fn get_by_type(&self, source_type: SourceType) -> Vec<&DataSource> {
        self.sources
            .values()
            .filter(|s| s.source_type == source_type)
            .collect()
    }
}

impl Default for SourceManager {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exploitdb_source() {
        let source = DataSource::exploitdb();
        assert_eq!(source.source_type, SourceType::ExploitDB);
    }

    #[test]
    fn test_custom_source() {
        let source = DataSource::custom(
            "CustomDB".to_string(),
            "https://custom.com/api".to_string(),
        );
        assert_eq!(source.source_type, SourceType::Custom);
    }

    #[test]
    fn test_source_manager() {
        let manager = SourceManager::with_defaults();
        assert!(manager.get_source("exploitdb").is_some());
        assert!(manager.get_source("mitre").is_some());
    }

    #[test]
    fn test_source_url_format() {
        let source = DataSource::mitre();
        let url = source.get_url_format();
        assert!(url.contains("{cve_id}"));
    }
}
