// Threat Intelligence Integration (400+ lines)
use crate::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntel {
    pub indicator: String,
    pub indicator_type: IndicatorType,
    pub threat_level: ThreatLevel,
    pub first_seen: u64,
    pub last_seen: u64,
    pub source: String,
    pub confidence: f64,
    pub tags: Vec<String>,
    pub related_vulns: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum IndicatorType {
    IpAddress,
    Domain,
    Url,
    FileHash,
    EmailAddress,
    ThreatActor,
    Malware,
    Exploit,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ThreatLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityIntel {
    pub cve_id: String,
    pub description: String,
    pub severity: String,
    pub cvss_score: f64,
    pub published_date: u64,
    pub exploit_available: bool,
    pub in_the_wild: bool,
    pub exploit_urls: Vec<String>,
    pub affected_products: Vec<String>,
}

pub struct ThreatIntelligenceEngine {
    threat_db: HashMap<String, ThreatIntel>,
    vuln_db: HashMap<String, VulnerabilityIntel>,
    ip_reputation: HashMap<String, f64>,
    domain_reputation: HashMap<String, f64>,
}

impl ThreatIntelligenceEngine {
    pub fn new() -> Self {
        Self {
            threat_db: HashMap::new(),
            vuln_db: HashMap::new(),
            ip_reputation: HashMap::new(),
            domain_reputation: HashMap::new(),
        }
    }

    /// Query threat intelligence
    pub fn query_threat(&self, indicator: &str) -> Option<ThreatIntel> {
        self.threat_db.get(indicator).cloned()
    }

    /// Query vulnerability intelligence
    pub fn query_vulnerability(&self, cve_id: &str) -> Option<VulnerabilityIntel> {
        self.vuln_db.get(cve_id).cloned()
    }

    /// Add threat indicator
    pub fn add_threat(
        &mut self,
        indicator: String,
        indicator_type: IndicatorType,
        threat_level: ThreatLevel,
    ) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let intel = ThreatIntel {
            indicator: indicator.clone(),
            indicator_type,
            threat_level,
            first_seen: now,
            last_seen: now,
            source: "internal_db".to_string(),
            confidence: 0.95,
            tags: vec![],
            related_vulns: vec![],
        };

        self.threat_db.insert(indicator, intel);
        Ok(())
    }

    /// Add vulnerability
    pub fn add_vulnerability(&mut self, vuln: VulnerabilityIntel) -> Result<()> {
        self.vuln_db.insert(vuln.cve_id.clone(), vuln);
        Ok(())
    }

    /// Check URL reputation
    pub fn check_url_reputation(&self, url: &str) -> Result<f64> {
        // Extract domain from URL
        let domain = self.extract_domain(url);
        let reputation = self.domain_reputation.get(domain).copied().unwrap_or(0.5);
        Ok(reputation)
    }

    /// Check IP reputation
    pub fn check_ip_reputation(&self, ip: &str) -> Result<f64> {
        let reputation = self.ip_reputation.get(ip).copied().unwrap_or(0.5);
        Ok(reputation)
    }

    /// Get active exploits
    pub fn get_active_exploits(&self) -> Vec<VulnerabilityIntel> {
        self.vuln_db
            .values()
            .filter(|v| v.in_the_wild && v.exploit_available)
            .cloned()
            .collect()
    }

    /// Get recent threats
    pub fn get_recent_threats(&self, hours: u64) -> Vec<ThreatIntel> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let threshold = now - (hours * 3600);

        self.threat_db
            .values()
            .filter(|t| t.last_seen >= threshold)
            .cloned()
            .collect()
    }

    /// Correlate threat with vulnerabilities
    pub fn correlate_threat(&self, threat: &ThreatIntel) -> Vec<VulnerabilityIntel> {
        self.vuln_db
            .values()
            .filter(|vuln| {
                threat
                    .related_vulns
                    .contains(&vuln.cve_id)
            })
            .cloned()
            .collect()
    }

    /// Build threat profile from multiple indicators
    pub fn build_threat_profile(&self, indicators: &[&str]) -> Result<ThreatProfile> {
        let mut threats = Vec::new();
        let mut total_score = 0.0;
        let mut critical_count = 0;

        for indicator in indicators {
            if let Some(threat) = self.query_threat(indicator) {
                total_score += threat.confidence;
                if threat.threat_level == ThreatLevel::Critical {
                    critical_count += 1;
                }
                threats.push(threat);
            }
        }

        let avg_confidence = if !threats.is_empty() {
            total_score / threats.len() as f64
        } else {
            0.0
        };

        let overall_level = if critical_count > 0 {
            ThreatLevel::Critical
        } else if threats.iter().any(|t| t.threat_level == ThreatLevel::High) {
            ThreatLevel::High
        } else if threats.iter().any(|t| t.threat_level == ThreatLevel::Medium) {
            ThreatLevel::Medium
        } else {
            ThreatLevel::Low
        };

        Ok(ThreatProfile {
            indicators: indicators.iter().map(|s| s.to_string()).collect(),
            threats,
            overall_threat_level: overall_level,
            confidence: avg_confidence,
            recommended_action: self.get_recommended_action(overall_level),
        })
    }

    /// Check for zero-day patterns
    pub fn check_zero_day_patterns(&self, payload: &str) -> Result<Vec<String>> {
        let mut patterns = Vec::new();

        // Check for known exploit signatures (simplified)
        if payload.contains("ROP") || payload.contains("gadget") {
            patterns.push("Possible ROP chain detected".to_string());
        }

        if payload.contains("shellcode") || payload.contains("\\x90\\x90") {
            patterns.push("Possible shellcode injection".to_string());
        }

        if payload.contains("syscall") || payload.contains("int 0x80") {
            patterns.push("Possible system call invocation".to_string());
        }

        Ok(patterns)
    }

    /// Update threat intelligence from external feeds
    pub fn update_from_feed(&mut self, feed_data: Vec<ThreatIntel>) -> Result<usize> {
        let mut count = 0;
        for threat in feed_data {
            let updated = self.threat_db.contains_key(&threat.indicator);
            self.threat_db.insert(threat.indicator.clone(), threat);
            if !updated {
                count += 1;
            }
        }
        Ok(count)
    }

    // Helper methods

    fn extract_domain<'a>(&self, url: &'a str) -> &'a str {
        if let Some(start) = url.find("://") {
            let after_scheme = &url[start + 3..];
            if let Some(end) = after_scheme.find('/') {
                &after_scheme[..end]
            } else {
                after_scheme
            }
        } else {
            url
        }
    }

    fn get_recommended_action(&self, level: ThreatLevel) -> String {
        match level {
            ThreatLevel::Critical => "Block immediately and escalate to security team".to_string(),
            ThreatLevel::High => "Block and investigate".to_string(),
            ThreatLevel::Medium => "Monitor and log".to_string(),
            ThreatLevel::Low => "Log for analysis".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatProfile {
    pub indicators: Vec<String>,
    pub threats: Vec<ThreatIntel>,
    pub overall_threat_level: ThreatLevel,
    pub confidence: f64,
    pub recommended_action: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_level_ordering() {
        assert!(ThreatLevel::Critical > ThreatLevel::High);
        assert!(ThreatLevel::High > ThreatLevel::Medium);
        assert!(ThreatLevel::Medium > ThreatLevel::Low);
    }

    #[test]
    fn test_indicator_type_differentiation() {
        assert_ne!(IndicatorType::IpAddress, IndicatorType::Domain);
        assert_ne!(IndicatorType::FileHash, IndicatorType::Malware);
    }

    #[test]
    fn test_engine_initialization() {
        let engine = ThreatIntelligenceEngine::new();
        assert_eq!(engine.threat_db.len(), 0);
        assert_eq!(engine.vuln_db.len(), 0);
    }

    #[test]
    fn test_add_threat() {
        let mut engine = ThreatIntelligenceEngine::new();
        engine
            .add_threat(
                "192.168.1.1".to_string(),
                IndicatorType::IpAddress,
                ThreatLevel::High,
            )
            .unwrap();

        assert_eq!(engine.threat_db.len(), 1);
    }

    #[test]
    fn test_query_threat() {
        let mut engine = ThreatIntelligenceEngine::new();
        engine
            .add_threat(
                "malicious.com".to_string(),
                IndicatorType::Domain,
                ThreatLevel::Critical,
            )
            .unwrap();

        let threat = engine.query_threat("malicious.com");
        assert!(threat.is_some());
        assert_eq!(threat.unwrap().threat_level, ThreatLevel::Critical);
    }

    #[test]
    fn test_extract_domain() {
        let engine = ThreatIntelligenceEngine::new();
        let domain = engine.extract_domain("http://example.com/path");
        assert_eq!(domain, "example.com");
    }

    #[test]
    fn test_vulnerability_intel() {
        let vuln = VulnerabilityIntel {
            cve_id: "CVE-2024-1234".to_string(),
            description: "Test vulnerability".to_string(),
            severity: "Critical".to_string(),
            cvss_score: 9.8,
            published_date: 1234567890,
            exploit_available: true,
            in_the_wild: true,
            exploit_urls: vec!["http://exploit.com".to_string()],
            affected_products: vec!["Product A".to_string()],
        };

        assert_eq!(vuln.cve_id, "CVE-2024-1234");
        assert!(vuln.exploit_available);
    }

    #[test]
    fn test_get_recommended_action() {
        let engine = ThreatIntelligenceEngine::new();

        let critical_action = engine.get_recommended_action(ThreatLevel::Critical);
        assert!(critical_action.contains("Block immediately"));

        let low_action = engine.get_recommended_action(ThreatLevel::Low);
        assert!(low_action.contains("Log"));
    }

    #[test]
    fn test_zero_day_pattern_detection() {
        let engine = ThreatIntelligenceEngine::new();
        let patterns = engine.check_zero_day_patterns("ROP gadget shellcode").unwrap();
        assert!(patterns.len() >= 2);
    }

    #[test]
    fn test_active_exploits() {
        let mut engine = ThreatIntelligenceEngine::new();

        let vuln = VulnerabilityIntel {
            cve_id: "CVE-2024-9999".to_string(),
            description: "Active exploit".to_string(),
            severity: "Critical".to_string(),
            cvss_score: 9.9,
            published_date: 1234567890,
            exploit_available: true,
            in_the_wild: true,
            exploit_urls: vec![],
            affected_products: vec![],
        };

        engine.add_vulnerability(vuln).unwrap();
        let active = engine.get_active_exploits();
        assert_eq!(active.len(), 1);
    }

    #[test]
    fn test_threat_profile_building() {
        let mut engine = ThreatIntelligenceEngine::new();

        engine
            .add_threat(
                "threat1".to_string(),
                IndicatorType::IpAddress,
                ThreatLevel::High,
            )
            .unwrap();

        engine
            .add_threat(
                "threat2".to_string(),
                IndicatorType::Domain,
                ThreatLevel::Medium,
            )
            .unwrap();

        let profile = engine
            .build_threat_profile(&["threat1", "threat2"])
            .unwrap();
        assert_eq!(profile.indicators.len(), 2);
        assert!(profile.confidence > 0.0);
    }
}
