use crate::Result;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PentestReport {
    pub report_id: String,
    pub target_url: String,
    pub scan_date: DateTime<Utc>,
    pub scan_duration_minutes: u32,
    pub executive_summary: String,
    pub risk_score: f32, // 0.0 - 10.0
    pub vulnerabilities: Vec<VulnerabilityFinding>,
    pub exploits_used: Vec<ExploitUsed>,
    pub recommendations: Vec<Recommendation>,
    pub statistics: ReportStatistics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityFinding {
    pub id: String,
    pub title: String,
    pub severity: String, // critical, high, medium, low
    pub cvss_score: f32,  // 0.0 - 10.0
    pub cwe: String,      // CWE-89 for SQLi, etc
    pub description: String,
    pub affected_parameter: String,
    pub affected_url: String,
    pub evidence: String,
    pub proof_of_concept: String,
    pub remediation: RemediationGuidance,
    pub exploitation_path: Vec<String>,
    pub discovered_date: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationGuidance {
    pub summary: String,
    pub root_cause: String,
    pub technical_fix: String,
    pub code_example: String,
    pub testing_steps: Vec<String>,
    pub references: Vec<String>,
    pub priority: String,
    pub estimated_effort: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitUsed {
    pub exploit_id: String,
    pub name: String,
    pub vulnerability_type: String,
    pub payload: String,
    pub success: bool,
    pub timestamp: DateTime<Utc>,
    pub target_affected: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub priority: String,
    pub category: String,
    pub description: String,
    pub implementation_steps: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportStatistics {
    pub total_vulnerabilities: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub exploits_attempted: usize,
    pub exploits_successful: usize,
    pub urls_scanned: usize,
    pub endpoints_tested: usize,
}

impl PentestReport {
    pub fn new(target_url: &str, scan_duration_minutes: u32) -> Self {
        Self {
            report_id: format!("VENOM-{}", uuid::Uuid::new_v4()),
            target_url: target_url.to_string(),
            scan_date: Utc::now(),
            scan_duration_minutes,
            executive_summary: String::new(),
            risk_score: 0.0,
            vulnerabilities: Vec::new(),
            exploits_used: Vec::new(),
            recommendations: Vec::new(),
            statistics: ReportStatistics {
                total_vulnerabilities: 0,
                critical_count: 0,
                high_count: 0,
                medium_count: 0,
                low_count: 0,
                exploits_attempted: 0,
                exploits_successful: 0,
                urls_scanned: 0,
                endpoints_tested: 0,
            },
        }
    }

    pub fn add_vulnerability(&mut self, vuln: VulnerabilityFinding) {
        match vuln.severity.as_str() {
            "critical" => self.statistics.critical_count += 1,
            "high" => self.statistics.high_count += 1,
            "medium" => self.statistics.medium_count += 1,
            "low" => self.statistics.low_count += 1,
            _ => {}
        }
        self.statistics.total_vulnerabilities += 1;
        self.vulnerabilities.push(vuln);
        self.update_risk_score();
    }

    pub fn add_exploit(&mut self, exploit: ExploitUsed) {
        self.statistics.exploits_attempted += 1;
        if exploit.success {
            self.statistics.exploits_successful += 1;
        }
        self.exploits_used.push(exploit);
    }

    pub fn update_risk_score(&mut self) {
        let critical_weight = self.statistics.critical_count as f32 * 3.5;
        let high_weight = self.statistics.high_count as f32 * 2.5;
        let medium_weight = self.statistics.medium_count as f32 * 1.5;
        let low_weight = self.statistics.low_count as f32 * 0.5;

        let total_weight = critical_weight + high_weight + medium_weight + low_weight;
        self.risk_score = (total_weight / 10.0).min(10.0);
    }

    pub fn generate_executive_summary(&mut self) {
        let risk_level = match self.risk_score {
            s if s >= 9.0 => "CRITICAL",
            s if s >= 7.0 => "HIGH",
            s if s >= 5.0 => "MEDIUM",
            s if s >= 3.0 => "LOW",
            _ => "MINIMAL",
        };

        self.executive_summary = format!(
            "Security assessment of {} completed on {}. \
            Overall Risk Level: {} (Score: {:.1}/10.0). \
            {} critical, {} high, {} medium, and {} low severity vulnerabilities identified. \
            {} exploits successfully executed. \
            Immediate remediation required for critical findings.",
            self.target_url,
            self.scan_date.format("%Y-%m-%d %H:%M:%S"),
            risk_level,
            self.risk_score,
            self.statistics.critical_count,
            self.statistics.high_count,
            self.statistics.medium_count,
            self.statistics.low_count,
            self.statistics.exploits_successful
        );
    }
}

// Vulnerability templates with remediation guidance

pub struct VulnerabilityTemplates;

impl VulnerabilityTemplates {
    pub fn sql_injection() -> RemediationGuidance {
        RemediationGuidance {
            summary: "SQL Injection allows attackers to execute arbitrary SQL commands".to_string(),
            root_cause: "User input is directly concatenated into SQL queries without parameterization".to_string(),
            technical_fix: "Use parameterized queries or prepared statements for all database operations".to_string(),
            code_example: r#"
// VULNERABLE
$query = "SELECT * FROM users WHERE id=" . $_GET['id'];
$result = mysqli_query($conn, $query);

// SECURE
$query = "SELECT * FROM users WHERE id = ?";
$stmt = $conn->prepare($query);
$stmt->bind_param("i", $_GET['id']);
$stmt->execute();
$result = $stmt->get_result();
            "#.to_string(),
            testing_steps: vec![
                "Attempt single quote injection: ' OR '1'='1".to_string(),
                "Test UNION-based extraction: ' UNION SELECT NULL, username, password--".to_string(),
                "Verify fix with parameterized queries".to_string(),
            ],
            references: vec![
                "OWASP SQLi: https://owasp.org/www-community/attacks/SQL_Injection".to_string(),
                "CWE-89: https://cwe.mitre.org/data/definitions/89.html".to_string(),
            ],
            priority: "CRITICAL".to_string(),
            estimated_effort: "2-4 hours".to_string(),
        }
    }

    pub fn xss() -> RemediationGuidance {
        RemediationGuidance {
            summary: "Cross-Site Scripting (XSS) allows injection of malicious scripts".to_string(),
            root_cause: "Unsanitized user input reflected in HTML output".to_string(),
            technical_fix: "HTML-encode all user input before displaying and use Content Security Policy".to_string(),
            code_example: r#"
// VULNERABLE
echo "Welcome " . $_GET['name'];

// SECURE
echo "Welcome " . htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');

// Additional: Content-Security-Policy header
header("Content-Security-Policy: script-src 'self'");
            "#.to_string(),
            testing_steps: vec![
                "Inject <script>alert('XSS')</script>".to_string(),
                "Test event handlers: <img src=x onerror=alert('XSS')>".to_string(),
                "Verify sanitization with automated scanners".to_string(),
            ],
            references: vec![
                "OWASP XSS: https://owasp.org/www-community/attacks/xss/".to_string(),
                "CWE-79: https://cwe.mitre.org/data/definitions/79.html".to_string(),
            ],
            priority: "HIGH".to_string(),
            estimated_effort: "4-8 hours".to_string(),
        }
    }

    pub fn authentication_bypass() -> RemediationGuidance {
        RemediationGuidance {
            summary: "Authentication mechanisms can be bypassed without valid credentials".to_string(),
            root_cause: "Weak authentication logic, missing session validation, or insecure token handling".to_string(),
            technical_fix: "Implement strong authentication with secure session management and proper token validation".to_string(),
            code_example: r#"
// Implement proper authentication
use std::time::{SystemTime, UNIX_EPOCH};

fn verify_session(token: &str) -> bool {
    // Verify JWT signature
    if !verify_jwt_signature(token) {
        return false;
    }

    // Check token expiration
    let claims = decode_jwt(token)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if claims.exp < now {
        return false;
    }

    true
}
            "#.to_string(),
            testing_steps: vec![
                "Attempt direct URL access without login".to_string(),
                "Test session token manipulation".to_string(),
                "Verify MFA enforcement".to_string(),
            ],
            references: vec![
                "OWASP Auth: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html".to_string(),
            ],
            priority: "CRITICAL".to_string(),
            estimated_effort: "8-16 hours".to_string(),
        }
    }

    pub fn ssti() -> RemediationGuidance {
        RemediationGuidance {
            summary: "Server-Side Template Injection leads to code execution".to_string(),
            root_cause: "User input is passed directly to template engines".to_string(),
            technical_fix: "Use sandboxed template rendering and avoid passing user input to template engines".to_string(),
            code_example: r#"
// VULNERABLE
render_template(f"Hello {user_input}", {})

// SECURE
render_template("Hello {name}", {"name": user_input})

// Use Jinja2 with autoescape
from jinja2 import Environment
env = Environment(autoescape=True)
template = env.from_string("Hello {{name}}")
result = template.render(name=user_input)
            "#.to_string(),
            testing_steps: vec![
                "Test basic injection: {{7*7}}".to_string(),
                "Attempt RCE: {{config.items()}}".to_string(),
                "Verify sandboxing prevents code execution".to_string(),
            ],
            references: vec![
                "OWASP SSTI: https://owasp.org/www-community/attacks/Server-Side_Template_Injection".to_string(),
            ],
            priority: "CRITICAL".to_string(),
            estimated_effort: "4-8 hours".to_string(),
        }
    }

    pub fn insecure_deserialization() -> RemediationGuidance {
        RemediationGuidance {
            summary: "Unsafe deserialization can lead to arbitrary code execution".to_string(),
            root_cause: "Deserialization of untrusted data without validation".to_string(),
            technical_fix: "Never deserialize untrusted data; use secure serialization formats".to_string(),
            code_example: r#"
// VULNERABLE
import pickle
data = pickle.loads(untrusted_data)  // DANGEROUS!

// SECURE
import json
data = json.loads(untrusted_data)  // Safe

// Or use signed serialization
from itsdangerous import Signer
signer = Signer('secret-key')
data = json.loads(signer.unsign(untrusted_data))
            "#.to_string(),
            testing_steps: vec![
                "Generate serialized payload for RCE".to_string(),
                "Attempt to deserialize malicious object".to_string(),
                "Verify gadget chains are blocked".to_string(),
            ],
            references: vec![
                "OWASP Deserialization: https://owasp.org/www-community/deserialization-of-untrusted-data".to_string(),
            ],
            priority: "CRITICAL".to_string(),
            estimated_effort: "6-12 hours".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_report_creation() {
        let mut report = PentestReport::new("http://example.com", 60);
        assert_eq!(report.target_url, "http://example.com");
        assert_eq!(report.scan_duration_minutes, 60);
    }

    #[test]
    fn test_risk_score_calculation() {
        let mut report = PentestReport::new("http://example.com", 60);

        // Add vulnerabilities: (10 * 3.5 + 6 * 2.5) / 10 = (35 + 15) / 10 = 5.0
        for _ in 0..10 {
            report.statistics.critical_count += 1;
        }
        for _ in 0..7 {
            report.statistics.high_count += 1;
        }

        report.update_risk_score();
        assert!(report.risk_score >= 5.0);
    }
}
