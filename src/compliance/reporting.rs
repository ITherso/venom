use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReportFormat {
    PDF,
    HTML,
    JSON,
    CSV,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditFinding {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: FindingSeverity,
    pub category: String,
    pub remediation: String,
    pub evidence: Vec<String>,
    pub status: FindingStatus,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum FindingSeverity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum FindingStatus {
    Open,
    InProgress,
    Resolved,
    Closed,
    Deferred,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub id: String,
    pub report_name: String,
    pub framework: String,
    pub report_date: DateTime<Utc>,
    pub report_period: (DateTime<Utc>, DateTime<Utc>),
    pub overall_status: ComplianceStatus,
    pub findings: Vec<AuditFinding>,
    pub summary: ReportSummary,
    pub format: ReportFormat,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ComplianceStatus {
    Compliant,
    PartiallyCompliant,
    NonCompliant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    pub total_findings: usize,
    pub critical_findings: usize,
    pub high_findings: usize,
    pub medium_findings: usize,
    pub low_findings: usize,
    pub open_findings: usize,
    pub resolved_findings: usize,
    pub compliance_percentage: f32,
}

impl ComplianceReport {
    pub fn new(
        report_name: String,
        framework: String,
        report_period: (DateTime<Utc>, DateTime<Utc>),
        findings: Vec<AuditFinding>,
        format: ReportFormat,
    ) -> Self {
        let critical = findings.iter().filter(|f| f.severity == FindingSeverity::Critical).count();
        let high = findings.iter().filter(|f| f.severity == FindingSeverity::High).count();
        let medium = findings.iter().filter(|f| f.severity == FindingSeverity::Medium).count();
        let low = findings.iter().filter(|f| f.severity == FindingSeverity::Low).count();
        let open = findings.iter().filter(|f| f.status == FindingStatus::Open).count();
        let resolved = findings.iter().filter(|f| f.status == FindingStatus::Resolved).count();

        let total = findings.len();
        let compliance_percentage = if total > 0 {
            ((total - open) as f32 / total as f32) * 100.0
        } else {
            100.0
        };

        let overall_status = if critical > 0 {
            ComplianceStatus::NonCompliant
        } else if high > 2 || open > 5 {
            ComplianceStatus::PartiallyCompliant
        } else {
            ComplianceStatus::Compliant
        };

        Self {
            id: Uuid::new_v4().to_string(),
            report_name,
            framework,
            report_date: Utc::now(),
            report_period,
            overall_status,
            findings,
            summary: ReportSummary {
                total_findings: total,
                critical_findings: critical,
                high_findings: high,
                medium_findings: medium,
                low_findings: low,
                open_findings: open,
                resolved_findings: resolved,
                compliance_percentage,
            },
            format,
        }
    }

    pub fn export(&self) -> String {
        match self.format {
            ReportFormat::JSON => serde_json::to_string_pretty(self).unwrap_or_default(),
            ReportFormat::CSV => self.to_csv(),
            ReportFormat::PDF | ReportFormat::HTML => self.to_html(),
        }
    }

    fn to_csv(&self) -> String {
        let mut csv = String::from("Finding ID,Title,Severity,Status,Category\n");
        for finding in &self.findings {
            csv.push_str(&format!(
                "{},{},{:?},{:?},{}\n",
                finding.id, finding.title, finding.severity, finding.status, finding.category
            ));
        }
        csv
    }

    fn to_html(&self) -> String {
        format!(
            "<html><body><h1>{}</h1><p>Framework: {}</p><p>Status: {:?}</p><p>Compliance: {:.1}%</p></body></html>",
            self.report_name, self.framework, self.overall_status, self.summary.compliance_percentage
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compliance_report_creation() {
        let findings = vec![];
        let report = ComplianceReport::new(
            "Test Report".to_string(),
            "SOC2".to_string(),
            (Utc::now(), Utc::now()),
            findings,
            ReportFormat::JSON,
        );
        assert_eq!(report.framework, "SOC2");
    }

    #[test]
    fn test_report_export_json() {
        let findings = vec![];
        let report = ComplianceReport::new(
            "Test Report".to_string(),
            "GDPR".to_string(),
            (Utc::now(), Utc::now()),
            findings,
            ReportFormat::JSON,
        );
        let exported = report.export();
        assert!(!exported.is_empty());
    }
}
