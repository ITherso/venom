use crate::Result;
use super::report::PentestReport;
use chrono::Utc;

pub struct HtmlReportGenerator;

impl HtmlReportGenerator {
    pub fn generate(report: &PentestReport) -> String {
        let vuln_html = Self::generate_vulnerabilities(&report);
        let rec_html = Self::generate_recommendations_html(&report);

        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>VENOM Report - {}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #d32f2f; }}
        h2 {{ color: #d32f2f; margin-top: 30px; }}
        .stat {{ background: #f5f5f5; padding: 10px; margin: 10px 0; }}
        .vuln {{ border-left: 4px solid #d32f2f; padding: 15px; margin: 15px 0; }}
        .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #ccc; }}
    </style>
</head>
<body>
    <h1>🐍 VENOM Pentesting Report</h1>
    <p><strong>Report ID:</strong> {}</p>
    <p><strong>Target:</strong> {}</p>
    <p><strong>Date:</strong> {}</p>
    <p><strong>Duration:</strong> {} minutes</p>
    <p><strong>Risk Score:</strong> {:.1}/10.0</p>
    <p><strong>Summary:</strong> {}</p>

    <h2>Findings Summary</h2>
    <div class="stat"><strong>Total Vulnerabilities:</strong> {}</div>
    <div class="stat"><strong>Critical:</strong> {}</div>
    <div class="stat"><strong>High:</strong> {}</div>
    <div class="stat"><strong>Medium:</strong> {}</div>
    <div class="stat"><strong>Low:</strong> {}</div>
    <div class="stat"><strong>Exploits Successful:</strong> {}/{}</div>
    <div class="stat"><strong>Endpoints Tested:</strong> {}</div>
    <div class="stat"><strong>URLs Scanned:</strong> {}</div>

    <h2>Vulnerabilities</h2>
    {}

    <h2>Remediation Guidance</h2>
    {}

    <div class="footer">
        <p><small>VENOM v0.5.0 | Generated: {}</small></p>
    </div>
</body>
</html>"#,
            report.report_id,
            report.report_id,
            report.target_url,
            report.scan_date,
            report.scan_duration_minutes,
            report.risk_score,
            report.executive_summary,
            report.statistics.total_vulnerabilities,
            report.statistics.critical_count,
            report.statistics.high_count,
            report.statistics.medium_count,
            report.statistics.low_count,
            report.statistics.exploits_successful,
            report.statistics.exploits_attempted,
            report.statistics.endpoints_tested,
            report.statistics.urls_scanned,
            vuln_html,
            rec_html,
            Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
        )
    }

    fn generate_vulnerabilities(report: &PentestReport) -> String {
        let mut html = String::new();
        for vuln in &report.vulnerabilities {
            html.push_str(&format!(
                r#"<div class="vuln">
                <h3>{}</h3>
                <p><strong>Severity:</strong> {}</p>
                <p><strong>CVSS:</strong> {:.1}</p>
                <p><strong>URL:</strong> {}</p>
                <p><strong>Description:</strong> {}</p>
                <p><strong>Root Cause:</strong> {}</p>
                <p><strong>Fix:</strong> {}</p>
                <pre>{}</pre>
            </div>"#,
                vuln.title,
                vuln.severity.to_uppercase(),
                vuln.cvss_score,
                vuln.affected_url,
                vuln.description,
                vuln.remediation.root_cause,
                vuln.remediation.technical_fix,
                vuln.remediation.code_example
            ));
        }
        html
    }

    fn generate_recommendations_html(report: &PentestReport) -> String {
        let mut html = String::new();
        for rec in &report.recommendations {
            html.push_str(&format!(
                r#"<div class="stat"><strong>{} - {}: </strong>{}</div>"#,
                rec.priority, rec.category, rec.description
            ));
        }
        html
    }
}
