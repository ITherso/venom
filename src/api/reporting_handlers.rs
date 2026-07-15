use crate::Result;
use crate::reporting::{PentestReport, HtmlReportGenerator, PdfReportGenerator};
use axum::{
    extract::Path,
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateReportRequest {
    pub report_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportResponse {
    pub report_id: String,
    pub format: String,
    pub size_bytes: usize,
    pub generated_at: chrono::DateTime<chrono::Utc>,
}

pub struct ReportingHandlers;

impl ReportingHandlers {
    /// Generate HTML report
    pub async fn generate_html_report(report: &PentestReport) -> Result<(String, String)> {
        let html = HtmlReportGenerator::generate(report);
        let filename = format!("venom_report_{}.html", report.report_id);
        Ok((filename, html))
    }

    /// Generate PDF report
    pub async fn generate_pdf_report(report: &PentestReport) -> Result<(String, Vec<u8>)> {
        let pdf_data = PdfReportGenerator::generate(report).await?;
        let filename = format!("venom_report_{}.pdf", report.report_id);
        Ok((filename, pdf_data))
    }

    /// Generate both HTML and PDF reports
    pub async fn generate_both_reports(report: &PentestReport) -> Result<ReportGenerationResult> {
        let (html_filename, html) = Self::generate_html_report(report).await?;
        let (pdf_filename, pdf_data) = Self::generate_pdf_report(report).await?;

        Ok(ReportGenerationResult {
            html_filename,
            html_size: html.len(),
            pdf_filename,
            pdf_size: pdf_data.len(),
            report_id: report.report_id.clone(),
            generated_at: chrono::Utc::now(),
        })
    }
}

#[derive(Debug, Serialize)]
pub struct ReportGenerationResult {
    pub html_filename: String,
    pub html_size: usize,
    pub pdf_filename: String,
    pub pdf_size: usize,
    pub report_id: String,
    pub generated_at: chrono::DateTime<chrono::Utc>,
}
