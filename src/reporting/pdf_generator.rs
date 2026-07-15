use crate::Result;
use super::report::PentestReport;
use super::html_generator::HtmlReportGenerator;

pub struct PdfReportGenerator;

impl PdfReportGenerator {
    /// Generate PDF report from pentest report
    pub async fn generate(report: &PentestReport) -> Result<Vec<u8>> {
        // Generate HTML first
        let html = HtmlReportGenerator::generate(report);

        // Use wkhtmltopdf via system command or library
        Self::html_to_pdf(&html).await
    }

    /// Convert HTML to PDF using available tools
    async fn html_to_pdf(html: &str) -> Result<Vec<u8>> {
        // Try to use wkhtmltopdf if available
        #[cfg(feature = "pdf-native")]
        {
            return Self::html_to_pdf_native(html).await;
        }

        // Fallback: use system wkhtmltopdf
        #[cfg(not(feature = "pdf-native"))]
        {
            return Self::html_to_pdf_system(html).await;
        }
    }

    /// Native PDF generation (requires pdf-native feature)
    #[cfg(feature = "pdf-native")]
    async fn html_to_pdf_native(html: &str) -> Result<Vec<u8>> {
        use futures::TryFutureExt;
        use std::process::Stdio;
        use tokio::io::AsyncWriteExt;
        use tokio::process::Command;

        let mut child = Command::new("wkhtmltopdf")
            .arg("--quiet")
            .arg("--print-media-type")
            .arg("-")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|e| crate::Error::ProxyError(format!("Failed to spawn wkhtmltopdf: {}", e)))?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(html.as_bytes())
                .await
                .map_err(|e| crate::Error::ProxyError(format!("Failed to write HTML: {}", e)))?;
        }

        let output = child
            .wait_with_output()
            .await
            .map_err(|e| crate::Error::ProxyError(format!("wkhtmltopdf error: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(crate::Error::ProxyError(format!(
                "PDF generation failed: {}",
                stderr
            )));
        }

        Ok(output.stdout)
    }

    /// System wkhtmltopdf fallback
    #[cfg(not(feature = "pdf-native"))]
    async fn html_to_pdf_system(html: &str) -> Result<Vec<u8>> {
        use std::process::Stdio;
        use tokio::io::AsyncWriteExt;
        use tokio::process::Command;

        // Create temporary HTML file
        let temp_dir = std::env::temp_dir();
        let temp_html = temp_dir.join(format!(
            "report_{}.html",
            chrono::Utc::now().timestamp_millis()
        ));
        let temp_pdf = temp_dir.join(format!(
            "report_{}.pdf",
            chrono::Utc::now().timestamp_millis()
        ));

        // Write HTML to temp file
        tokio::fs::write(&temp_html, html)
            .await
            .map_err(|e| crate::Error::ProxyError(format!("Failed to write temp file: {}", e)))?;

        // Run wkhtmltopdf
        let output = Command::new("wkhtmltopdf")
            .arg("--quiet")
            .arg("--print-media-type")
            .arg(&temp_html)
            .arg(&temp_pdf)
            .output()
            .await
            .map_err(|e| crate::Error::ProxyError(format!("wkhtmltopdf error: {}", e)))?;

        // Clean up HTML temp file
        let _ = tokio::fs::remove_file(&temp_html).await;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let _ = tokio::fs::remove_file(&temp_pdf).await;
            return Err(crate::Error::ProxyError(format!(
                "PDF generation failed: {}",
                stderr
            )));
        }

        // Read PDF file
        let pdf_data = tokio::fs::read(&temp_pdf)
            .await
            .map_err(|e| crate::Error::ProxyError(format!("Failed to read PDF: {}", e)))?;

        // Clean up PDF temp file
        let _ = tokio::fs::remove_file(&temp_pdf).await;

        Ok(pdf_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Only run if wkhtmltopdf is installed
    async fn test_pdf_generation() {
        let report = PentestReport::new("http://example.com", 60);
        let result = PdfReportGenerator::generate(&report).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().is_empty());
    }
}
