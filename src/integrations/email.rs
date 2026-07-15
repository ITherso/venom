use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailConfig {
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_username: String,
    pub smtp_password: String,
    pub from_email: String,
    pub from_name: String,
    pub tls_enabled: bool,
    pub tls_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailReport {
    pub id: String,
    pub recipient: String,
    pub subject: String,
    pub body: String,
    pub html_body: Option<String>,
    pub attachments: Vec<EmailAttachment>,
    pub sent_at: Option<DateTime<Utc>>,
    pub status: EmailStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailAttachment {
    pub filename: String,
    pub content_type: String,
    pub size_bytes: usize,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum EmailStatus {
    Draft,
    Queued,
    Sending,
    Sent,
    Failed,
    Bounced,
}

impl EmailConfig {
    pub fn new(
        smtp_host: String,
        smtp_port: u16,
        from_email: String,
    ) -> Self {
        Self {
            smtp_host,
            smtp_port,
            smtp_username: String::new(),
            smtp_password: String::new(),
            from_email,
            from_name: "VENOM".to_string(),
            tls_enabled: true,
            tls_required: true,
        }
    }

    pub fn with_credentials(mut self, username: String, password: String) -> Self {
        self.smtp_username = username;
        self.smtp_password = password;
        self
    }

    pub fn verify(&self) -> Result<(), String> {
        if self.smtp_host.is_empty() {
            return Err("SMTP host is required".to_string());
        }
        if self.smtp_port == 0 {
            return Err("SMTP port is required".to_string());
        }
        if self.from_email.is_empty() {
            return Err("From email is required".to_string());
        }
        Ok(())
    }
}

impl EmailReport {
    pub fn new(
        recipient: String,
        subject: String,
        body: String,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            recipient,
            subject,
            body,
            html_body: None,
            attachments: Vec::new(),
            sent_at: None,
            status: EmailStatus::Draft,
        }
    }

    pub fn with_html(mut self, html: String) -> Self {
        self.html_body = Some(html);
        self
    }

    pub fn add_attachment(&mut self, filename: String, content_type: String, size: usize) {
        self.attachments.push(EmailAttachment {
            filename,
            content_type,
            size_bytes: size,
        });
    }

    pub fn queue(&mut self) {
        self.status = EmailStatus::Queued;
    }

    pub fn mark_sent(&mut self) {
        self.status = EmailStatus::Sent;
        self.sent_at = Some(Utc::now());
    }

    pub fn mark_failed(&mut self) {
        self.status = EmailStatus::Failed;
    }

    pub fn can_retry(&self) -> bool {
        matches!(self.status, EmailStatus::Failed | EmailStatus::Bounced)
    }
}

#[derive(Debug, Clone)]
pub struct EmailReportBuilder {
    report: EmailReport,
}

impl EmailReportBuilder {
    pub fn new(recipient: String, subject: String, body: String) -> Self {
        Self {
            report: EmailReport::new(recipient, subject, body),
        }
    }

    pub fn with_html(mut self, html: String) -> Self {
        self.report.html_body = Some(html);
        self
    }

    pub fn add_attachment(mut self, filename: String, content_type: String, size: usize) -> Self {
        self.report.add_attachment(filename, content_type, size);
        self
    }

    pub fn build(self) -> EmailReport {
        self.report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_config_creation() {
        let config = EmailConfig::new(
            "smtp.gmail.com".to_string(),
            587,
            "noreply@venom.dev".to_string(),
        );
        assert_eq!(config.smtp_host, "smtp.gmail.com");
        assert!(config.verify().is_ok());
    }

    #[test]
    fn test_email_report_creation() {
        let report = EmailReport::new(
            "recipient@example.com".to_string(),
            "Scan Report".to_string(),
            "Here is your scan report...".to_string(),
        );
        assert_eq!(report.status, EmailStatus::Draft);
    }

    #[test]
    fn test_email_report_builder() {
        let report = EmailReportBuilder::new(
            "recipient@example.com".to_string(),
            "Scan Report".to_string(),
            "Content".to_string(),
        )
        .with_html("<h1>Report</h1>".to_string())
        .add_attachment("report.pdf".to_string(), "application/pdf".to_string(), 5000)
        .build();

        assert!(report.html_body.is_some());
        assert_eq!(report.attachments.len(), 1);
    }
}
