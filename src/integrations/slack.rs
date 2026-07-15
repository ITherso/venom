use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackIntegration {
    pub webhook_url: String,
    pub channel: String,
    pub username: String,
    pub enabled: bool,
    pub notify_on_scan_complete: bool,
    pub notify_on_vulnerability: bool,
    pub notify_on_error: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackMessage {
    pub text: String,
    pub channel: Option<String>,
    pub username: Option<String>,
    pub icon_emoji: Option<String>,
    pub attachments: Vec<SlackAttachment>,
    pub blocks: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackAttachment {
    pub color: String,
    pub title: String,
    pub text: String,
    pub fields: Vec<SlackField>,
    pub image_url: Option<String>,
    pub thumb_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackField {
    pub title: String,
    pub value: String,
    pub short: bool,
}

impl SlackIntegration {
    pub fn new(webhook_url: String, channel: String) -> Self {
        Self {
            webhook_url,
            channel,
            username: "VENOM".to_string(),
            enabled: true,
            notify_on_scan_complete: true,
            notify_on_vulnerability: true,
            notify_on_error: true,
        }
    }

    pub fn scan_complete_message(
        &self,
        scan_id: &str,
        vulnerabilities: usize,
        duration_minutes: u32,
    ) -> SlackMessage {
        SlackMessage {
            text: format!("Scan {} completed", scan_id),
            channel: Some(self.channel.clone()),
            username: Some(self.username.clone()),
            icon_emoji: Some(":shield:".to_string()),
            attachments: vec![
                SlackAttachment {
                    color: "#36a64f".to_string(),
                    title: format!("Scan Complete: {}", scan_id),
                    text: format!(
                        "Found {} vulnerabilities in {} minutes",
                        vulnerabilities, duration_minutes
                    ),
                    fields: vec![
                        SlackField {
                            title: "Vulnerabilities".to_string(),
                            value: vulnerabilities.to_string(),
                            short: true,
                        },
                        SlackField {
                            title: "Duration".to_string(),
                            value: format!("{} minutes", duration_minutes),
                            short: true,
                        },
                    ],
                    image_url: None,
                    thumb_url: None,
                }
            ],
            blocks: vec![],
        }
    }

    pub fn vulnerability_message(
        &self,
        vuln_type: &str,
        severity: &str,
        target: &str,
    ) -> SlackMessage {
        let color = match severity {
            "Critical" => "#ff0000",
            "High" => "#ff6600",
            "Medium" => "#ffcc00",
            _ => "#00cc00",
        };

        SlackMessage {
            text: format!("Vulnerability found: {}", vuln_type),
            channel: Some(self.channel.clone()),
            username: Some(self.username.clone()),
            icon_emoji: Some(":warning:".to_string()),
            attachments: vec![
                SlackAttachment {
                    color: color.to_string(),
                    title: format!("Vulnerability: {}", vuln_type),
                    text: format!("Found on {}", target),
                    fields: vec![
                        SlackField {
                            title: "Type".to_string(),
                            value: vuln_type.to_string(),
                            short: true,
                        },
                        SlackField {
                            title: "Severity".to_string(),
                            value: severity.to_string(),
                            short: true,
                        },
                        SlackField {
                            title: "Target".to_string(),
                            value: target.to_string(),
                            short: false,
                        },
                    ],
                    image_url: None,
                    thumb_url: None,
                }
            ],
            blocks: vec![],
        }
    }

    pub fn error_message(&self, error_type: &str, message: &str) -> SlackMessage {
        SlackMessage {
            text: format!("Error: {}", error_type),
            channel: Some(self.channel.clone()),
            username: Some(self.username.clone()),
            icon_emoji: Some(":x:".to_string()),
            attachments: vec![
                SlackAttachment {
                    color: "#ff0000".to_string(),
                    title: format!("Error: {}", error_type),
                    text: message.to_string(),
                    fields: vec![],
                    image_url: None,
                    thumb_url: None,
                }
            ],
            blocks: vec![],
        }
    }

    pub fn export_json(&self) -> String {
        serde_json::to_string_pretty(&self).unwrap_or_default()
    }
}

impl SlackMessage {
    pub fn to_json(&self) -> String {
        serde_json::to_string(&self).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slack_integration_creation() {
        let slack = SlackIntegration::new(
            "https://hooks.slack.com/services/xxx".to_string(),
            "#security".to_string(),
        );
        assert_eq!(slack.channel, "#security");
        assert!(slack.enabled);
    }

    #[test]
    fn test_scan_complete_message() {
        let slack = SlackIntegration::new(
            "https://hooks.slack.com/services/xxx".to_string(),
            "#security".to_string(),
        );
        let msg = slack.scan_complete_message("scan-123", 5, 10);
        assert_eq!(msg.attachments.len(), 1);
    }

    #[test]
    fn test_vulnerability_message() {
        let slack = SlackIntegration::new(
            "https://hooks.slack.com/services/xxx".to_string(),
            "#security".to_string(),
        );
        let msg = slack.vulnerability_message("SQL Injection", "High", "example.com");
        assert!(msg.text.contains("SQL Injection"));
    }
}
