#![allow(missing_docs)]

pub mod webhooks;
pub mod slack;
pub mod email;
pub mod external_tools;

pub use webhooks::{WebhookConfig, WebhookEvent, WebhookManager};
pub use slack::{SlackIntegration, SlackMessage};
pub use email::{EmailConfig, EmailReport};
pub use external_tools::{ExternalTool, ToolIntegration};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationConfig {
    pub slack_enabled: bool,
    pub slack_webhook_url: Option<String>,
    pub email_enabled: bool,
    pub email_config: Option<EmailConfig>,
    pub webhooks_enabled: bool,
    pub external_tools_enabled: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum IntegrationType {
    Slack,
    Email,
    Webhook,
    BurpSuite,
    Metasploit,
    Jenkins,
    GitLabCI,
    Splunk,
    ELK,
}

impl Default for IntegrationConfig {
    fn default() -> Self {
        Self {
            slack_enabled: false,
            slack_webhook_url: None,
            email_enabled: false,
            email_config: None,
            webhooks_enabled: false,
            external_tools_enabled: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_integration_config_default() {
        let config = IntegrationConfig::default();
        assert!(!config.slack_enabled);
        assert!(!config.email_enabled);
    }
}
