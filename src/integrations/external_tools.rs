use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalTool {
    pub name: String,
    pub tool_type: ToolType,
    pub endpoint: String,
    pub api_key: Option<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ToolType {
    BurpSuite,
    OWASP_ZAP,
    Metasploit,
    Nessus,
    Qualys,
    Jenkins,
    GitLabCI,
    Splunk,
    ElasticsearchLogstash,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolIntegration {
    pub tool: ExternalTool,
    pub status: IntegrationStatus,
    pub last_sync: Option<String>,
    pub import_formats: Vec<String>,
    pub export_formats: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum IntegrationStatus {
    Configured,
    Connected,
    Disconnected,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportJob {
    pub id: String,
    pub source_tool: String,
    pub file_path: String,
    pub format: String,
    pub status: ImportStatus,
    pub records_imported: usize,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ImportStatus {
    Pending,
    Processing,
    Completed,
    Failed,
    Partial,
}

impl ExternalTool {
    pub fn burp_suite(endpoint: String) -> Self {
        Self {
            name: "Burp Suite".to_string(),
            tool_type: ToolType::BurpSuite,
            endpoint,
            api_key: None,
            enabled: true,
        }
    }

    pub fn metasploit(endpoint: String, api_key: String) -> Self {
        Self {
            name: "Metasploit".to_string(),
            tool_type: ToolType::Metasploit,
            endpoint,
            api_key: Some(api_key),
            enabled: true,
        }
    }

    pub fn jenkins(endpoint: String, api_key: String) -> Self {
        Self {
            name: "Jenkins".to_string(),
            tool_type: ToolType::Jenkins,
            endpoint,
            api_key: Some(api_key),
            enabled: true,
        }
    }

    pub fn splunk(endpoint: String, api_key: String) -> Self {
        Self {
            name: "Splunk".to_string(),
            tool_type: ToolType::Splunk,
            endpoint,
            api_key: Some(api_key),
            enabled: true,
        }
    }

    pub fn export_json(&self) -> String {
        serde_json::to_string_pretty(&self).unwrap_or_default()
    }
}

impl ToolIntegration {
    pub fn new(tool: ExternalTool) -> Self {
        let import_formats = match tool.tool_type {
            ToolType::BurpSuite => vec!["xml".to_string(), "json".to_string()],
            ToolType::OWASP_ZAP => vec!["xml".to_string(), "json".to_string(), "html".to_string()],
            ToolType::Metasploit => vec!["json".to_string(), "xml".to_string()],
            ToolType::Nessus => vec!["nessus".to_string(), "csv".to_string()],
            ToolType::Qualys => vec!["xml".to_string(), "csv".to_string()],
            _ => vec!["json".to_string()],
        };

        let export_formats = vec!["json".to_string(), "xml".to_string(), "csv".to_string()];

        Self {
            tool,
            status: IntegrationStatus::Configured,
            last_sync: None,
            import_formats,
            export_formats,
        }
    }

    pub fn test_connection(&mut self) -> Result<(), String> {
        // Implementation would test the connection
        self.status = IntegrationStatus::Connected;
        Ok(())
    }

    pub fn disconnect(&mut self) {
        self.status = IntegrationStatus::Disconnected;
    }

    pub fn supports_import_format(&self, format: &str) -> bool {
        self.import_formats.contains(&format.to_lowercase())
    }

    pub fn supports_export_format(&self, format: &str) -> bool {
        self.export_formats.contains(&format.to_lowercase())
    }

    pub fn get_supported_formats(&self) -> HashMap<String, Vec<String>> {
        let mut formats = HashMap::new();
        formats.insert("import".to_string(), self.import_formats.clone());
        formats.insert("export".to_string(), self.export_formats.clone());
        formats
    }
}

impl ImportJob {
    pub fn new(source_tool: String, file_path: String, format: String) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            source_tool,
            file_path,
            format,
            status: ImportStatus::Pending,
            records_imported: 0,
            errors: Vec::new(),
        }
    }

    pub fn mark_processing(&mut self) {
        self.status = ImportStatus::Processing;
    }

    pub fn mark_completed(&mut self, count: usize) {
        self.status = ImportStatus::Completed;
        self.records_imported = count;
    }

    pub fn mark_failed(&mut self, error: String) {
        self.status = ImportStatus::Failed;
        self.errors.push(error);
    }

    pub fn add_error(&mut self, error: String) {
        self.errors.push(error);
        if self.status != ImportStatus::Failed {
            self.status = ImportStatus::Partial;
        }
    }

    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    pub fn error_count(&self) -> usize {
        self.errors.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_external_tool_creation() {
        let tool = ExternalTool::burp_suite("http://localhost:8080".to_string());
        assert_eq!(tool.name, "Burp Suite");
        assert!(tool.enabled);
    }

    #[test]
    fn test_tool_integration() {
        let tool = ExternalTool::metasploit(
            "http://localhost:55553".to_string(),
            "rpc_token".to_string(),
        );
        let mut integration = ToolIntegration::new(tool);
        assert!(integration.supports_import_format("json"));
        assert!(integration.supports_export_format("xml"));
    }

    #[test]
    fn test_import_job() {
        let mut job = ImportJob::new(
            "Burp Suite".to_string(),
            "/path/to/export.xml".to_string(),
            "xml".to_string(),
        );
        job.mark_processing();
        job.mark_completed(50);

        assert_eq!(job.records_imported, 50);
        assert_eq!(job.status, ImportStatus::Completed);
    }
}
