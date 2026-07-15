use super::{CLIResult, OutputFormat};

#[derive(Debug, Clone)]
pub struct OutputFormatter {
    format: OutputFormat,
    color_output: bool,
}

impl OutputFormatter {
    pub fn new(format: OutputFormat, color_output: bool) -> Self {
        Self {
            format,
            color_output,
        }
    }

    pub fn format(&self, result: &CLIResult) -> String {
        match self.format {
            OutputFormat::Text => self.format_text(result),
            OutputFormat::Json => self.format_json(result),
            OutputFormat::Yaml => self.format_yaml(result),
            OutputFormat::Table => self.format_table(result),
        }
    }

    fn format_text(&self, result: &CLIResult) -> String {
        let mut output = String::new();

        if self.color_output {
            if result.success {
                output.push_str("\u{001b}[32m✓\u{001b}[0m ");
            } else {
                output.push_str("\u{001b}[31m✗\u{001b}[0m ");
            }
        }

        output.push_str(&result.message);

        if let Some(data) = &result.data {
            output.push('\n');
            output.push_str(data);
        }

        if let Some(error) = &result.error {
            output.push('\n');
            output.push_str("Error: ");
            output.push_str(error);
        }

        output
    }

    fn format_json(&self, result: &CLIResult) -> String {
        let data = result.data.as_ref().cloned().unwrap_or_else(|| "null".to_string());
        format!(
            r#"{{
  "success": {},
  "message": "{}",
  "data": {},
  "error": {}
}}"#,
            result.success,
            result.message.replace("\"", "\\\""),
            data,
            result.error.as_ref()
                .map(|e| format!(r#""{}""#, e.replace("\"", "\\\"")))
                .unwrap_or_else(|| "null".to_string())
        )
    }

    fn format_yaml(&self, result: &CLIResult) -> String {
        let mut output = String::new();
        output.push_str("success: ");
        output.push_str(if result.success { "true" } else { "false" });
        output.push('\n');
        output.push_str("message: ");
        output.push_str(&result.message);
        output.push('\n');

        if let Some(data) = &result.data {
            output.push_str("data: ");
            output.push_str(data);
            output.push('\n');
        }

        if let Some(error) = &result.error {
            output.push_str("error: ");
            output.push_str(error);
            output.push('\n');
        }

        output
    }

    fn format_table(&self, result: &CLIResult) -> String {
        let mut output = String::new();

        output.push_str("┌─────────────────────────────────┐\n");
        output.push_str("│ VENOM Command Result            │\n");
        output.push_str("├─────────────────────────────────┤\n");
        output.push_str("│ Status: ");
        if result.success {
            output.push_str("✓ SUCCESS");
        } else {
            output.push_str("✗ FAILED");
        }
        output.push_str("              │\n");
        output.push_str("├─────────────────────────────────┤\n");
        output.push_str("│ Message:                        │\n");
        output.push_str("│ ");
        output.push_str(&self.truncate(&result.message, 31));
        output.push_str("\n");

        if let Some(data) = &result.data {
            output.push_str("├─────────────────────────────────┤\n");
            output.push_str("│ Data:                           │\n");
            for line in data.lines() {
                output.push_str("│ ");
                output.push_str(&self.truncate(line, 31));
                output.push_str("\n");
            }
        }

        if let Some(error) = &result.error {
            output.push_str("├─────────────────────────────────┤\n");
            output.push_str("│ Error:                          │\n");
            output.push_str("│ ");
            output.push_str(&self.truncate(error, 31));
            output.push_str("\n");
        }

        output.push_str("└─────────────────────────────────┘\n");
        output
    }

    fn truncate(&self, text: &str, width: usize) -> String {
        if text.len() <= width {
            format!("{:<width$}", text, width = width)
        } else {
            format!("{}...", &text[..width - 3])
        }
    }

    pub fn format_error(&self, error: &str) -> String {
        match self.format {
            OutputFormat::Json => {
                format!(r#"{{"success": false, "error": "{}"}}"#, error.replace("\"", "\\\""))
            }
            _ => {
                if self.color_output {
                    format!("\u{001b}[31mError: {}\u{001b}[0m", error)
                } else {
                    format!("Error: {}", error)
                }
            }
        }
    }

    pub fn format_help(&self) -> String {
        r#"VENOM v0.5.0 - Enterprise Pentesting Framework CLI

USAGE:
    venom [OPTIONS] <COMMAND> [ARGS]

COMMANDS:
    SCANNING:
        scan:start              Start a new security scan
        scan:status             Get scan status
        scan:stop               Stop running scan
        scan:list               List all scans
        scan:results            Get scan results

    BACKUP & RESTORE:
        backup:create           Create a new backup
        backup:restore          Restore from backup
        backup:list             List all backups
        backup:schedule         Configure backup schedule
        backup:status           Check backup status

    DEPLOYMENT:
        deploy:status           Get deployment status
        deploy:rollback         Rollback deployment
        deploy:health           Check deployment health
        deploy:scale            Scale deployment

    MONITORING:
        sla:status              Get SLA status
        sla:report              Generate SLA report
        metrics:get             Get system metrics
        audit:log               View audit logs

    ACCESS CONTROL:
        role:create             Create new role
        role:list               List all roles
        role:delete             Delete role
        user:create             Create new user
        user:list               List all users
        user:delete             Delete user
        permission:grant        Grant permission
        permission:revoke       Revoke permission

    DISASTER RECOVERY:
        dr:plan:create          Create disaster recovery plan
        dr:drill:start          Start DR drill
        dr:drill:status         Get DR drill status
        dr:failover             Execute failover
        dr:history              View failover history

    SYSTEM:
        status                  Show system status
        config                  Show configuration
        health                  Check system health
        version                 Show version
        help                    Show this help message
        reset                   Reset system

OPTIONS:
    -v, --verbose               Enable verbose output
    -f, --format <FORMAT>       Output format (text|json|yaml|table)
    --no-color                  Disable colored output
    -h, --help                  Print help information

EXAMPLES:
    venom scan:start --target example.com
    venom backup:create --type full --retention 30
    venom deploy:status
    venom user:create testuser
    venom sla:report --period monthly

For more information, visit https://github.com/ITherso/venom
"#.to_string()
    }
}

impl Default for OutputFormatter {
    fn default() -> Self {
        Self::new(OutputFormat::Table, true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_text() {
        let formatter = OutputFormatter::new(OutputFormat::Text, false);
        let result = CLIResult::success("Test".to_string());
        let output = formatter.format(&result);
        assert!(output.contains("Test"));
    }

    #[test]
    fn test_format_json() {
        let formatter = OutputFormatter::new(OutputFormat::Json, false);
        let result = CLIResult::success("Test".to_string());
        let output = formatter.format(&result);
        assert!(output.contains("\"success\": true"));
    }

    #[test]
    fn test_format_yaml() {
        let formatter = OutputFormatter::new(OutputFormat::Yaml, false);
        let result = CLIResult::success("Test".to_string());
        let output = formatter.format(&result);
        assert!(output.contains("success: true"));
    }

    #[test]
    fn test_format_error() {
        let formatter = OutputFormatter::new(OutputFormat::Text, false);
        let output = formatter.format_error("Test error");
        assert!(output.contains("Test error"));
    }

    #[test]
    fn test_help_format() {
        let formatter = OutputFormatter::default();
        let help = formatter.format_help();
        assert!(help.contains("VENOM v0.5.0"));
        assert!(help.contains("USAGE:"));
    }
}
