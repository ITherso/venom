use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Command {
    pub id: String,
    pub command_type: CommandType,
    pub payload: String,
    pub priority: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CommandType {
    Exec,
    Shell,
    Download,
    Upload,
    Persistence,
    PrivEsc,
    Lateral,
    Exfil,
    Evasion,
    PowerShell,
    Bash,
    Python,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    pub output: String,
    pub error: Option<String>,
    pub exit_code: i32,
}

impl Command {
    pub fn new(command_type: CommandType, payload: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            command_type,
            payload,
            priority: 0,
        }
    }

    pub fn with_priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }

    pub fn execute(&self) -> CommandResult {
        match self.command_type {
            CommandType::Exec => self.execute_exec(),
            CommandType::Shell => self.execute_shell(),
            CommandType::PowerShell => self.execute_powershell(),
            CommandType::Bash => self.execute_bash(),
            CommandType::Download => self.execute_download(),
            CommandType::Upload => self.execute_upload(),
            _ => CommandResult {
                output: String::new(),
                error: Some("Command type not implemented".to_string()),
                exit_code: 1,
            },
        }
    }

    fn execute_exec(&self) -> CommandResult {
        CommandResult {
            output: format!("Executed: {}", self.payload),
            error: None,
            exit_code: 0,
        }
    }

    fn execute_shell(&self) -> CommandResult {
        CommandResult {
            output: format!("Shell command: {}", self.payload),
            error: None,
            exit_code: 0,
        }
    }

    fn execute_powershell(&self) -> CommandResult {
        CommandResult {
            output: format!("PowerShell: {}", self.payload),
            error: None,
            exit_code: 0,
        }
    }

    fn execute_bash(&self) -> CommandResult {
        CommandResult {
            output: format!("Bash: {}", self.payload),
            error: None,
            exit_code: 0,
        }
    }

    fn execute_download(&self) -> CommandResult {
        CommandResult {
            output: format!("Download initiated: {}", self.payload),
            error: None,
            exit_code: 0,
        }
    }

    fn execute_upload(&self) -> CommandResult {
        CommandResult {
            output: format!("Upload initiated: {}", self.payload),
            error: None,
            exit_code: 0,
        }
    }

    pub fn is_high_priority(&self) -> bool {
        self.priority > 50
    }

    pub fn get_description(&self) -> String {
        match self.command_type {
            CommandType::Exec => "Execute command".to_string(),
            CommandType::Shell => "Shell command".to_string(),
            CommandType::Download => "Download file".to_string(),
            CommandType::Upload => "Upload file".to_string(),
            CommandType::Persistence => "Establish persistence".to_string(),
            CommandType::PrivEsc => "Privilege escalation".to_string(),
            CommandType::Lateral => "Lateral movement".to_string(),
            CommandType::Exfil => "Data exfiltration".to_string(),
            CommandType::Evasion => "Evasion technique".to_string(),
            CommandType::PowerShell => "PowerShell command".to_string(),
            CommandType::Bash => "Bash command".to_string(),
            CommandType::Python => "Python command".to_string(),
            CommandType::Custom => "Custom command".to_string(),
        }
    }
}

impl CommandResult {
    pub fn success(&self) -> bool {
        self.exit_code == 0 && self.error.is_none()
    }

    pub fn get_error_message(&self) -> String {
        self.error
            .clone()
            .unwrap_or_else(|| format!("Exit code: {}", self.exit_code))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandBuilder {
    command_type: CommandType,
    payload: String,
    priority: u32,
}

impl CommandBuilder {
    pub fn new(command_type: CommandType) -> Self {
        Self {
            command_type,
            payload: String::new(),
            priority: 0,
        }
    }

    pub fn with_payload(mut self, payload: String) -> Self {
        self.payload = payload;
        self
    }

    pub fn with_priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }

    pub fn build(self) -> Command {
        Command {
            id: Uuid::new_v4().to_string(),
            command_type: self.command_type,
            payload: self.payload,
            priority: self.priority,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_creation() {
        let cmd = Command::new(CommandType::Exec, "whoami".to_string());
        assert_eq!(cmd.command_type, CommandType::Exec);
    }

    #[test]
    fn test_command_execute() {
        let cmd = Command::new(CommandType::Exec, "whoami".to_string());
        let result = cmd.execute();
        assert_eq!(result.exit_code, 0);
        assert!(result.success());
    }

    #[test]
    fn test_command_priority() {
        let cmd = Command::new(CommandType::Exec, "whoami".to_string()).with_priority(75);
        assert!(cmd.is_high_priority());
    }

    #[test]
    fn test_command_builder() {
        let cmd = CommandBuilder::new(CommandType::Shell)
            .with_payload("ls -la".to_string())
            .with_priority(25)
            .build();

        assert_eq!(cmd.command_type, CommandType::Shell);
        assert_eq!(cmd.payload, "ls -la");
        assert_eq!(cmd.priority, 25);
    }

    #[test]
    fn test_command_description() {
        let cmd = Command::new(CommandType::PrivEsc, "".to_string());
        assert_eq!(cmd.get_description(), "Privilege escalation");
    }
}
