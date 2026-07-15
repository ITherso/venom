pub mod commands;
pub mod parser;
pub mod executor;
pub mod output;

pub use commands::{Command, CommandContext};
pub use parser::CommandParser;
pub use executor::CommandExecutor;
pub use output::OutputFormatter;

#[derive(Debug, Clone)]
pub struct CLIConfig {
    pub verbose: bool,
    pub output_format: OutputFormat,
    pub color_output: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
    Yaml,
    Table,
}

impl Default for CLIConfig {
    fn default() -> Self {
        Self {
            verbose: false,
            output_format: OutputFormat::Table,
            color_output: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CLIResult {
    pub success: bool,
    pub message: String,
    pub data: Option<String>,
    pub error: Option<String>,
}

impl CLIResult {
    pub fn success(message: String) -> Self {
        Self {
            success: true,
            message,
            data: None,
            error: None,
        }
    }

    pub fn success_with_data(message: String, data: String) -> Self {
        Self {
            success: true,
            message,
            data: Some(data),
            error: None,
        }
    }

    pub fn error(message: String) -> Self {
        let error_msg = message.clone();
        Self {
            success: false,
            message,
            data: None,
            error: Some(error_msg),
        }
    }
}
