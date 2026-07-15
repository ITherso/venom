use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    pub level: LogLevel,
    pub format: LogFormat,
    pub structured: bool,
    pub retention_days: u32,
    pub max_file_size_mb: u32,
    pub max_files: usize,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum LogFormat {
    Json,
    Text,
    Compact,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: DateTime<Utc>,
    pub level: LogLevel,
    pub module: String,
    pub message: String,
    pub request_id: Option<String>,
    pub user_id: Option<String>,
    pub context: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct StructuredLogger {
    level: LogLevel,
    format: LogFormat,
    entries: Vec<LogEntry>,
}

impl StructuredLogger {
    pub fn new(level: LogLevel, format: LogFormat) -> Self {
        Self {
            level,
            format,
            entries: Vec::new(),
        }
    }

    pub fn log(
        &mut self,
        level: LogLevel,
        module: &str,
        message: &str,
        request_id: Option<String>,
    ) {
        if level >= self.level {
            let entry = LogEntry {
                timestamp: Utc::now(),
                level,
                module: module.to_string(),
                message: message.to_string(),
                request_id,
                user_id: None,
                context: None,
            };
            self.entries.push(entry.clone());
            self.print_entry(&entry);
        }
    }

    pub fn log_with_context(
        &mut self,
        level: LogLevel,
        module: &str,
        message: &str,
        request_id: Option<String>,
        user_id: Option<String>,
        context: Option<serde_json::Value>,
    ) {
        if level >= self.level {
            let entry = LogEntry {
                timestamp: Utc::now(),
                level,
                module: module.to_string(),
                message: message.to_string(),
                request_id,
                user_id,
                context,
            };
            self.entries.push(entry.clone());
            self.print_entry(&entry);
        }
    }

    pub fn trace(&mut self, module: &str, message: &str) {
        self.log(LogLevel::Trace, module, message, None);
    }

    pub fn debug(&mut self, module: &str, message: &str) {
        self.log(LogLevel::Debug, module, message, None);
    }

    pub fn info(&mut self, module: &str, message: &str) {
        self.log(LogLevel::Info, module, message, None);
    }

    pub fn warn(&mut self, module: &str, message: &str) {
        self.log(LogLevel::Warn, module, message, None);
    }

    pub fn error(&mut self, module: &str, message: &str) {
        self.log(LogLevel::Error, module, message, None);
    }

    fn print_entry(&self, entry: &LogEntry) {
        match self.format {
            LogFormat::Json => {
                if let Ok(json) = serde_json::to_string(entry) {
                    println!("{}", json);
                }
            }
            LogFormat::Text => {
                println!(
                    "[{}] {} - {} - {}",
                    entry.timestamp.format("%Y-%m-%d %H:%M:%S"),
                    entry.level.as_str(),
                    entry.module,
                    entry.message
                );
            }
            LogFormat::Compact => {
                println!(
                    "{} {:?} {} {}",
                    entry.timestamp.format("%H:%M:%S"),
                    entry.level,
                    entry.module,
                    entry.message
                );
            }
        }
    }

    pub fn get_entries(&self) -> &[LogEntry] {
        &self.entries
    }

    pub fn filter_by_level(&self, level: LogLevel) -> Vec<&LogEntry> {
        self.entries.iter().filter(|e| e.level == level).collect()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

impl LogLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Trace => "TRACE",
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
        }
    }
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            format: LogFormat::Json,
            structured: true,
            retention_days: 30,
            max_file_size_mb: 100,
            max_files: 10,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logger_creation() {
        let logger = StructuredLogger::new(LogLevel::Info, LogFormat::Json);
        assert_eq!(logger.entries.len(), 0);
    }

    #[test]
    fn test_log_entry() {
        let mut logger = StructuredLogger::new(LogLevel::Debug, LogFormat::Text);
        logger.debug("test", "test message");
        assert_eq!(logger.entries.len(), 1);
    }

    #[test]
    fn test_filter_by_level() {
        let mut logger = StructuredLogger::new(LogLevel::Trace, LogFormat::Json);
        logger.debug("module", "debug msg");
        logger.error("module", "error msg");

        let errors = logger.filter_by_level(LogLevel::Error);
        assert_eq!(errors.len(), 1);
    }
}
