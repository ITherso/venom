pub mod telemetry;
pub mod health;
pub mod logging;
pub mod metrics;
pub mod tracing;

pub use telemetry::{TelemetryConfig, TelemetryCollector};
pub use health::{HealthChecker, ComponentStatus, HealthReport};
pub use logging::{LogConfig, StructuredLogger};
pub use metrics::{MetricsExporter, PrometheusMetrics};
pub use tracing::{TracingConfig, TracingSpan};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilityConfig {
    pub telemetry_enabled: bool,
    pub telemetry_endpoint: String,
    pub telemetry_sample_rate: f64,

    pub health_check_interval_seconds: u32,
    pub health_check_timeout_seconds: u32,

    pub logging_enabled: bool,
    pub log_level: String,
    pub log_format: LogFormat,
    pub structured_logging: bool,
    pub log_retention_days: u32,

    pub metrics_enabled: bool,
    pub metrics_endpoint: String,
    pub metrics_port: u16,

    pub tracing_enabled: bool,
    pub tracing_sample_rate: f64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum LogFormat {
    Json,
    Text,
    Compact,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            telemetry_enabled: false,
            telemetry_endpoint: "https://telemetry.venom.dev".to_string(),
            telemetry_sample_rate: 0.1,

            health_check_interval_seconds: 30,
            health_check_timeout_seconds: 10,

            logging_enabled: true,
            log_level: "info".to_string(),
            log_format: LogFormat::Json,
            structured_logging: true,
            log_retention_days: 30,

            metrics_enabled: true,
            metrics_endpoint: "http://localhost:9090".to_string(),
            metrics_port: 9090,

            tracing_enabled: false,
            tracing_sample_rate: 0.1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_observability_config_default() {
        let config = ObservabilityConfig::default();
        assert!(!config.telemetry_enabled);
        assert!(config.logging_enabled);
        assert!(config.metrics_enabled);
    }
}
