use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryConfig {
    pub enabled: bool,
    pub endpoint: String,
    pub sample_rate: f64,
    pub api_key: Option<String>,
    pub batch_size: usize,
    pub flush_interval_seconds: u32,
    pub error_tracking_enabled: bool,
    pub performance_tracking_enabled: bool,
    pub feature_tracking_enabled: bool,
    pub crash_reporting_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub event_type: EventType,
    pub user_id: Option<String>,
    pub session_id: String,
    pub properties: HashMap<String, String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum EventType {
    AppStart,
    AppStop,
    ScanStarted,
    ScanCompleted,
    ExploitExecuted,
    Error,
    FeatureUsage,
    PerformanceMetric,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorReport {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub error_type: String,
    pub message: String,
    pub stacktrace: Option<String>,
    pub context: HashMap<String, String>,
    pub severity: ErrorSeverity,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ErrorSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetric {
    pub name: String,
    pub duration_ms: f64,
    pub timestamp: DateTime<Utc>,
    pub tags: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct TelemetryCollector {
    config: TelemetryConfig,
    events: Vec<TelemetryEvent>,
    session_id: String,
    errors: Vec<ErrorReport>,
    metrics: Vec<PerformanceMetric>,
}

impl TelemetryCollector {
    pub fn new(config: TelemetryConfig) -> Self {
        Self {
            config,
            events: Vec::new(),
            session_id: Uuid::new_v4().to_string(),
            errors: Vec::new(),
            metrics: Vec::new(),
        }
    }

    pub fn record_event(
        &mut self,
        event_type: EventType,
        user_id: Option<String>,
        properties: HashMap<String, String>,
    ) {
        if !self.should_sample() {
            return;
        }

        let event = TelemetryEvent {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            event_type,
            user_id,
            session_id: self.session_id.clone(),
            properties,
        };

        self.events.push(event);

        if self.events.len() >= self.config.batch_size {
            self.flush();
        }
    }

    pub fn record_error(
        &mut self,
        error_type: String,
        message: String,
        severity: ErrorSeverity,
    ) {
        if !self.config.error_tracking_enabled {
            return;
        }

        let error = ErrorReport {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            error_type,
            message,
            stacktrace: None,
            context: HashMap::new(),
            severity,
        };

        self.errors.push(error);
    }

    pub fn record_performance_metric(&mut self, metric: PerformanceMetric) {
        if !self.config.performance_tracking_enabled {
            return;
        }

        self.metrics.push(metric);
    }

    pub fn record_feature_usage(&mut self, _feature: String, properties: HashMap<String, String>) {
        if !self.config.feature_tracking_enabled {
            return;
        }

        self.record_event(EventType::FeatureUsage, None, properties);
    }

    pub fn flush(&mut self) {
        if self.config.enabled && !self.events.is_empty() {
            // Send events to telemetry endpoint
            let _ = self.send_events();
            self.events.clear();
        }
    }

    fn should_sample(&self) -> bool {
        let nanos = Utc::now().timestamp_nanos_opt().unwrap_or(0) as f64;
        (nanos % 100.0) / 100.0 < self.config.sample_rate
    }

    fn send_events(&self) -> Result<(), String> {
        // Implementation would send to telemetry endpoint
        Ok(())
    }

    pub fn get_events(&self) -> &[TelemetryEvent] {
        &self.events
    }

    pub fn get_errors(&self) -> &[ErrorReport] {
        &self.errors
    }

    pub fn get_metrics(&self) -> &[PerformanceMetric] {
        &self.metrics
    }
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: "https://telemetry.venom.dev".to_string(),
            sample_rate: 0.1,
            api_key: None,
            batch_size: 100,
            flush_interval_seconds: 60,
            error_tracking_enabled: true,
            performance_tracking_enabled: true,
            feature_tracking_enabled: true,
            crash_reporting_enabled: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_telemetry_collector_creation() {
        let config = TelemetryConfig::default();
        let collector = TelemetryCollector::new(config);
        assert_eq!(collector.events.len(), 0);
    }

    #[test]
    fn test_record_event() {
        let config = TelemetryConfig {
            enabled: true,
            sample_rate: 1.0,
            ..Default::default()
        };
        let mut collector = TelemetryCollector::new(config);
        let mut props = HashMap::new();
        props.insert("scan_type".to_string(), "web".to_string());

        collector.record_event(EventType::ScanStarted, None, props);
        assert!(collector.events.len() > 0);
    }

    #[test]
    fn test_record_error() {
        let config = TelemetryConfig {
            error_tracking_enabled: true,
            ..Default::default()
        };
        let mut collector = TelemetryCollector::new(config);
        collector.record_error(
            "NullPointerException".to_string(),
            "Value was null".to_string(),
            ErrorSeverity::High,
        );
        assert_eq!(collector.errors.len(), 1);
    }
}
