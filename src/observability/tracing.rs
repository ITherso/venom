use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracingConfig {
    pub enabled: bool,
    pub endpoint: String,
    pub sample_rate: f64,
    pub max_attributes: usize,
    pub max_events: usize,
    pub exporter_type: ExporterType,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExporterType {
    Jaeger,
    Zipkin,
    OpenTelemetry,
    Datadog,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracingSpan {
    pub id: String,
    pub trace_id: String,
    pub parent_span_id: Option<String>,
    pub name: String,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub status: SpanStatus,
    pub attributes: Vec<(String, String)>,
    pub events: Vec<SpanEvent>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SpanStatus {
    Unset,
    Ok,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanEvent {
    pub name: String,
    pub timestamp: DateTime<Utc>,
    pub attributes: Vec<(String, String)>,
}

impl TracingSpan {
    pub fn new(name: String, trace_id: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            trace_id,
            parent_span_id: None,
            name,
            start_time: Utc::now(),
            end_time: None,
            status: SpanStatus::Unset,
            attributes: Vec::new(),
            events: Vec::new(),
        }
    }

    pub fn with_parent(name: String, trace_id: String, parent_span_id: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            trace_id,
            parent_span_id: Some(parent_span_id),
            name,
            start_time: Utc::now(),
            end_time: None,
            status: SpanStatus::Unset,
            attributes: Vec::new(),
            events: Vec::new(),
        }
    }

    pub fn add_attribute(&mut self, key: String, value: String) {
        if self.attributes.len() < 100 {
            self.attributes.push((key, value));
        }
    }

    pub fn add_event(&mut self, name: String) {
        if self.events.len() < 128 {
            self.events.push(SpanEvent {
                name,
                timestamp: Utc::now(),
                attributes: Vec::new(),
            });
        }
    }

    pub fn end(&mut self) {
        self.end_time = Some(Utc::now());
    }

    pub fn end_with_status(&mut self, status: SpanStatus) {
        self.end_time = Some(Utc::now());
        self.status = status;
    }

    pub fn duration_ms(&self) -> Option<f64> {
        self.end_time.map(|end| {
            (end - self.start_time).num_milliseconds() as f64
        })
    }

    pub fn is_finished(&self) -> bool {
        self.end_time.is_some()
    }
}

#[derive(Debug, Clone)]
pub struct TracingCollector {
    config: TracingConfig,
    spans: Vec<TracingSpan>,
}

impl TracingCollector {
    pub fn new(config: TracingConfig) -> Self {
        Self {
            config,
            spans: Vec::new(),
        }
    }

    pub fn create_span(&self, name: String) -> TracingSpan {
        TracingSpan::new(name, Uuid::new_v4().to_string())
    }

    pub fn record_span(&mut self, span: TracingSpan) {
        if self.config.enabled && self.should_sample() {
            self.spans.push(span);
        }
    }

    pub fn get_trace(&self, trace_id: &str) -> Vec<&TracingSpan> {
        self.spans
            .iter()
            .filter(|s| s.trace_id == trace_id)
            .collect()
    }

    pub fn get_spans(&self) -> &[TracingSpan] {
        &self.spans
    }

    fn should_sample(&self) -> bool {
        let nanos = Utc::now().timestamp_nanos_opt().unwrap_or(0) as f64;
        (nanos % 100.0) / 100.0 < self.config.sample_rate
    }

    pub fn export(&self) -> String {
        serde_json::to_string(&self.spans).unwrap_or_default()
    }
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: "http://localhost:4317".to_string(),
            sample_rate: 0.1,
            max_attributes: 128,
            max_events: 128,
            exporter_type: ExporterType::OpenTelemetry,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_span_creation() {
        let span = TracingSpan::new("test".to_string(), "trace123".to_string());
        assert_eq!(span.name, "test");
        assert!(!span.is_finished());
    }

    #[test]
    fn test_span_with_parent() {
        let span = TracingSpan::with_parent(
            "child".to_string(),
            "trace123".to_string(),
            "parent_span".to_string(),
        );
        assert_eq!(span.parent_span_id, Some("parent_span".to_string()));
    }

    #[test]
    fn test_span_attributes() {
        let mut span = TracingSpan::new("test".to_string(), "trace123".to_string());
        span.add_attribute("key".to_string(), "value".to_string());
        assert_eq!(span.attributes.len(), 1);
    }

    #[test]
    fn test_span_duration() {
        let mut span = TracingSpan::new("test".to_string(), "trace123".to_string());
        span.end();
        assert!(span.duration_ms().is_some());
    }
}
