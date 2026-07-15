use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrometheusMetrics {
    pub version: String,
    pub uptime_seconds: u64,
    pub cpu_usage_percent: f64,
    pub memory_usage_mb: f64,
    pub memory_limit_mb: f64,
    pub disk_usage_mb: f64,
    pub disk_limit_mb: f64,
    pub request_count: u64,
    pub request_errors: u64,
    pub request_latency_ms: f64,
    pub active_connections: u32,
    pub database_connections: u32,
    pub cache_hits: u64,
    pub cache_misses: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricPoint {
    pub timestamp: DateTime<Utc>,
    pub value: f64,
    pub labels: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct MetricsExporter {
    pub metrics: PrometheusMetrics,
    pub history: Vec<MetricPoint>,
    pub start_time: DateTime<Utc>,
}

impl MetricsExporter {
    pub fn new() -> Self {
        Self {
            metrics: PrometheusMetrics {
                version: "1.0.0".to_string(),
                uptime_seconds: 0,
                cpu_usage_percent: 0.0,
                memory_usage_mb: 0.0,
                memory_limit_mb: 0.0,
                disk_usage_mb: 0.0,
                disk_limit_mb: 0.0,
                request_count: 0,
                request_errors: 0,
                request_latency_ms: 0.0,
                active_connections: 0,
                database_connections: 0,
                cache_hits: 0,
                cache_misses: 0,
            },
            history: Vec::new(),
            start_time: Utc::now(),
        }
    }

    pub fn record_request(&mut self, latency_ms: f64, success: bool) {
        self.metrics.request_count += 1;
        self.metrics.request_latency_ms = latency_ms;
        if !success {
            self.metrics.request_errors += 1;
        }
    }

    pub fn record_cache_hit(&mut self) {
        self.metrics.cache_hits += 1;
    }

    pub fn record_cache_miss(&mut self) {
        self.metrics.cache_misses += 1;
    }

    pub fn update_resource_usage(
        &mut self,
        cpu_percent: f64,
        memory_mb: f64,
        disk_mb: f64,
    ) {
        self.metrics.cpu_usage_percent = cpu_percent;
        self.metrics.memory_usage_mb = memory_mb;
        self.metrics.disk_usage_mb = disk_mb;
    }

    pub fn update_connections(&mut self, active: u32, db: u32) {
        self.metrics.active_connections = active;
        self.metrics.database_connections = db;
    }

    pub fn export_prometheus_format(&self) -> String {
        format!(
            r#"# HELP venom_uptime_seconds Uptime in seconds
# TYPE venom_uptime_seconds gauge
venom_uptime_seconds {}

# HELP venom_cpu_usage_percent CPU usage percentage
# TYPE venom_cpu_usage_percent gauge
venom_cpu_usage_percent {:.2}

# HELP venom_memory_usage_mb Memory usage in MB
# TYPE venom_memory_usage_mb gauge
venom_memory_usage_mb {:.2}

# HELP venom_memory_limit_mb Memory limit in MB
# TYPE venom_memory_limit_mb gauge
venom_memory_limit_mb {:.2}

# HELP venom_request_count Total requests
# TYPE venom_request_count counter
venom_request_count {}

# HELP venom_request_errors Total request errors
# TYPE venom_request_errors counter
venom_request_errors {}

# HELP venom_request_latency_ms Request latency in milliseconds
# TYPE venom_request_latency_ms gauge
venom_request_latency_ms {:.2}

# HELP venom_active_connections Active connections
# TYPE venom_active_connections gauge
venom_active_connections {}

# HELP venom_cache_hits Cache hits
# TYPE venom_cache_hits counter
venom_cache_hits {}

# HELP venom_cache_misses Cache misses
# TYPE venom_cache_misses counter
venom_cache_misses {}
"#,
            self.metrics.uptime_seconds,
            self.metrics.cpu_usage_percent,
            self.metrics.memory_usage_mb,
            self.metrics.memory_limit_mb,
            self.metrics.request_count,
            self.metrics.request_errors,
            self.metrics.request_latency_ms,
            self.metrics.active_connections,
            self.metrics.cache_hits,
            self.metrics.cache_misses,
        )
    }

    pub fn cache_hit_rate(&self) -> f64 {
        let total = self.metrics.cache_hits + self.metrics.cache_misses;
        if total == 0 {
            0.0
        } else {
            (self.metrics.cache_hits as f64 / total as f64) * 100.0
        }
    }

    pub fn error_rate(&self) -> f64 {
        if self.metrics.request_count == 0 {
            0.0
        } else {
            (self.metrics.request_errors as f64 / self.metrics.request_count as f64) * 100.0
        }
    }

    pub fn memory_usage_percent(&self) -> f64 {
        if self.metrics.memory_limit_mb > 0.0 {
            (self.metrics.memory_usage_mb / self.metrics.memory_limit_mb) * 100.0
        } else {
            0.0
        }
    }

    pub fn disk_usage_percent(&self) -> f64 {
        if self.metrics.disk_limit_mb > 0.0 {
            (self.metrics.disk_usage_mb / self.metrics.disk_limit_mb) * 100.0
        } else {
            0.0
        }
    }
}

impl Default for MetricsExporter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_creation() {
        let exporter = MetricsExporter::new();
        assert_eq!(exporter.metrics.request_count, 0);
    }

    #[test]
    fn test_record_request() {
        let mut exporter = MetricsExporter::new();
        exporter.record_request(50.0, true);
        assert_eq!(exporter.metrics.request_count, 1);
        assert_eq!(exporter.metrics.request_errors, 0);
    }

    #[test]
    fn test_cache_hit_rate() {
        let mut exporter = MetricsExporter::new();
        exporter.record_cache_hit();
        exporter.record_cache_hit();
        exporter.record_cache_miss();
        let rate = exporter.cache_hit_rate();
        assert!((rate - 66.666666).abs() < 0.01);
    }

    #[test]
    fn test_error_rate() {
        let mut exporter = MetricsExporter::new();
        exporter.record_request(50.0, true);
        exporter.record_request(100.0, false);
        assert_eq!(exporter.error_rate(), 50.0);
    }
}
