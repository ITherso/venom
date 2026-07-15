use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc, Duration};
use uuid::Uuid;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum SLALevel {
    Platinum,
    Gold,
    Silver,
    Bronze,
}

impl SLALevel {
    pub fn availability_percentage(&self) -> f32 {
        match self {
            SLALevel::Platinum => 99.99,
            SLALevel::Gold => 99.9,
            SLALevel::Silver => 99.5,
            SLALevel::Bronze => 99.0,
        }
    }

    pub fn max_downtime_hours_per_month(&self) -> f32 {
        let availability = self.availability_percentage();
        (100.0 - availability) / 100.0 * 24.0 * 30.0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SLAMetric {
    pub id: String,
    pub name: String,
    pub metric_type: MetricType,
    pub sla_level: SLALevel,
    pub target_value: f32,
    pub current_value: f32,
    pub unit: String,
    pub last_updated: DateTime<Utc>,
    pub measurements: Vec<MetricMeasurement>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MetricType {
    Availability,
    Latency,
    Throughput,
    ErrorRate,
    CustomMetric,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricMeasurement {
    pub timestamp: DateTime<Utc>,
    pub value: f32,
}

impl SLAMetric {
    pub fn new(
        name: String,
        metric_type: MetricType,
        sla_level: SLALevel,
        target_value: f32,
        unit: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            metric_type,
            sla_level,
            target_value,
            current_value: target_value,
            unit,
            last_updated: Utc::now(),
            measurements: Vec::new(),
        }
    }

    pub fn record_measurement(&mut self, value: f32) {
        self.measurements.push(MetricMeasurement {
            timestamp: Utc::now(),
            value,
        });
        self.current_value = value;
        self.last_updated = Utc::now();
    }

    pub fn is_within_sla(&self) -> bool {
        match self.metric_type {
            MetricType::Availability => self.current_value >= self.target_value,
            MetricType::Latency => self.current_value <= self.target_value,
            MetricType::Throughput => self.current_value >= self.target_value,
            MetricType::ErrorRate => self.current_value <= self.target_value,
            MetricType::CustomMetric => self.current_value >= self.target_value,
        }
    }

    pub fn get_average_value(&self, last_n_hours: i64) -> Option<f32> {
        let cutoff = Utc::now() - Duration::hours(last_n_hours);
        let recent: Vec<f32> = self.measurements
            .iter()
            .filter(|m| m.timestamp > cutoff)
            .map(|m| m.value)
            .collect();

        if recent.is_empty() {
            None
        } else {
            Some(recent.iter().sum::<f32>() / recent.len() as f32)
        }
    }

    pub fn get_min_max(&self, last_n_hours: i64) -> Option<(f32, f32)> {
        let cutoff = Utc::now() - Duration::hours(last_n_hours);
        let recent: Vec<f32> = self.measurements
            .iter()
            .filter(|m| m.timestamp > cutoff)
            .map(|m| m.value)
            .collect();

        if recent.is_empty() {
            None
        } else {
            let min = recent.iter().copied().fold(f32::INFINITY, f32::min);
            let max = recent.iter().copied().fold(f32::NEG_INFINITY, f32::max);
            Some((min, max))
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SLAViolation {
    pub id: String,
    pub metric_id: String,
    pub severity: ViolationSeverity,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub duration_seconds: Option<u32>,
    pub breach_value: f32,
    pub threshold_value: f32,
    pub description: String,
    pub resolution: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ViolationSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SLAMonitor {
    metrics: HashMap<String, SLAMetric>,
    violations: Vec<SLAViolation>,
    sla_agreements: HashMap<String, SLAAgreement>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SLAAgreement {
    pub id: String,
    pub name: String,
    pub sla_level: SLALevel,
    pub start_date: DateTime<Utc>,
    pub end_date: Option<DateTime<Utc>>,
    pub metrics: Vec<String>,
    pub penalties: HashMap<ViolationSeverity, String>,
}

impl SLAAgreement {
    pub fn new(name: String, sla_level: SLALevel) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            sla_level,
            start_date: Utc::now(),
            end_date: None,
            metrics: Vec::new(),
            penalties: HashMap::new(),
        }
    }

    pub fn add_metric(&mut self, metric_id: String) {
        self.metrics.push(metric_id);
    }
}

impl SLAMonitor {
    pub fn new() -> Self {
        Self {
            metrics: HashMap::new(),
            violations: Vec::new(),
            sla_agreements: HashMap::new(),
        }
    }

    pub fn create_metric(
        &mut self,
        name: String,
        metric_type: MetricType,
        sla_level: SLALevel,
        target_value: f32,
        unit: String,
    ) -> String {
        let metric = SLAMetric::new(name, metric_type, sla_level, target_value, unit);
        let metric_id = metric.id.clone();
        self.metrics.insert(metric_id.clone(), metric);
        metric_id
    }

    pub fn get_metric(&self, metric_id: &str) -> Option<&SLAMetric> {
        self.metrics.get(metric_id)
    }

    pub fn get_metric_mut(&mut self, metric_id: &str) -> Option<&mut SLAMetric> {
        self.metrics.get_mut(metric_id)
    }

    pub fn record_metric_value(&mut self, metric_id: &str, value: f32) {
        let should_violate = if let Some(metric) = self.get_metric_mut(metric_id) {
            metric.record_measurement(value);
            !metric.is_within_sla()
        } else {
            false
        };

        if let Some(metric) = self.get_metric(metric_id) {
            if should_violate {
                self.create_violation(metric_id, value, metric.target_value);
            }
        }
    }

    fn create_violation(&mut self, metric_id: &str, breach_value: f32, threshold_value: f32) {
        if let Some(metric) = self.get_metric(metric_id) {
            let severity = match metric.sla_level {
                SLALevel::Platinum => ViolationSeverity::Critical,
                SLALevel::Gold => ViolationSeverity::High,
                SLALevel::Silver => ViolationSeverity::Medium,
                SLALevel::Bronze => ViolationSeverity::Low,
            };

            let violation = SLAViolation {
                id: Uuid::new_v4().to_string(),
                metric_id: metric_id.to_string(),
                severity,
                start_time: Utc::now(),
                end_time: None,
                duration_seconds: None,
                breach_value,
                threshold_value,
                description: format!("{} SLA violated: {} (threshold: {})", metric.name, breach_value, threshold_value),
                resolution: None,
            };
            self.violations.push(violation);
        }
    }

    pub fn list_metrics(&self) -> Vec<&SLAMetric> {
        self.metrics.values().collect()
    }

    pub fn get_metrics_within_sla(&self) -> Vec<&SLAMetric> {
        self.metrics
            .values()
            .filter(|m| m.is_within_sla())
            .collect()
    }

    pub fn get_metrics_violating_sla(&self) -> Vec<&SLAMetric> {
        self.metrics
            .values()
            .filter(|m| !m.is_within_sla())
            .collect()
    }

    pub fn get_active_violations(&self) -> Vec<&SLAViolation> {
        self.violations
            .iter()
            .filter(|v| v.end_time.is_none())
            .collect()
    }

    pub fn get_all_violations(&self) -> Vec<&SLAViolation> {
        self.violations.iter().collect()
    }

    pub fn resolve_violation(&mut self, violation_id: &str, resolution: String) -> bool {
        if let Some(violation) = self.violations.iter_mut().find(|v| v.id == violation_id) {
            violation.end_time = Some(Utc::now());
            violation.duration_seconds = Some((violation.end_time.unwrap() - violation.start_time).num_seconds() as u32);
            violation.resolution = Some(resolution);
            true
        } else {
            false
        }
    }

    pub fn create_sla_agreement(&mut self, name: String, sla_level: SLALevel) -> String {
        let agreement = SLAAgreement::new(name, sla_level);
        let agreement_id = agreement.id.clone();
        self.sla_agreements.insert(agreement_id.clone(), agreement);
        agreement_id
    }

    pub fn get_sla_agreement(&self, agreement_id: &str) -> Option<&SLAAgreement> {
        self.sla_agreements.get(agreement_id)
    }

    pub fn list_sla_agreements(&self) -> Vec<&SLAAgreement> {
        self.sla_agreements.values().collect()
    }

    pub fn get_statistics(&self) -> SLAStatistics {
        let total_metrics = self.metrics.len();
        let metrics_within_sla = self.get_metrics_within_sla().len();
        let active_violations = self.get_active_violations().len();
        let total_violations = self.violations.len();

        let avg_availability = if total_metrics > 0 {
            self.metrics
                .values()
                .filter(|m| m.metric_type == MetricType::Availability)
                .map(|m| m.current_value)
                .sum::<f32>() / self.metrics.len() as f32
        } else {
            0.0
        };

        SLAStatistics {
            total_metrics,
            metrics_within_sla,
            active_violations,
            total_violations,
            average_availability_percentage: avg_availability,
            total_agreements: self.sla_agreements.len(),
        }
    }
}

impl Default for SLAMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SLAStatistics {
    pub total_metrics: usize,
    pub metrics_within_sla: usize,
    pub active_violations: usize,
    pub total_violations: usize,
    pub average_availability_percentage: f32,
    pub total_agreements: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sla_level_availability() {
        assert_eq!(SLALevel::Platinum.availability_percentage(), 99.99);
        assert_eq!(SLALevel::Gold.availability_percentage(), 99.9);
    }

    #[test]
    fn test_sla_metric_creation() {
        let metric = SLAMetric::new(
            "Availability".to_string(),
            MetricType::Availability,
            SLALevel::Gold,
            99.9,
            "%".to_string(),
        );
        assert_eq!(metric.current_value, 99.9);
    }

    #[test]
    fn test_metric_within_sla() {
        let metric = SLAMetric::new(
            "Availability".to_string(),
            MetricType::Availability,
            SLALevel::Gold,
            99.9,
            "%".to_string(),
        );
        assert!(metric.is_within_sla());
    }

    #[test]
    fn test_sla_monitor_creation() {
        let monitor = SLAMonitor::new();
        assert_eq!(monitor.list_metrics().len(), 0);
    }

    #[test]
    fn test_create_metric_and_record() {
        let mut monitor = SLAMonitor::new();
        let metric_id = monitor.create_metric(
            "Availability".to_string(),
            MetricType::Availability,
            SLALevel::Gold,
            99.9,
            "%".to_string(),
        );
        monitor.record_metric_value(&metric_id, 99.95);

        let metric = monitor.get_metric(&metric_id).unwrap();
        assert_eq!(metric.current_value, 99.95);
    }

    #[test]
    fn test_sla_violation_detection() {
        let mut monitor = SLAMonitor::new();
        let metric_id = monitor.create_metric(
            "Availability".to_string(),
            MetricType::Availability,
            SLALevel::Gold,
            99.9,
            "%".to_string(),
        );
        monitor.record_metric_value(&metric_id, 98.5);

        assert!(!monitor.get_active_violations().is_empty());
    }

    #[test]
    fn test_create_sla_agreement() {
        let mut monitor = SLAMonitor::new();
        let agreement_id = monitor.create_sla_agreement(
            "Agreement1".to_string(),
            SLALevel::Gold,
        );
        assert!(monitor.get_sla_agreement(&agreement_id).is_some());
    }
}
