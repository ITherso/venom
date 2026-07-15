use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StressTest {
    pub id: String,
    pub name: String,
    pub profile: StressProfile,
    pub target_url: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StressProfile {
    pub initial_rps: u32,
    pub peak_rps: u32,
    pub ramp_up_seconds: u32,
    pub sustain_seconds: u32,
    pub cooldown_seconds: u32,
    pub payload_size_bytes: usize,
    pub concurrent_connections: u32,
}

impl StressProfile {
    pub fn new() -> Self {
        Self {
            initial_rps: 100,
            peak_rps: 1000,
            ramp_up_seconds: 60,
            sustain_seconds: 300,
            cooldown_seconds: 60,
            payload_size_bytes: 1024,
            concurrent_connections: 50,
        }
    }

    pub fn with_peak_rps(mut self, rps: u32) -> Self {
        self.peak_rps = rps;
        self
    }

    pub fn with_concurrent_connections(mut self, connections: u32) -> Self {
        self.concurrent_connections = connections;
        self
    }
}

impl Default for StressProfile {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StressTestResult {
    pub test_id: String,
    pub test_name: String,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub total_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub avg_response_time_ms: f64,
    pub p50_response_time_ms: f64,
    pub p95_response_time_ms: f64,
    pub p99_response_time_ms: f64,
    pub max_response_time_ms: f64,
    pub throughput_rps: f64,
    pub errors: Vec<StressError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StressError {
    pub error_type: String,
    pub count: u32,
    pub first_occurrence: DateTime<Utc>,
}

impl StressTest {
    pub fn new(name: String, target_url: String, profile: StressProfile) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            profile,
            target_url,
            created_at: Utc::now(),
        }
    }
}

impl StressTestResult {
    pub fn new(test_id: String, test_name: String) -> Self {
        Self {
            test_id,
            test_name,
            start_time: Utc::now(),
            end_time: Utc::now(),
            total_requests: 0,
            successful_requests: 0,
            failed_requests: 0,
            avg_response_time_ms: 0.0,
            p50_response_time_ms: 0.0,
            p95_response_time_ms: 0.0,
            p99_response_time_ms: 0.0,
            max_response_time_ms: 0.0,
            throughput_rps: 0.0,
            errors: Vec::new(),
        }
    }

    pub fn success_rate(&self) -> f32 {
        if self.total_requests == 0 {
            return 0.0;
        }
        (self.successful_requests as f32 / self.total_requests as f32) * 100.0
    }

    pub fn error_rate(&self) -> f32 {
        100.0 - self.success_rate()
    }

    pub fn duration_seconds(&self) -> u64 {
        (self.end_time - self.start_time).num_seconds() as u64
    }

    pub fn is_sla_compliant(&self, max_p99_ms: f64, min_success_rate: f32) -> bool {
        self.p99_response_time_ms <= max_p99_ms && self.success_rate() >= min_success_rate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stress_profile_creation() {
        let profile = StressProfile::new();
        assert_eq!(profile.peak_rps, 1000);
    }

    #[test]
    fn test_stress_test_creation() {
        let profile = StressProfile::new();
        let test = StressTest::new(
            "Load Test".to_string(),
            "https://example.com".to_string(),
            profile,
        );
        assert_eq!(test.name, "Load Test");
    }

    #[test]
    fn test_stress_result_metrics() {
        let mut result = StressTestResult::new("test_1".to_string(), "Test 1".to_string());
        result.total_requests = 1000;
        result.successful_requests = 950;
        result.failed_requests = 50;
        result.p99_response_time_ms = 150.0;

        assert_eq!(result.success_rate(), 95.0);
        assert!(result.is_sla_compliant(200.0, 90.0));
    }
}
