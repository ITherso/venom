use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadTestConfig {
    pub target_url: String,
    pub duration_seconds: u32,
    pub concurrent_users: u32,
    pub requests_per_second: u32,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    pub timeout_seconds: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LoadProfile {
    /// Baseline: 10 concurrent, 100 req/s for 60s
    Baseline,
    /// Standard: 50 concurrent, 500 req/s for 300s
    Standard,
    /// High: 100 concurrent, 1000 req/s for 300s
    High,
    /// Stress: 200 concurrent, 2000 req/s for 600s
    Stress,
    /// Spike: 500 concurrent, 5000 req/s for 60s
    Spike,
    /// Custom configuration
    Custom(LoadTestConfig),
}

impl LoadProfile {
    pub fn config(&self, target_url: &str) -> LoadTestConfig {
        match self {
            LoadProfile::Baseline => LoadTestConfig {
                target_url: target_url.to_string(),
                duration_seconds: 60,
                concurrent_users: 10,
                requests_per_second: 100,
                method: "GET".to_string(),
                headers: vec![],
                body: None,
                timeout_seconds: 30,
            },
            LoadProfile::Standard => LoadTestConfig {
                target_url: target_url.to_string(),
                duration_seconds: 300,
                concurrent_users: 50,
                requests_per_second: 500,
                method: "GET".to_string(),
                headers: vec![],
                body: None,
                timeout_seconds: 30,
            },
            LoadProfile::High => LoadTestConfig {
                target_url: target_url.to_string(),
                duration_seconds: 300,
                concurrent_users: 100,
                requests_per_second: 1000,
                method: "GET".to_string(),
                headers: vec![],
                body: None,
                timeout_seconds: 30,
            },
            LoadProfile::Stress => LoadTestConfig {
                target_url: target_url.to_string(),
                duration_seconds: 600,
                concurrent_users: 200,
                requests_per_second: 2000,
                method: "GET".to_string(),
                headers: vec![],
                body: None,
                timeout_seconds: 30,
            },
            LoadProfile::Spike => LoadTestConfig {
                target_url: target_url.to_string(),
                duration_seconds: 60,
                concurrent_users: 500,
                requests_per_second: 5000,
                method: "GET".to_string(),
                headers: vec![],
                body: None,
                timeout_seconds: 30,
            },
            LoadProfile::Custom(config) => config.clone(),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            LoadProfile::Baseline => "Baseline",
            LoadProfile::Standard => "Standard",
            LoadProfile::High => "High",
            LoadProfile::Stress => "Stress",
            LoadProfile::Spike => "Spike",
            LoadProfile::Custom(_) => "Custom",
        }
    }
}

impl LoadTestConfig {
    pub fn new(target_url: &str) -> Self {
        Self {
            target_url: target_url.to_string(),
            duration_seconds: 60,
            concurrent_users: 10,
            requests_per_second: 100,
            method: "GET".to_string(),
            headers: vec![],
            body: None,
            timeout_seconds: 30,
        }
    }

    pub fn with_duration(mut self, seconds: u32) -> Self {
        self.duration_seconds = seconds;
        self
    }

    pub fn with_concurrency(mut self, users: u32) -> Self {
        self.concurrent_users = users;
        self
    }

    pub fn with_rps(mut self, rps: u32) -> Self {
        self.requests_per_second = rps;
        self
    }

    pub fn with_method(mut self, method: &str) -> Self {
        self.method = method.to_string();
        self
    }

    pub fn with_body(mut self, body: &str) -> Self {
        self.body = Some(body.to_string());
        self
    }

    pub fn with_header(mut self, key: &str, value: &str) -> Self {
        self.headers.push((key.to_string(), value.to_string()));
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_baseline_profile() {
        let config = LoadProfile::Baseline.config("http://localhost:8080");
        assert_eq!(config.concurrent_users, 10);
        assert_eq!(config.requests_per_second, 100);
        assert_eq!(config.duration_seconds, 60);
    }

    #[test]
    fn test_stress_profile() {
        let config = LoadProfile::Stress.config("http://localhost:8080");
        assert_eq!(config.concurrent_users, 200);
        assert_eq!(config.requests_per_second, 2000);
        assert_eq!(config.duration_seconds, 600);
    }

    #[test]
    fn test_custom_config() {
        let config = LoadTestConfig::new("http://target.com")
            .with_concurrency(50)
            .with_rps(500)
            .with_duration(120);

        assert_eq!(config.concurrent_users, 50);
        assert_eq!(config.requests_per_second, 500);
        assert_eq!(config.duration_seconds, 120);
    }
}
