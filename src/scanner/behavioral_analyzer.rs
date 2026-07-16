// Behavioral Analysis - User & Bot Detection (300+ lines)
use crate::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorProfile {
    pub user_id: String,
    pub patterns: HashMap<String, f64>,
    pub request_count: usize,
    pub anomaly_score: f64,
    pub behavior_type: BehaviorType,
    pub risk_indicators: Vec<String>,
    pub confidence: f64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum BehaviorType {
    NormalUser,
    Attacker,
    Scanner,
    BotActivity,
    PrivilegedUser,
    SuspiciousActivity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSession {
    pub session_id: String,
    pub user_id: String,
    pub requests: Vec<RequestBehavior>,
    pub start_time: u64,
    pub end_time: u64,
    pub ip_address: String,
    pub user_agent: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestBehavior {
    pub timestamp: u64,
    pub method: String,
    pub path: String,
    pub response_code: u16,
    pub response_time_ms: u64,
    pub parameter_count: usize,
    pub has_payload: bool,
    pub payload_type: String,
}

pub struct BehavioralAnalyzer {
    profiles: HashMap<String, BehaviorProfile>,
    sessions: HashMap<String, UserSession>,
    patterns: PatternLearner,
}

pub struct PatternLearner {
    normal_patterns: HashMap<String, f64>,
    attack_patterns: HashMap<String, f64>,
    bot_patterns: HashMap<String, f64>,
}

impl BehavioralAnalyzer {
    pub fn new() -> Self {
        Self {
            profiles: HashMap::new(),
            sessions: HashMap::new(),
            patterns: PatternLearner::new(),
        }
    }

    /// Analyze user behavior
    pub fn analyze_behavior(
        &mut self,
        user_id: &str,
        requests: &[RequestBehavior],
    ) -> Result<BehaviorProfile> {
        let mut patterns = HashMap::new();
        let mut risk_indicators = Vec::new();

        // Analyze request patterns
        patterns.insert("request_rate".to_string(), self.calculate_request_rate(requests));
        patterns.insert(
            "response_time_variance".to_string(),
            self.calculate_response_time_variance(requests),
        );
        patterns.insert(
            "parameter_variance".to_string(),
            self.calculate_parameter_variance(requests),
        );
        patterns.insert("method_diversity".to_string(), self.calculate_method_diversity(requests));
        patterns.insert("path_entropy".to_string(), self.calculate_path_entropy(requests));

        // Detect behavioral anomalies
        if patterns["request_rate"] > 100.0 {
            risk_indicators.push("Extremely high request rate".to_string());
        }

        if patterns["response_time_variance"] > 5.0 {
            risk_indicators.push("Unusual response time variance".to_string());
        }

        if self.detect_scanning_pattern(requests) {
            risk_indicators.push("Scanning pattern detected".to_string());
        }

        if self.detect_timing_attack(requests) {
            risk_indicators.push("Possible timing attack".to_string());
        }

        if self.detect_brute_force(requests) {
            risk_indicators.push("Brute force pattern detected".to_string());
        }

        // Determine behavior type
        let behavior_type = self.classify_behavior(&patterns, &risk_indicators);
        let anomaly_score = self.calculate_anomaly_score(&patterns);

        let profile = BehaviorProfile {
            user_id: user_id.to_string(),
            patterns,
            request_count: requests.len(),
            anomaly_score,
            behavior_type,
            risk_indicators,
            confidence: 0.85,
        };

        self.profiles.insert(user_id.to_string(), profile.clone());
        Ok(profile)
    }

    /// Detect if behavior is scanning
    fn detect_scanning_pattern(&self, requests: &[RequestBehavior]) -> bool {
        let mut path_count = HashMap::new();

        for req in requests {
            *path_count.entry(req.path.clone()).or_insert(0) += 1;
        }

        // High number of unique paths = likely scanning
        path_count.len() > requests.len() / 2
    }

    /// Detect timing attacks
    fn detect_timing_attack(&self, requests: &[RequestBehavior]) -> bool {
        if requests.len() < 5 {
            return false;
        }

        let times: Vec<u64> = requests.iter().map(|r| r.response_time_ms).collect();
        let avg = times.iter().sum::<u64>() as f64 / times.len() as f64;

        // Check for precise timing patterns (possible timing attack)
        let mut precision_count = 0;
        for time in &times {
            if (*time as f64 - avg).abs() < 10.0 {
                precision_count += 1;
            }
        }

        precision_count as f64 / times.len() as f64 > 0.7
    }

    /// Detect brute force attempts
    fn detect_brute_force(&self, requests: &[RequestBehavior]) -> bool {
        if requests.len() < 10 {
            return false;
        }

        let mut post_count = 0;
        let mut failed_count = 0;

        for req in requests {
            if req.method == "POST" {
                post_count += 1;
            }
            if req.response_code == 401 || req.response_code == 403 {
                failed_count += 1;
            }
        }

        // Frequent POST requests with auth failures = brute force
        post_count > 5 && failed_count as f64 / post_count as f64 > 0.5
    }

    /// Calculate request rate (requests per minute)
    fn calculate_request_rate(&self, requests: &[RequestBehavior]) -> f64 {
        if requests.is_empty() {
            return 0.0;
        }

        if requests.len() == 1 {
            return 0.0;
        }

        let first_time = requests[0].timestamp;
        let last_time = requests[requests.len() - 1].timestamp;
        let duration_secs = if last_time > first_time {
            (last_time - first_time) as f64
        } else {
            1.0
        };

        (requests.len() as f64 / duration_secs) * 60.0
    }

    /// Calculate response time variance
    fn calculate_response_time_variance(&self, requests: &[RequestBehavior]) -> f64 {
        if requests.is_empty() {
            return 0.0;
        }

        let times: Vec<u64> = requests.iter().map(|r| r.response_time_ms).collect();
        let avg = times.iter().sum::<u64>() as f64 / times.len() as f64;

        let variance: f64 = times
            .iter()
            .map(|t| (*t as f64 - avg).powi(2))
            .sum::<f64>()
            / times.len() as f64;

        variance.sqrt() / avg
    }

    /// Calculate parameter variance
    fn calculate_parameter_variance(&self, requests: &[RequestBehavior]) -> f64 {
        if requests.is_empty() {
            return 0.0;
        }

        let params: Vec<usize> = requests.iter().map(|r| r.parameter_count).collect();
        let avg = params.iter().sum::<usize>() as f64 / params.len() as f64;

        let variance: f64 = params
            .iter()
            .map(|p| (*p as f64 - avg).powi(2))
            .sum::<f64>()
            / params.len() as f64;

        variance.sqrt()
    }

    /// Calculate method diversity (GET/POST/etc)
    fn calculate_method_diversity(&self, requests: &[RequestBehavior]) -> f64 {
        if requests.is_empty() {
            return 0.0;
        }

        let mut methods = std::collections::HashSet::new();
        for req in requests {
            methods.insert(req.method.clone());
        }

        methods.len() as f64
    }

    /// Calculate path entropy (randomness of paths)
    fn calculate_path_entropy(&self, requests: &[RequestBehavior]) -> f64 {
        if requests.is_empty() {
            return 0.0;
        }

        let mut path_chars = HashMap::new();
        let mut total_chars = 0;

        for req in requests {
            for ch in req.path.chars() {
                *path_chars.entry(ch).or_insert(0) += 1;
                total_chars += 1;
            }
        }

        let mut entropy = 0.0;
        for count in path_chars.values() {
            let p = *count as f64 / total_chars as f64;
            entropy -= p * p.log2();
        }

        entropy
    }

    /// Classify behavior into categories
    fn classify_behavior(&self, patterns: &HashMap<String, f64>, risk_indicators: &[String]) -> BehaviorType {
        let request_rate = patterns.get("request_rate").copied().unwrap_or(0.0);
        let path_entropy = patterns.get("path_entropy").copied().unwrap_or(0.0);

        if risk_indicators.iter().any(|r| r.contains("Brute force")) {
            return BehaviorType::Attacker;
        }

        if risk_indicators.iter().any(|r| r.contains("Scanning")) {
            return BehaviorType::Scanner;
        }

        if request_rate > 50.0 || (request_rate > 20.0 && path_entropy > 4.0) {
            return BehaviorType::BotActivity;
        }

        if risk_indicators.is_empty() && request_rate < 5.0 {
            return BehaviorType::NormalUser;
        }

        BehaviorType::SuspiciousActivity
    }

    /// Calculate overall anomaly score
    fn calculate_anomaly_score(&self, patterns: &HashMap<String, f64>) -> f64 {
        let mut score = 0.0;
        let mut count = 0;

        if let Some(&rate) = patterns.get("request_rate") {
            score += (rate / 100.0).min(1.0);
            count += 1;
        }

        if let Some(&variance) = patterns.get("response_time_variance") {
            score += (variance / 5.0).min(1.0);
            count += 1;
        }

        if let Some(&param_var) = patterns.get("parameter_variance") {
            score += (param_var / 10.0).min(1.0);
            count += 1;
        }

        if count > 0 {
            score / count as f64
        } else {
            0.0
        }
    }

    /// Get behavior profile
    pub fn get_profile(&self, user_id: &str) -> Option<BehaviorProfile> {
        self.profiles.get(user_id).cloned()
    }

    /// Compare behaviors for similarity
    pub fn compare_behaviors(
        &self,
        profile1: &BehaviorProfile,
        profile2: &BehaviorProfile,
    ) -> f64 {
        let mut similarity = 0.0;
        let mut count = 0;

        for (key, val1) in &profile1.patterns {
            if let Some(val2) = profile2.patterns.get(key) {
                let diff = (val1 - val2).abs();
                similarity += 1.0 - (diff / (val1.abs().max(val2.abs()) + 0.001));
                count += 1;
            }
        }

        if count > 0 {
            similarity / count as f64
        } else {
            0.0
        }
    }
}

impl PatternLearner {
    fn new() -> Self {
        Self {
            normal_patterns: HashMap::new(),
            attack_patterns: HashMap::new(),
            bot_patterns: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_behavior_type_differentiation() {
        assert_ne!(BehaviorType::NormalUser, BehaviorType::Attacker);
        assert_ne!(BehaviorType::Scanner, BehaviorType::BotActivity);
    }

    #[test]
    fn test_analyzer_initialization() {
        let analyzer = BehavioralAnalyzer::new();
        assert_eq!(analyzer.profiles.len(), 0);
    }

    #[test]
    fn test_calculate_request_rate() {
        let analyzer = BehavioralAnalyzer::new();
        let requests = vec![
            RequestBehavior {
                timestamp: 1000,
                method: "GET".to_string(),
                path: "/api".to_string(),
                response_code: 200,
                response_time_ms: 100,
                parameter_count: 1,
                has_payload: false,
                payload_type: "".to_string(),
            },
            RequestBehavior {
                timestamp: 1060,
                method: "GET".to_string(),
                path: "/api".to_string(),
                response_code: 200,
                response_time_ms: 100,
                parameter_count: 1,
                has_payload: false,
                payload_type: "".to_string(),
            },
        ];

        let rate = analyzer.calculate_request_rate(&requests);
        assert!(rate > 0.0);
    }

    #[test]
    fn test_detect_scanning_pattern() {
        let analyzer = BehavioralAnalyzer::new();
        let requests = vec![
            RequestBehavior {
                timestamp: 1000,
                method: "GET".to_string(),
                path: "/path1".to_string(),
                response_code: 200,
                response_time_ms: 100,
                parameter_count: 1,
                has_payload: false,
                payload_type: "".to_string(),
            },
            RequestBehavior {
                timestamp: 1001,
                method: "GET".to_string(),
                path: "/path2".to_string(),
                response_code: 200,
                response_time_ms: 100,
                parameter_count: 1,
                has_payload: false,
                payload_type: "".to_string(),
            },
            RequestBehavior {
                timestamp: 1002,
                method: "GET".to_string(),
                path: "/path3".to_string(),
                response_code: 200,
                response_time_ms: 100,
                parameter_count: 1,
                has_payload: false,
                payload_type: "".to_string(),
            },
        ];

        assert!(analyzer.detect_scanning_pattern(&requests));
    }

    #[test]
    fn test_detect_brute_force() {
        let analyzer = BehavioralAnalyzer::new();
        let mut requests = Vec::new();

        for _ in 0..10 {
            requests.push(RequestBehavior {
                timestamp: 1000,
                method: "POST".to_string(),
                path: "/login".to_string(),
                response_code: 401,
                response_time_ms: 100,
                parameter_count: 2,
                has_payload: true,
                payload_type: "form".to_string(),
            });
        }

        assert!(analyzer.detect_brute_force(&requests));
    }

    #[test]
    fn test_method_diversity() {
        let analyzer = BehavioralAnalyzer::new();
        let requests = vec![
            RequestBehavior {
                timestamp: 1000,
                method: "GET".to_string(),
                path: "/".to_string(),
                response_code: 200,
                response_time_ms: 100,
                parameter_count: 0,
                has_payload: false,
                payload_type: "".to_string(),
            },
            RequestBehavior {
                timestamp: 1001,
                method: "POST".to_string(),
                path: "/".to_string(),
                response_code: 200,
                response_time_ms: 100,
                parameter_count: 1,
                has_payload: true,
                payload_type: "json".to_string(),
            },
            RequestBehavior {
                timestamp: 1002,
                method: "DELETE".to_string(),
                path: "/".to_string(),
                response_code: 200,
                response_time_ms: 100,
                parameter_count: 0,
                has_payload: false,
                payload_type: "".to_string(),
            },
        ];

        let diversity = analyzer.calculate_method_diversity(&requests);
        assert_eq!(diversity, 3.0);
    }

    #[test]
    fn test_behavior_profile_analysis() {
        let mut analyzer = BehavioralAnalyzer::new();
        let requests = vec![
            RequestBehavior {
                timestamp: 1000,
                method: "GET".to_string(),
                path: "/api".to_string(),
                response_code: 200,
                response_time_ms: 100,
                parameter_count: 1,
                has_payload: false,
                payload_type: "".to_string(),
            },
        ];

        let profile = analyzer.analyze_behavior("user1", &requests).unwrap();
        assert_eq!(profile.user_id, "user1");
        assert_eq!(profile.request_count, 1);
    }

    #[test]
    fn test_profile_storage() {
        let mut analyzer = BehavioralAnalyzer::new();
        let requests = vec![RequestBehavior {
            timestamp: 1000,
            method: "GET".to_string(),
            path: "/api".to_string(),
            response_code: 200,
            response_time_ms: 100,
            parameter_count: 1,
            has_payload: false,
            payload_type: "".to_string(),
        }];

        analyzer.analyze_behavior("user1", &requests).unwrap();
        let retrieved = analyzer.get_profile("user1");
        assert!(retrieved.is_some());
    }
}
