//! Adaptive Payload Engine
//!
//! Analyzes responses and intelligently adapts payloads based on:
//! - Detection patterns (blacklist detection)
//! - Response timing (rate limiting)
//! - Status codes (WAF blocking patterns)
//! - Content changes (response filtering)

use std::collections::VecDeque;
use std::time::Duration;

/// Response metadata for analysis
#[derive(Debug, Clone)]
pub struct ResponseMetrics {
    /// HTTP status code
    pub status: u16,
    /// Response body length
    pub content_length: usize,
    /// Response time in milliseconds
    pub elapsed_ms: u64,
    /// Whether response contained error keywords
    pub has_error_keywords: bool,
    /// Number of redirects followed
    pub redirect_count: u8,
}

/// Payload adaptation strategy based on analysis
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdaptationStrategy {
    /// Increase encoding depth
    IncreaseEncoding,
    /// Add delays between requests
    AddDelay,
    /// Use case variation
    CaseVariation,
    /// Use comment injection
    CommentInjection,
    /// Reduce payload size
    ReducePayload,
    /// Use parameter pollution
    ParameterPollution,
    /// Change HTTP method
    ChangeMethod,
    /// Add decoy parameters
    AddDecoys,
}

/// Learning engine for payload adaptation
#[derive(Debug)]
pub struct AdaptiveEngine {
    /// Recent response metrics
    history: VecDeque<ResponseMetrics>,
    /// Maximum history size
    max_history: usize,
    /// Detection threshold
    detection_threshold: f32,
}

impl AdaptiveEngine {
    /// Creates a new adaptive engine
    pub fn new() -> Self {
        Self {
            history: VecDeque::with_capacity(10),
            max_history: 10,
            detection_threshold: 0.7,
        }
    }

    /// Adds response metrics to history
    pub fn record_response(&mut self, metrics: ResponseMetrics) {
        self.history.push_back(metrics);
        if self.history.len() > self.max_history {
            self.history.pop_front();
        }
    }

    /// Analyzes detection patterns in recent responses
    pub fn analyze_detection_pattern(&self) -> Option<DetectionPattern> {
        if self.history.len() < 3 {
            return None;
        }

        let recent = self.history.iter().rev().take(5);
        let blocked_count = recent.clone().filter(|r| r.status == 403 || r.status == 406).count();
        let timeout_count = recent.clone().filter(|r| r.elapsed_ms > 5000).count();

        if blocked_count >= 3 {
            return Some(DetectionPattern::StatusCodeBlocking(403));
        }
        if timeout_count >= 3 {
            return Some(DetectionPattern::RateLimiting);
        }

        None
    }

    /// Recommends next adaptation strategy
    pub fn recommend_strategy(&self) -> Vec<AdaptationStrategy> {
        let mut strategies = Vec::new();

        match self.analyze_detection_pattern() {
            Some(DetectionPattern::StatusCodeBlocking(_)) => {
                strategies.push(AdaptationStrategy::IncreaseEncoding);
                strategies.push(AdaptationStrategy::CommentInjection);
                strategies.push(AdaptationStrategy::AddDecoys);
            }
            Some(DetectionPattern::RateLimiting) => {
                strategies.push(AdaptationStrategy::AddDelay);
                strategies.push(AdaptationStrategy::ChangeMethod);
            }
            Some(DetectionPattern::ContentFiltering) => {
                strategies.push(AdaptationStrategy::CaseVariation);
                strategies.push(AdaptationStrategy::ReducePayload);
            }
            None => {
                strategies.push(AdaptationStrategy::ParameterPollution);
            }
        }

        strategies
    }

    /// Calculates detection probability (0.0 - 1.0)
    pub fn detection_probability(&self) -> f32 {
        if self.history.is_empty() {
            return 0.0;
        }

        let mut score = 0.0;
        let recent_count = self.history.len().min(5);

        // Status code analysis
        let blocked_ratio = self.history
            .iter()
            .rev()
            .take(recent_count)
            .filter(|r| r.status == 403 || r.status == 406 || r.status == 418)
            .count() as f32 / recent_count as f32;
        score += blocked_ratio * 0.4;

        // Timing analysis
        let slow_ratio = self.history
            .iter()
            .rev()
            .take(recent_count)
            .filter(|r| r.elapsed_ms > 5000)
            .count() as f32 / recent_count as f32;
        score += slow_ratio * 0.3;

        // Error keyword analysis
        let error_ratio = self.history
            .iter()
            .rev()
            .take(recent_count)
            .filter(|r| r.has_error_keywords)
            .count() as f32 / recent_count as f32;
        score += error_ratio * 0.3;

        (score * 100.0).min(1.0)
    }

    /// Checks if payload should be adjusted based on metrics
    pub fn should_adjust_payload(&self) -> bool {
        self.detection_probability() > self.detection_threshold
    }
}

impl Default for AdaptiveEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Detected pattern in responses
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetectionPattern {
    /// Status code blocking (e.g., 403, 406)
    StatusCodeBlocking(u16),
    /// Rate limiting pattern
    RateLimiting,
    /// Content filtering (response content modified)
    ContentFiltering,
}

/// Payload mutation based on analysis
pub struct PayloadMutator;

impl PayloadMutator {
    /// Mutates payload based on detection pattern
    pub fn mutate(payload: &str, pattern: Option<DetectionPattern>) -> String {
        match pattern {
            Some(DetectionPattern::StatusCodeBlocking(_)) => {
                // Use case variation and comment injection
                Self::apply_encoding_mutation(payload)
            }
            Some(DetectionPattern::RateLimiting) => {
                // Use parameter pollution to distribute requests
                format!("{}&_={}", payload, std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis())
            }
            Some(DetectionPattern::ContentFiltering) => {
                // Use case variation
                Self::case_mutate(payload)
            }
            None => payload.to_string(),
        }
    }

    /// Applies encoding mutation
    fn apply_encoding_mutation(payload: &str) -> String {
        payload
            .chars()
            .map(|c| {
                if c.is_alphabetic() {
                    if c.is_uppercase() {
                        c.to_lowercase().to_string()
                    } else {
                        c.to_uppercase().to_string()
                    }
                } else {
                    c.to_string()
                }
            })
            .collect()
    }

    /// Applies case mutation
    fn case_mutate(payload: &str) -> String {
        payload
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if c.is_alphabetic() {
                    if i % 2 == 0 {
                        c.to_uppercase().to_string()
                    } else {
                        c.to_lowercase().to_string()
                    }
                } else {
                    c.to_string()
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adaptive_engine_creation() {
        let engine = AdaptiveEngine::new();
        assert_eq!(engine.history.len(), 0);
    }

    #[test]
    fn test_response_recording() {
        let mut engine = AdaptiveEngine::new();
        let metrics = ResponseMetrics {
            status: 200,
            content_length: 1000,
            elapsed_ms: 100,
            has_error_keywords: false,
            redirect_count: 0,
        };

        engine.record_response(metrics.clone());
        assert_eq!(engine.history.len(), 1);
    }

    #[test]
    fn test_detection_probability() {
        let mut engine = AdaptiveEngine::new();

        // Add blocked responses
        for _ in 0..4 {
            engine.record_response(ResponseMetrics {
                status: 403,
                content_length: 100,
                elapsed_ms: 100,
                has_error_keywords: true,
                redirect_count: 0,
            });
        }

        let prob = engine.detection_probability();
        assert!(prob > 0.5);
    }

    #[test]
    fn test_should_adjust_payload() {
        let mut engine = AdaptiveEngine::new();

        for _ in 0..5 {
            engine.record_response(ResponseMetrics {
                status: 403,
                content_length: 100,
                elapsed_ms: 6000,
                has_error_keywords: true,
                redirect_count: 0,
            });
        }

        assert!(engine.should_adjust_payload());
    }

    #[test]
    fn test_payload_mutation_status_blocking() {
        let original = "SELECT * FROM users";
        let mutated = PayloadMutator::mutate(original, Some(DetectionPattern::StatusCodeBlocking(403)));
        assert_ne!(original, mutated);
    }

    #[test]
    fn test_payload_mutation_rate_limiting() {
        let original = "test";
        let mutated = PayloadMutator::mutate(original, Some(DetectionPattern::RateLimiting));
        assert!(mutated.contains("&_="));
    }

    #[test]
    fn test_recommend_strategies() {
        let mut engine = AdaptiveEngine::new();

        for _ in 0..4 {
            engine.record_response(ResponseMetrics {
                status: 403,
                content_length: 100,
                elapsed_ms: 100,
                has_error_keywords: false,
                redirect_count: 0,
            });
        }

        let strategies = engine.recommend_strategy();
        assert!(!strategies.is_empty());
    }
}
