//! Response scoring and analysis for adaptive payloads

use std::collections::VecDeque;

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

/// Detects and scores response patterns
#[derive(Debug)]
pub struct ScoringEngine {
    /// Detection threshold
    pub detection_threshold: f32,
}

impl ScoringEngine {
    /// Creates new scoring engine
    pub fn new() -> Self {
        Self {
            detection_threshold: 0.7,
        }
    }

    /// Calculates detection probability (0.0 - 1.0)
    pub fn detection_probability(&self, history: &VecDeque<ResponseMetrics>) -> f32 {
        if history.is_empty() {
            return 0.0;
        }

        let mut score = 0.0;
        let recent_count = history.len().min(5);

        // Status code analysis
        let blocked_ratio = history
            .iter()
            .rev()
            .take(recent_count)
            .filter(|r| r.status == 403 || r.status == 406 || r.status == 418)
            .count() as f32 / recent_count as f32;
        score += blocked_ratio * 0.4;

        // Timing analysis
        let slow_ratio = history
            .iter()
            .rev()
            .take(recent_count)
            .filter(|r| r.elapsed_ms > 5000)
            .count() as f32 / recent_count as f32;
        score += slow_ratio * 0.3;

        // Error keyword analysis
        let error_ratio = history
            .iter()
            .rev()
            .take(recent_count)
            .filter(|r| r.has_error_keywords)
            .count() as f32 / recent_count as f32;
        score += error_ratio * 0.3;

        (score * 100.0).min(1.0)
    }

    /// Checks if payload should be adjusted based on metrics
    pub fn should_adjust_payload(&self, history: &VecDeque<ResponseMetrics>) -> bool {
        self.detection_probability(history) > self.detection_threshold
    }
}

impl Default for ScoringEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scoring_engine_creation() {
        let engine = ScoringEngine::new();
        assert_eq!(engine.detection_threshold, 0.7);
    }

    #[test]
    fn test_detection_probability_empty() {
        let engine = ScoringEngine::new();
        let history = VecDeque::new();
        assert_eq!(engine.detection_probability(&history), 0.0);
    }

    #[test]
    fn test_detection_probability_with_blocks() {
        let engine = ScoringEngine::new();
        let mut history = VecDeque::new();

        for _ in 0..4 {
            history.push_back(ResponseMetrics {
                status: 403,
                content_length: 100,
                elapsed_ms: 100,
                has_error_keywords: true,
                redirect_count: 0,
            });
        }

        let prob = engine.detection_probability(&history);
        assert!(prob > 0.5);
    }

    #[test]
    fn test_should_adjust_payload() {
        let engine = ScoringEngine::new();
        let mut history = VecDeque::new();

        for _ in 0..5 {
            history.push_back(ResponseMetrics {
                status: 403,
                content_length: 100,
                elapsed_ms: 6000,
                has_error_keywords: true,
                redirect_count: 0,
            });
        }

        assert!(engine.should_adjust_payload(&history));
    }
}
