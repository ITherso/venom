//! Payload mutation and encoding variations

use super::strategy::DetectionPattern;
use std::time::{SystemTime, UNIX_EPOCH};

/// Payload mutation based on analysis
pub struct PayloadMutator;

impl PayloadMutator {
    /// Mutates payload based on detection pattern
    pub fn mutate(payload: &str, pattern: Option<DetectionPattern>) -> String {
        match pattern {
            Some(DetectionPattern::StatusCodeBlocking(_)) => {
                Self::apply_encoding_mutation(payload)
            }
            Some(DetectionPattern::RateLimiting) => {
                Self::apply_parameter_pollution(payload)
            }
            Some(DetectionPattern::ContentFiltering) => {
                Self::case_mutate(payload)
            }
            None => payload.to_string(),
        }
    }

    /// Applies encoding mutation (case flip)
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

    /// Applies case mutation (alternating case)
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

    /// Applies parameter pollution (adds timestamp decoy)
    fn apply_parameter_pollution(payload: &str) -> String {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        format!("{}&_={}", payload, timestamp)
    }

    /// Adds comment injection
    pub fn inject_comment(payload: &str) -> String {
        format!("{}/**/", payload)
    }

    /// Reduces payload size (basic truncation)
    pub fn reduce_payload(payload: &str, max_size: usize) -> String {
        if payload.len() > max_size {
            payload[..max_size].to_string()
        } else {
            payload.to_string()
        }
    }

    /// Adds decoy parameters
    pub fn add_decoys(payload: &str) -> String {
        format!("{}&x=1&y=2&z=3", payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encoding_mutation() {
        let original = "SELECT";
        let mutated = PayloadMutator::apply_encoding_mutation(original);
        assert_ne!(original, mutated);
        assert_eq!(mutated, "select");
    }

    #[test]
    fn test_case_mutation() {
        let original = "test";
        let mutated = PayloadMutator::case_mutate(original);
        assert_eq!(mutated, "TeStT".chars().take(4).collect::<String>());
    }

    #[test]
    fn test_parameter_pollution() {
        let original = "test";
        let mutated = PayloadMutator::apply_parameter_pollution(original);
        assert!(mutated.contains("&_="));
    }

    #[test]
    fn test_mutation_status_blocking() {
        let original = "SELECT * FROM users";
        let mutated = PayloadMutator::mutate(original, Some(DetectionPattern::StatusCodeBlocking(403)));
        assert_ne!(original, mutated);
    }

    #[test]
    fn test_mutation_rate_limiting() {
        let original = "test";
        let mutated = PayloadMutator::mutate(original, Some(DetectionPattern::RateLimiting));
        assert!(mutated.contains("&_="));
    }

    #[test]
    fn test_comment_injection() {
        let payload = "test";
        let injected = PayloadMutator::inject_comment(payload);
        assert_eq!(injected, "test/**/");
    }

    #[test]
    fn test_reduce_payload() {
        let payload = "verylongpayload";
        let reduced = PayloadMutator::reduce_payload(payload, 4);
        assert_eq!(reduced, "very");
    }

    #[test]
    fn test_add_decoys() {
        let payload = "test";
        let with_decoys = PayloadMutator::add_decoys(payload);
        assert!(with_decoys.contains("&x=1"));
    }
}
