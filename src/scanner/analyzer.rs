// Comparative Analysis Engine - Detect vulnerabilities by comparing responses
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseComparison {
    pub normal_response: ResponseData,
    pub attack_response: ResponseData,
    pub analysis: AnalysisResult,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseData {
    pub status_code: u16,
    pub content_length: usize,
    pub response_time: Duration,
    pub body: String,
    pub headers: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub is_vulnerable: bool,
    pub confidence: f64,
    pub factors: Vec<Factor>,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Factor {
    pub name: String,
    pub score: f64,
    pub weight: f64,
    pub explanation: String,
}

pub struct ComparativeAnalyzer;

impl ComparativeAnalyzer {
    /// Compare normal response with attack response
    pub fn analyze(normal: &ResponseData, attack: &ResponseData) -> AnalysisResult {
        let mut factors = Vec::new();
        let mut evidence = Vec::new();

        // Factor 1: Response time analysis
        let time_factor = Self::analyze_response_time(&normal, &attack);
        if time_factor.score > 0.0 {
            factors.push(time_factor.clone());
            evidence.push(time_factor.explanation);
        }

        // Factor 2: Content length analysis
        let length_factor = Self::analyze_content_length(&normal, &attack);
        if length_factor.score > 0.0 {
            factors.push(length_factor.clone());
            evidence.push(length_factor.explanation);
        }

        // Factor 3: Status code analysis
        let status_factor = Self::analyze_status_code(&normal, &attack);
        if status_factor.score > 0.0 {
            factors.push(status_factor.clone());
            evidence.push(status_factor.explanation);
        }

        // Factor 4: Error message analysis
        let error_factor = Self::analyze_error_messages(&normal, &attack);
        if error_factor.score > 0.0 {
            factors.push(error_factor.clone());
            evidence.push(error_factor.explanation);
        }

        // Factor 5: Content similarity
        let similarity_factor = Self::analyze_content_similarity(&normal, &attack);
        if similarity_factor.score > 0.0 {
            factors.push(similarity_factor.clone());
            evidence.push(similarity_factor.explanation);
        }

        // Factor 6: Header analysis
        let header_factor = Self::analyze_headers(&normal, &attack);
        if header_factor.score > 0.0 {
            factors.push(header_factor.clone());
            evidence.push(header_factor.explanation);
        }

        // Calculate confidence
        let confidence = Self::calculate_confidence(&factors);

        AnalysisResult {
            is_vulnerable: confidence > 0.65,
            confidence,
            factors,
            evidence,
        }
    }

    fn analyze_response_time(normal: &ResponseData, attack: &ResponseData) -> Factor {
        let normal_ms = normal.response_time.as_millis() as f64;
        let attack_ms = attack.response_time.as_millis() as f64;

        let difference = attack_ms - normal_ms;
        let percentage_increase = (difference / normal_ms) * 100.0;

        // Time-based SQLi detection: >5s difference or >500% increase
        let score = if attack_ms > 5000.0 {
            0.9
        } else if percentage_increase > 500.0 {
            0.7
        } else if percentage_increase > 200.0 {
            0.5
        } else if percentage_increase > 50.0 {
            0.3
        } else {
            0.0
        };

        Factor {
            name: "Response Time Anomaly".to_string(),
            score,
            weight: 0.20,
            explanation: format!(
                "Response time increased by {:.0}% ({:.0}ms -> {:.0}ms)",
                percentage_increase, normal_ms, attack_ms
            ),
        }
    }

    fn analyze_content_length(normal: &ResponseData, attack: &ResponseData) -> Factor {
        let normal_len = normal.content_length as f64;
        let attack_len = attack.content_length as f64;

        let difference = (attack_len - normal_len).abs();
        let percentage_diff = (difference / normal_len) * 100.0;

        // Significant content change
        let score = if percentage_diff > 50.0 {
            0.8
        } else if percentage_diff > 20.0 {
            0.6
        } else if percentage_diff > 10.0 {
            0.4
        } else {
            0.0
        };

        Factor {
            name: "Content Length Anomaly".to_string(),
            score,
            weight: 0.15,
            explanation: format!(
                "Content length changed by {:.0}% ({} -> {} bytes)",
                percentage_diff, normal_len, attack_len
            ),
        }
    }

    fn analyze_status_code(normal: &ResponseData, attack: &ResponseData) -> Factor {
        if normal.status_code == attack.status_code {
            return Factor {
                name: "Status Code Consistency".to_string(),
                score: 0.0,
                weight: 0.10,
                explanation: "Status codes match".to_string(),
            };
        }

        let score = match (normal.status_code, attack.status_code) {
            (200, 500) | (200, 502) | (200, 503) => 0.9,
            (200, 404) => 0.7,
            (_, 403) => 0.5,
            _ => 0.2,
        };

        Factor {
            name: "Status Code Anomaly".to_string(),
            score,
            weight: 0.10,
            explanation: format!(
                "Status code changed: {} -> {}",
                normal.status_code, attack.status_code
            ),
        }
    }

    fn analyze_error_messages(normal: &ResponseData, attack: &ResponseData) -> Factor {
        let error_keywords = vec![
            "error", "warning", "sql", "mysql", "postgresql", "oracle", "exception", "traceback",
            "stack trace", "syntax error", "parse error", "fatal",
        ];

        let normal_errors = error_keywords
            .iter()
            .filter(|kw| normal.body.to_lowercase().contains(**kw))
            .count();

        let attack_errors = error_keywords
            .iter()
            .filter(|kw| attack.body.to_lowercase().contains(**kw))
            .count();

        let score = if attack_errors > normal_errors {
            let increase = attack_errors - normal_errors;
            if increase >= 3 {
                0.9
            } else if increase >= 2 {
                0.7
            } else {
                0.5
            }
        } else {
            0.0
        };

        Factor {
            name: "Error Message Anomaly".to_string(),
            score,
            weight: 0.20,
            explanation: format!(
                "Error messages increased: {} -> {}",
                normal_errors, attack_errors
            ),
        }
    }

    fn analyze_content_similarity(normal: &ResponseData, attack: &ResponseData) -> Factor {
        let similarity = Self::calculate_similarity(&normal.body, &attack.body);

        let score = if similarity < 0.5 {
            0.8
        } else if similarity < 0.7 {
            0.6
        } else if similarity < 0.9 {
            0.3
        } else {
            0.0
        };

        Factor {
            name: "Content Similarity".to_string(),
            score,
            weight: 0.15,
            explanation: format!("Content similarity: {:.1}%", similarity * 100.0),
        }
    }

    fn analyze_headers(normal: &ResponseData, attack: &ResponseData) -> Factor {
        let normal_headers: std::collections::HashMap<_, _> =
            normal.headers.iter().map(|(k, v)| (k.to_lowercase(), v)).collect();
        let attack_headers: std::collections::HashMap<_, _> =
            attack.headers.iter().map(|(k, v)| (k.to_lowercase(), v)).collect();

        let mut differences = 0;
        for (key, value) in &attack_headers {
            if !normal_headers.contains_key(key) || normal_headers.get(key) != Some(value) {
                differences += 1;
            }
        }

        let score = if differences > 3 {
            0.7
        } else if differences > 1 {
            0.4
        } else {
            0.0
        };

        Factor {
            name: "Header Anomalies".to_string(),
            score,
            weight: 0.10,
            explanation: format!("{} header differences detected", differences),
        }
    }

    fn calculate_similarity(text1: &str, text2: &str) -> f64 {
        let len1 = text1.len();
        let len2 = text2.len();

        if len1 == 0 || len2 == 0 {
            return 0.0;
        }

        let common = text1.chars().filter(|c| text2.contains(*c)).count();
        common as f64 / len1.max(len2) as f64
    }

    fn calculate_confidence(factors: &[Factor]) -> f64 {
        if factors.is_empty() {
            return 0.0;
        }

        let weighted_sum: f64 = factors.iter().map(|f| f.score * f.weight).sum();
        let total_weight: f64 = factors.iter().map(|f| f.weight).sum();

        weighted_sum / total_weight
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_response(status: u16, length: usize, time_ms: u128) -> ResponseData {
        ResponseData {
            status_code: status,
            content_length: length,
            response_time: Duration::from_millis(time_ms as u64),
            body: "test response".to_string(),
            headers: vec![],
        }
    }

    #[test]
    fn test_time_based_detection() {
        let normal = create_response(200, 1000, 100);
        let attack = create_response(200, 1000, 6000);

        let analysis = ComparativeAnalyzer::analyze(&normal, &attack);
        assert!(analysis.is_vulnerable);
        assert!(analysis.confidence > 0.6);
    }

    #[test]
    fn test_error_based_detection() {
        let normal = ResponseData {
            status_code: 200,
            content_length: 1000,
            response_time: Duration::from_millis(100),
            body: "Welcome to our site".to_string(),
            headers: vec![],
        };

        let attack = ResponseData {
            status_code: 200,
            content_length: 2000,
            response_time: Duration::from_millis(100),
            body: "SQL syntax error in query: SELECT * FROM users WHERE id='test' error mysql".to_string(),
            headers: vec![],
        };

        let analysis = ComparativeAnalyzer::analyze(&normal, &attack);
        assert!(analysis.confidence > 0.5);
    }
}
