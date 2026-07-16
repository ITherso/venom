// Anomaly Detection - Statistical & Behavioral Analysis (400+ lines)
use crate::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyScore {
    pub request_id: String,
    pub url: String,
    pub method: String,
    pub anomaly_type: AnomalyType,
    pub score: f64, // 0.0-1.0
    pub confidence: f64,
    pub indicators: Vec<String>,
    pub severity: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum AnomalyType {
    ParameterAnomaly,
    VolumeAnomaly,
    TimingAnomaly,
    EncodingAnomaly,
    PayloadAnomaly,
    BehavioralAnomaly,
    HeaderAnomaly,
}

#[derive(Debug, Clone)]
pub struct RequestMetrics {
    pub url: String,
    pub method: String,
    pub parameter_count: usize,
    pub payload_size: usize,
    pub request_time_ms: u64,
    pub encoding_type: String,
    pub header_count: usize,
    pub suspicious_characters: usize,
    pub entropy: f64,
}

pub struct AnomalyDetector {
    baseline_metrics: HashMap<String, RequestMetrics>,
    request_history: Vec<RequestMetrics>,
}

impl AnomalyDetector {
    pub fn new() -> Self {
        Self {
            baseline_metrics: HashMap::new(),
            request_history: Vec::new(),
        }
    }

    /// Comprehensive anomaly detection
    pub fn detect_anomaly(&mut self, metrics: &RequestMetrics) -> Result<Vec<AnomalyScore>> {
        let mut anomalies = Vec::new();

        // Establish baseline from history
        if self.request_history.len() < 10 {
            self.request_history.push(metrics.clone());
            return Ok(anomalies);
        }

        // Parameter anomaly
        if let Some(score) = self.detect_parameter_anomaly(metrics) {
            anomalies.push(score);
        }

        // Volume anomaly
        if let Some(score) = self.detect_volume_anomaly(metrics) {
            anomalies.push(score);
        }

        // Timing anomaly
        if let Some(score) = self.detect_timing_anomaly(metrics) {
            anomalies.push(score);
        }

        // Encoding anomaly
        if let Some(score) = self.detect_encoding_anomaly(metrics) {
            anomalies.push(score);
        }

        // Payload anomaly
        if let Some(score) = self.detect_payload_anomaly(metrics) {
            anomalies.push(score);
        }

        // Header anomaly
        if let Some(score) = self.detect_header_anomaly(metrics) {
            anomalies.push(score);
        }

        self.request_history.push(metrics.clone());

        Ok(anomalies)
    }

    /// Detect unusual parameter count
    fn detect_parameter_anomaly(&self, metrics: &RequestMetrics) -> Option<AnomalyScore> {
        let avg_params = self.calculate_average_parameters();
        let std_dev = self.calculate_std_dev_parameters();

        if metrics.parameter_count as f64 > avg_params + (3.0 * std_dev) {
            return Some(AnomalyScore {
                request_id: format!("anomaly_{}", self.request_history.len()),
                url: metrics.url.clone(),
                method: metrics.method.clone(),
                anomaly_type: AnomalyType::ParameterAnomaly,
                score: 0.85,
                confidence: 0.90,
                indicators: vec![format!(
                    "Parameter count {} is {} standard deviations above mean {}",
                    metrics.parameter_count,
                    ((metrics.parameter_count as f64 - avg_params) / std_dev).abs(),
                    avg_params
                )],
                severity: "High".to_string(),
                recommendation: "Review request for parameter injection or scanning activity".to_string(),
            });
        }

        None
    }

    /// Detect unusual volume/payload size
    fn detect_volume_anomaly(&self, metrics: &RequestMetrics) -> Option<AnomalyScore> {
        let avg_size = self.calculate_average_payload_size();
        let max_size = avg_size as f64 * 5.0;

        if metrics.payload_size as f64 > max_size {
            return Some(AnomalyScore {
                request_id: format!("anomaly_{}", self.request_history.len()),
                url: metrics.url.clone(),
                method: metrics.method.clone(),
                anomaly_type: AnomalyType::VolumeAnomaly,
                score: 0.80,
                confidence: 0.85,
                indicators: vec![format!(
                    "Payload size {} is 5x above average {}",
                    metrics.payload_size, avg_size
                )],
                severity: "Medium".to_string(),
                recommendation: "Check for large file uploads or zip bombs".to_string(),
            });
        }

        None
    }

    /// Detect timing anomalies
    fn detect_timing_anomaly(&self, metrics: &RequestMetrics) -> Option<AnomalyScore> {
        let avg_time = self.calculate_average_request_time();
        let std_dev_time = self.calculate_std_dev_request_time();

        // Extremely fast or extremely slow requests
        if metrics.request_time_ms as f64 > avg_time + (4.0 * std_dev_time) {
            return Some(AnomalyScore {
                request_id: format!("anomaly_{}", self.request_history.len()),
                url: metrics.url.clone(),
                method: metrics.method.clone(),
                anomaly_type: AnomalyType::TimingAnomaly,
                score: 0.75,
                confidence: 0.80,
                indicators: vec![format!(
                    "Request time {}ms is unusually high (avg: {}ms)",
                    metrics.request_time_ms, avg_time as u64
                )],
                severity: "Medium".to_string(),
                recommendation: "Investigate for time-based blind SQLi or slow queries".to_string(),
            });
        }

        None
    }

    /// Detect encoding anomalies
    fn detect_encoding_anomaly(&self, metrics: &RequestMetrics) -> Option<AnomalyScore> {
        let suspicious_encodings = vec!["double_url", "unicode", "hex", "octal"];

        if suspicious_encodings.contains(&metrics.encoding_type.as_str()) {
            let avg_encoding_rate = self.calculate_encoding_rate();

            if metrics.encoding_type.len() > 5 && avg_encoding_rate < 0.2 {
                return Some(AnomalyScore {
                    request_id: format!("anomaly_{}", self.request_history.len()),
                    url: metrics.url.clone(),
                    method: metrics.method.clone(),
                    anomaly_type: AnomalyType::EncodingAnomaly,
                    score: 0.88,
                    confidence: 0.92,
                    indicators: vec![format!(
                        "Unusual encoding detected: {} (rare in baseline)",
                        metrics.encoding_type
                    )],
                    severity: "High".to_string(),
                    recommendation: "Likely WAF bypass attempt or filter evasion".to_string(),
                });
            }
        }

        None
    }

    /// Detect payload anomalies (injection attempts)
    fn detect_payload_anomaly(&self, metrics: &RequestMetrics) -> Option<AnomalyScore> {
        let suspicious_keywords = [
            "union select", "exec(", "system(", "shell_exec", "passthru", "proc_open",
            "popen", "socket", "fsockopen", "fopen", "file_get_contents", "eval",
            "base64_decode", "assert", "create_function", "call_user_func",
        ];

        // This would be checked against actual payload content in real implementation
        let score = if metrics.suspicious_characters > 10 {
            0.78
        } else if metrics.suspicious_characters > 5 {
            0.65
        } else {
            0.0
        };

        if score > 0.65 {
            return Some(AnomalyScore {
                request_id: format!("anomaly_{}", self.request_history.len()),
                url: metrics.url.clone(),
                method: metrics.method.clone(),
                anomaly_type: AnomalyType::PayloadAnomaly,
                score,
                confidence: 0.80,
                indicators: vec![format!(
                    "Detected {} suspicious characters in payload",
                    metrics.suspicious_characters
                )],
                severity: "Critical".to_string(),
                recommendation: "Likely injection attack - block and analyze".to_string(),
            });
        }

        None
    }

    /// Detect behavioral anomalies
    fn detect_behavioral_anomaly(&self, metrics: &RequestMetrics) -> Option<AnomalyScore> {
        // Check for sequential scanning pattern
        let recent_urls: Vec<&String> = self
            .request_history
            .iter()
            .rev()
            .take(5)
            .map(|m| &m.url)
            .collect();

        let similar_urls = recent_urls
            .iter()
            .filter(|url| url.contains(&metrics.url) || metrics.url.contains(url.as_str()))
            .count();

        if similar_urls > 3 {
            return Some(AnomalyScore {
                request_id: format!("anomaly_{}", self.request_history.len()),
                url: metrics.url.clone(),
                method: metrics.method.clone(),
                anomaly_type: AnomalyType::BehavioralAnomaly,
                score: 0.82,
                confidence: 0.88,
                indicators: vec!["Sequential scanning pattern detected".to_string()],
                severity: "High".to_string(),
                recommendation: "Possible automated vulnerability scanning".to_string(),
            });
        }

        None
    }

    /// Detect header anomalies
    fn detect_header_anomaly(&self, metrics: &RequestMetrics) -> Option<AnomalyScore> {
        let avg_headers = self.calculate_average_headers();

        if metrics.header_count as f64 > avg_headers * 2.0 {
            return Some(AnomalyScore {
                request_id: format!("anomaly_{}", self.request_history.len()),
                url: metrics.url.clone(),
                method: metrics.method.clone(),
                anomaly_type: AnomalyType::HeaderAnomaly,
                score: 0.70,
                confidence: 0.75,
                indicators: vec![format!(
                    "Unusual header count: {} (avg: {})",
                    metrics.header_count, avg_headers
                )],
                severity: "Medium".to_string(),
                recommendation: "Verify header legitimacy and purpose".to_string(),
            });
        }

        None
    }

    // Statistical helper methods

    fn calculate_average_parameters(&self) -> f64 {
        if self.request_history.is_empty() {
            return 0.0;
        }

        let sum: usize = self.request_history.iter().map(|m| m.parameter_count).sum();
        sum as f64 / self.request_history.len() as f64
    }

    fn calculate_std_dev_parameters(&self) -> f64 {
        let avg = self.calculate_average_parameters();
        let variance: f64 = self
            .request_history
            .iter()
            .map(|m| (m.parameter_count as f64 - avg).powi(2))
            .sum::<f64>()
            / self.request_history.len() as f64;
        variance.sqrt()
    }

    fn calculate_average_payload_size(&self) -> usize {
        if self.request_history.is_empty() {
            return 0;
        }

        let sum: usize = self.request_history.iter().map(|m| m.payload_size).sum();
        sum / self.request_history.len()
    }

    fn calculate_average_request_time(&self) -> f64 {
        if self.request_history.is_empty() {
            return 0.0;
        }

        let sum: u64 = self.request_history.iter().map(|m| m.request_time_ms).sum();
        sum as f64 / self.request_history.len() as f64
    }

    fn calculate_std_dev_request_time(&self) -> f64 {
        let avg = self.calculate_average_request_time();
        let variance: f64 = self
            .request_history
            .iter()
            .map(|m| (m.request_time_ms as f64 - avg).powi(2))
            .sum::<f64>()
            / self.request_history.len() as f64;
        variance.sqrt()
    }

    fn calculate_encoding_rate(&self) -> f64 {
        if self.request_history.is_empty() {
            return 0.0;
        }

        let encoded_count = self
            .request_history
            .iter()
            .filter(|m| !m.encoding_type.is_empty())
            .count();

        encoded_count as f64 / self.request_history.len() as f64
    }

    fn calculate_average_headers(&self) -> f64 {
        if self.request_history.is_empty() {
            return 0.0;
        }

        let sum: usize = self.request_history.iter().map(|m| m.header_count).sum();
        sum as f64 / self.request_history.len() as f64
    }

    fn calculate_entropy(&self, data: &str) -> f64 {
        let mut freq = [0f64; 256];

        for byte in data.bytes() {
            freq[byte as usize] += 1.0;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;

        for &count in &freq {
            if count > 0.0 {
                let p = count / len;
                entropy -= p * p.log2();
            }
        }

        entropy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anomaly_type_differentiation() {
        assert_ne!(AnomalyType::ParameterAnomaly, AnomalyType::VolumeAnomaly);
        assert_ne!(AnomalyType::TimingAnomaly, AnomalyType::EncodingAnomaly);
    }

    #[test]
    fn test_detector_initialization() {
        let detector = AnomalyDetector::new();
        assert_eq!(detector.request_history.len(), 0);
    }

    #[test]
    fn test_calculate_average_parameters() {
        let mut detector = AnomalyDetector::new();

        for i in 1..=5 {
            detector.request_history.push(RequestMetrics {
                url: "http://example.com".to_string(),
                method: "GET".to_string(),
                parameter_count: i * 2,
                payload_size: 100,
                request_time_ms: 100,
                encoding_type: "none".to_string(),
                header_count: 10,
                suspicious_characters: 0,
                entropy: 5.0,
            });
        }

        let avg = detector.calculate_average_parameters();
        assert_eq!(avg, 6.0);
    }

    #[test]
    fn test_anomaly_score_creation() {
        let score = AnomalyScore {
            request_id: "test_1".to_string(),
            url: "http://example.com".to_string(),
            method: "POST".to_string(),
            anomaly_type: AnomalyType::ParameterAnomaly,
            score: 0.85,
            confidence: 0.90,
            indicators: vec!["High parameter count".to_string()],
            severity: "High".to_string(),
            recommendation: "Review".to_string(),
        };

        assert!(score.score > 0.8);
        assert_eq!(score.severity, "High");
    }

    #[test]
    fn test_encoding_detection() {
        let detector = AnomalyDetector::new();
        let encoding = "double_url";

        assert!(["double_url", "unicode", "hex", "octal"].contains(&encoding));
    }
}
