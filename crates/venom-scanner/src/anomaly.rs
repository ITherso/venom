//! Anomaly Detection Engine
//!
//! Detects unusual patterns in responses that may indicate vulnerabilities.
//! Uses statistical analysis to identify deviations from normal behavior.

/// Anomaly score components
#[derive(Debug, Clone)]
pub struct AnomalyScore {
    /// Timing anomaly (0.0 - 1.0)
    pub timing_anomaly: f32,
    /// Size anomaly (0.0 - 1.0)
    pub size_anomaly: f32,
    /// Error keyword anomaly (0.0 - 1.0)
    pub error_anomaly: f32,
    /// Status code anomaly (0.0 - 1.0)
    pub status_anomaly: f32,
    /// Combined anomaly score (0.0 - 1.0)
    pub combined_score: f32,
}

/// Statistical baseline for comparison
#[derive(Debug, Clone)]
pub struct Baseline {
    /// Average response time (ms)
    pub avg_time: f32,
    /// Standard deviation of response time
    pub std_dev_time: f32,
    /// Average response size (bytes)
    pub avg_size: f32,
    /// Standard deviation of response size
    pub std_dev_size: f32,
    /// Expected status code
    pub expected_status: u16,
}

/// Anomaly detector for response analysis
pub struct AnomalyDetector {
    /// Baseline for comparison
    baseline: Option<Baseline>,
    /// Recent responses for baseline calculation
    responses: Vec<ResponseData>,
}

/// Response data for analysis
#[derive(Debug, Clone)]
pub struct ResponseData {
    pub status: u16,
    pub content_length: usize,
    pub elapsed_ms: u64,
    pub has_error_keywords: bool,
}

impl AnomalyDetector {
    /// Creates a new anomaly detector
    pub fn new() -> Self {
        Self {
            baseline: None,
            responses: Vec::new(),
        }
    }

    /// Records a response for baseline learning
    pub fn record_response(&mut self, response: ResponseData) {
        self.responses.push(response);

        // Recalculate baseline after every 5 responses
        if self.responses.len() >= 5 {
            self.recalculate_baseline();
        }
    }

    /// Recalculates baseline from recorded responses
    fn recalculate_baseline(&mut self) {
        if self.responses.is_empty() {
            return;
        }

        let count = self.responses.len() as f32;

        // Calculate timing statistics
        let times: Vec<f32> = self.responses.iter().map(|r| r.elapsed_ms as f32).collect();
        let avg_time = times.iter().sum::<f32>() / count;
        let variance_time = times.iter()
            .map(|t| (t - avg_time).powi(2))
            .sum::<f32>() / count;
        let std_dev_time = variance_time.sqrt();

        // Calculate size statistics
        let sizes: Vec<f32> = self.responses.iter().map(|r| r.content_length as f32).collect();
        let avg_size = sizes.iter().sum::<f32>() / count;
        let variance_size = sizes.iter()
            .map(|s| (s - avg_size).powi(2))
            .sum::<f32>() / count;
        let std_dev_size = variance_size.sqrt();

        // Find most common status code
        let expected_status = self.responses.iter()
            .map(|r| r.status)
            .max_by_key(|status| {
                self.responses.iter().filter(|r| r.status == *status).count()
            })
            .unwrap_or(200);

        self.baseline = Some(Baseline {
            avg_time,
            std_dev_time,
            avg_size,
            std_dev_size,
            expected_status,
        });
    }

    /// Analyzes a response for anomalies
    pub fn analyze(&self, response: &ResponseData) -> AnomalyScore {
        let baseline = match &self.baseline {
            Some(b) => b,
            None => return AnomalyScore {
                timing_anomaly: 0.0,
                size_anomaly: 0.0,
                error_anomaly: 0.0,
                status_anomaly: 0.0,
                combined_score: 0.0,
            },
        };

        let timing_anomaly = self.calculate_timing_anomaly(response, baseline);
        let size_anomaly = self.calculate_size_anomaly(response, baseline);
        let error_anomaly = if response.has_error_keywords { 0.5 } else { 0.0 };
        let status_anomaly = if response.status != baseline.expected_status { 0.3 } else { 0.0 };

        let combined_score = (timing_anomaly * 0.3
            + size_anomaly * 0.3
            + error_anomaly * 0.2
            + status_anomaly * 0.2)
            .min(1.0);

        AnomalyScore {
            timing_anomaly,
            size_anomaly,
            error_anomaly,
            status_anomaly,
            combined_score,
        }
    }

    /// Calculates timing anomaly using Z-score
    fn calculate_timing_anomaly(&self, response: &ResponseData, baseline: &Baseline) -> f32 {
        if baseline.std_dev_time == 0.0 {
            return 0.0;
        }

        let response_time = response.elapsed_ms as f32;
        let z_score = (response_time - baseline.avg_time).abs() / baseline.std_dev_time;

        // Z-score > 2 is anomalous (95% confidence)
        if z_score > 2.0 {
            ((z_score - 2.0) / (4.0 - 2.0)).min(1.0)
        } else {
            0.0
        }
    }

    /// Calculates size anomaly using Z-score
    fn calculate_size_anomaly(&self, response: &ResponseData, baseline: &Baseline) -> f32 {
        if baseline.std_dev_size == 0.0 {
            return 0.0;
        }

        let response_size = response.content_length as f32;
        let z_score = (response_size - baseline.avg_size).abs() / baseline.std_dev_size;

        // Z-score > 2 is anomalous
        if z_score > 2.0 {
            ((z_score - 2.0) / (4.0 - 2.0)).min(1.0)
        } else {
            0.0
        }
    }

    /// Detects if response should trigger investigation
    pub fn is_anomalous(&self, response: &ResponseData, threshold: f32) -> bool {
        let score = self.analyze(response);
        score.combined_score > threshold
    }

    /// Gets severity classification of anomaly
    pub fn classify_severity(&self, response: &ResponseData) -> SeverityClass {
        let score = self.analyze(response);

        match score.combined_score {
            s if s > 0.8 => SeverityClass::Critical,
            s if s > 0.6 => SeverityClass::High,
            s if s > 0.4 => SeverityClass::Medium,
            s if s > 0.2 => SeverityClass::Low,
            _ => SeverityClass::None,
        }
    }
}

impl Default for AnomalyDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Severity classification for anomalies
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeverityClass {
    Critical,
    High,
    Medium,
    Low,
    None,
}

impl SeverityClass {
    pub fn as_str(&self) -> &str {
        match self {
            SeverityClass::Critical => "CRITICAL",
            SeverityClass::High => "HIGH",
            SeverityClass::Medium => "MEDIUM",
            SeverityClass::Low => "LOW",
            SeverityClass::None => "NONE",
        }
    }
}

/// Anomaly interpreter for generating findings
pub struct AnomalyInterpreter;

impl AnomalyInterpreter {
    /// Generates description based on anomaly score
    pub fn describe_anomaly(score: &AnomalyScore) -> String {
        let mut descriptions = Vec::new();

        if score.timing_anomaly > 0.3 {
            descriptions.push("Timing behavior differs significantly from baseline");
        }
        if score.size_anomaly > 0.3 {
            descriptions.push("Response size deviates from typical responses");
        }
        if score.error_anomaly > 0.3 {
            descriptions.push("Error keywords detected in response");
        }
        if score.status_anomaly > 0.3 {
            descriptions.push("Unexpected HTTP status code");
        }

        descriptions.join(" | ")
    }

    /// Suggests investigation type based on anomaly
    pub fn suggest_investigation(score: &AnomalyScore) -> &'static str {
        if score.timing_anomaly > 0.5 {
            "Time-based injection (SQLi, SSTI)"
        } else if score.size_anomaly > 0.5 {
            "Information disclosure or content filtering"
        } else if score.error_anomaly > 0.5 {
            "Error-based injection technique"
        } else if score.status_anomaly > 0.5 {
            "WAF or access control bypass"
        } else {
            "General behavioral anomaly"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anomaly_detector_creation() {
        let detector = AnomalyDetector::new();
        assert!(detector.baseline.is_none());
    }

    #[test]
    fn test_record_response() {
        let mut detector = AnomalyDetector::new();
        let response = ResponseData {
            status: 200,
            content_length: 1000,
            elapsed_ms: 100,
            has_error_keywords: false,
        };

        detector.record_response(response);
        assert_eq!(detector.responses.len(), 1);
    }

    #[test]
    fn test_baseline_calculation() {
        let mut detector = AnomalyDetector::new();

        for i in 0..5 {
            detector.record_response(ResponseData {
                status: 200,
                content_length: 1000 + i * 100,
                elapsed_ms: 100 + i as u64 * 10,
                has_error_keywords: false,
            });
        }

        assert!(detector.baseline.is_some());
    }

    #[test]
    fn test_timing_anomaly() {
        let mut detector = AnomalyDetector::new();

        // Establish baseline with varying times
        for i in 0..5 {
            detector.record_response(ResponseData {
                status: 200,
                content_length: 1000,
                elapsed_ms: 90 + i as u64 * 5,
                has_error_keywords: false,
            });
        }

        // Test anomalous response (much slower)
        let anomalous = ResponseData {
            status: 200,
            content_length: 1000,
            elapsed_ms: 1000,
            has_error_keywords: false,
        };

        let score = detector.analyze(&anomalous);
        assert!(score.timing_anomaly > 0.0 || score.combined_score > 0.0);
    }

    #[test]
    fn test_size_anomaly() {
        let mut detector = AnomalyDetector::new();

        for i in 0..5 {
            detector.record_response(ResponseData {
                status: 200,
                content_length: 900 + i * 100,
                elapsed_ms: 100,
                has_error_keywords: false,
            });
        }

        let anomalous = ResponseData {
            status: 200,
            content_length: 10000,
            elapsed_ms: 100,
            has_error_keywords: false,
        };

        let score = detector.analyze(&anomalous);
        assert!(score.size_anomaly > 0.0 || score.combined_score > 0.0);
    }

    #[test]
    fn test_severity_classification() {
        let detector = AnomalyDetector::new();

        let high_anomaly = ResponseData {
            status: 403,
            content_length: 1000000,
            elapsed_ms: 10000,
            has_error_keywords: true,
        };

        let severity = detector.classify_severity(&high_anomaly);
        assert_eq!(severity, SeverityClass::None); // No baseline yet
    }

    #[test]
    fn test_anomaly_description() {
        let score = AnomalyScore {
            timing_anomaly: 0.8,
            size_anomaly: 0.2,
            error_anomaly: 0.1,
            status_anomaly: 0.1,
            combined_score: 0.5,
        };

        let desc = AnomalyInterpreter::describe_anomaly(&score);
        assert!(desc.contains("Timing"));
    }

    #[test]
    fn test_investigation_suggestion() {
        let score = AnomalyScore {
            timing_anomaly: 0.7,
            size_anomaly: 0.1,
            error_anomaly: 0.1,
            status_anomaly: 0.1,
            combined_score: 0.5,
        };

        let suggestion = AnomalyInterpreter::suggest_investigation(&score);
        assert!(suggestion.contains("injection"));
    }
}
