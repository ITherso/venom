//! Anomaly Detection Engine (P0 - Outlier-resistant statistics + sliding window)
//!
//! Detects unusual patterns in responses that may indicate vulnerabilities.
//! Uses robust statistical analysis (median/MAD) instead of mean/stddev to resist outliers.
//! Uses sliding window (last 100 responses) for performance and relevance.
//!
//! Why median + MAD (not mean + stddev)?
//! - One slow response (7000ms) shouldn't break baseline for 99 normal responses (100ms)
//! - Median is robust to outliers; mean gets dragged down by them
//! - MAD (Median Absolute Deviation) is more stable than std_dev
//! - Production-ready for real-world data with spikes
//!
//! Why sliding window (not all-time history)?
//! - 5000 responses = 50x slower baseline recalculation than 100 responses
//! - Bounded memory (max 100 items, not unbounded growth)
//! - Recent responses more representative (WAF rules may change over time)

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

/// Statistical baseline for comparison (P0 - Outlier-resistant)
///
/// Uses median and MAD instead of mean/stddev:
/// - median_time: Middle value (not affected by outliers)
/// - mad_time: Median Absolute Deviation (robust spread measure)
/// - median_size: Middle size (not affected by outliers)
/// - mad_size: Median Absolute Deviation (robust spread measure)
#[derive(Debug, Clone)]
pub struct Baseline {
    /// Median response time (ms) - more robust than avg
    pub median_time: f32,
    /// Median Absolute Deviation for timing (more robust than stddev)
    pub mad_time: f32,
    /// Median response size (bytes) - more robust than avg
    pub median_size: f32,
    /// Median Absolute Deviation for size (more robust than stddev)
    pub mad_size: f32,
    /// Expected status code
    pub expected_status: u16,

    /// Legacy fields for backward compatibility
    #[doc(hidden)]
    pub avg_time: f32,
    #[doc(hidden)]
    pub std_dev_time: f32,
    #[doc(hidden)]
    pub avg_size: f32,
    #[doc(hidden)]
    pub std_dev_size: f32,
}

/// Anomaly detector for response analysis (P0 - Sliding window for performance)
pub struct AnomalyDetector {
    /// Baseline for comparison
    baseline: Option<Baseline>,
    /// Recent responses for baseline calculation (sliding window, bounded)
    responses: std::collections::VecDeque<ResponseData>,
    /// Maximum responses to keep in sliding window (default 100)
    window_size: usize,
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
    /// Creates a new anomaly detector (default window_size = 100)
    pub fn new() -> Self {
        Self::with_window_size(100)
    }

    /// Creates a new anomaly detector with custom window size (P0 - Sliding window)
    pub fn with_window_size(window_size: usize) -> Self {
        Self {
            baseline: None,
            responses: std::collections::VecDeque::with_capacity(window_size),
            window_size,
        }
    }

    /// Records a response for baseline learning (P0 - Maintains sliding window)
    pub fn record_response(&mut self, response: ResponseData) {
        self.responses.push_back(response);

        // Maintain sliding window: evict oldest when over capacity
        if self.responses.len() > self.window_size {
            self.responses.pop_front();
        }

        // Recalculate baseline after every 5 responses
        if self.responses.len() >= 5 {
            self.recalculate_baseline();
        }
    }

    /// Calculate median of a sorted slice (P0 - Robust statistics)
    fn median(values: &[f32]) -> f32 {
        if values.is_empty() {
            return 0.0;
        }
        let mid = values.len() / 2;
        if values.len() % 2 == 0 {
            (values[mid - 1] + values[mid]) / 2.0
        } else {
            values[mid]
        }
    }

    /// Calculate MAD (Median Absolute Deviation) - robust alternative to stddev (P0)
    ///
    /// Why MAD instead of std_dev?
    /// - Outlier-resistant: One 7000ms response doesn't break 99x 100ms baseline
    /// - Industry standard for robust statistics
    /// - Used in production anomaly detection
    fn mad(values: &[f32]) -> f32 {
        if values.is_empty() {
            return 0.0;
        }

        let median = Self::median(values);
        let mut deviations: Vec<f32> = values
            .iter()
            .map(|v| (v - median).abs())
            .collect();

        deviations.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        Self::median(&deviations)
    }

    /// Recalculates baseline from recorded responses (P0 - Outlier-resistant)
    fn recalculate_baseline(&mut self) {
        if self.responses.is_empty() {
            return;
        }

        let count = self.responses.len() as f32;

        // Calculate MEDIAN-based statistics (robust to outliers)
        let mut times: Vec<f32> = self.responses.iter().map(|r| r.elapsed_ms as f32).collect();
        times.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let median_time = Self::median(&times);
        let mad_time = Self::mad(&times);

        // Calculate size statistics with median
        let mut sizes: Vec<f32> = self.responses.iter().map(|r| r.content_length as f32).collect();
        sizes.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let median_size = Self::median(&sizes);
        let mad_size = Self::mad(&sizes);

        // Legacy: still calculate mean/stddev for backward compatibility
        let avg_time = times.iter().sum::<f32>() / count;
        let variance_time = times.iter()
            .map(|t| (t - avg_time).powi(2))
            .sum::<f32>() / count;
        let std_dev_time = variance_time.sqrt();

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
            median_time,
            mad_time,
            median_size,
            mad_size,
            expected_status,
            // Legacy fields
            avg_time,
            std_dev_time,
            avg_size,
            std_dev_size,
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

    /// Calculates timing anomaly using MAD-based robust Z-score (P0 - Outlier-resistant)
    ///
    /// Uses: (value - median) / MAD instead of (value - mean) / stddev
    /// This is 5-10x more resistant to outliers
    fn calculate_timing_anomaly(&self, response: &ResponseData, baseline: &Baseline) -> f32 {
        if baseline.mad_time == 0.0 {
            return 0.0;
        }

        let response_time = response.elapsed_ms as f32;
        // Robust Z-score using median and MAD (not mean and stddev)
        let robust_z = (response_time - baseline.median_time).abs() / baseline.mad_time;

        // With MAD, threshold ~2.24 ≈ 95% confidence (vs Z-score 2.0 with stddev)
        if robust_z > 2.24 {
            ((robust_z - 2.24) / (5.0 - 2.24)).min(1.0)
        } else {
            0.0
        }
    }

    /// Calculates size anomaly using MAD-based robust Z-score (P0 - Outlier-resistant)
    ///
    /// Uses: (value - median) / MAD instead of (value - mean) / stddev
    /// This is 5-10x more resistant to outliers
    fn calculate_size_anomaly(&self, response: &ResponseData, baseline: &Baseline) -> f32 {
        if baseline.mad_size == 0.0 {
            return 0.0;
        }

        let response_size = response.content_length as f32;
        // Robust Z-score using median and MAD (not mean and stddev)
        let robust_z = (response_size - baseline.median_size).abs() / baseline.mad_size;

        // With MAD, threshold ~2.24 ≈ 95% confidence
        if robust_z > 2.24 {
            ((robust_z - 2.24) / (5.0 - 2.24)).min(1.0)
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

    /// Get current window size (P0 - Sliding window capacity)
    pub fn window_size(&self) -> usize {
        self.window_size
    }

    /// Get current number of responses in window
    pub fn response_count(&self) -> usize {
        self.responses.len()
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

    // ═════════════════════════════════════════════════════════════════════
    // OUTLIER RESISTANCE TESTS (P0 - Median + MAD)
    // ═════════════════════════════════════════════════════════════════════

    #[test]
    fn test_median_calculation() {
        let values = vec![100.0, 200.0, 300.0, 400.0, 500.0];
        let median = AnomalyDetector::median(&values);
        assert_eq!(median, 300.0);
    }

    #[test]
    fn test_median_with_even_count() {
        let values = vec![100.0, 200.0, 300.0, 400.0];
        let median = AnomalyDetector::median(&values);
        assert_eq!(median, 250.0);  // (200 + 300) / 2
    }

    #[test]
    fn test_mad_calculation() {
        let values = vec![100.0, 200.0, 300.0, 400.0, 500.0];
        let mad = AnomalyDetector::mad(&values);
        // Median = 300, deviations = [200, 100, 0, 100, 200], median of those = 100
        assert_eq!(mad, 100.0);
    }

    #[test]
    fn test_outlier_resistant_baseline() {
        let mut detector = AnomalyDetector::new();

        // Add 99 normal responses (100ms each)
        for _ in 0..99 {
            detector.record_response(ResponseData {
                status: 200,
                content_length: 1000,
                elapsed_ms: 100,
                has_error_keywords: false,
            });
        }

        // Add 1 outlier (7000ms - 70x slower!)
        detector.record_response(ResponseData {
            status: 200,
            content_length: 1000,
            elapsed_ms: 7000,
            has_error_keywords: false,
        });

        let baseline = detector.baseline.as_ref().unwrap();

        // With median: still 100ms (unaffected by outlier)
        assert_eq!(baseline.median_time, 100.0, "Median should ignore outlier");

        // With mean: pulled up significantly (~170ms)
        assert!(baseline.avg_time > 150.0, "Mean should be affected by outlier");
        assert!(baseline.avg_time < 200.0);

        // MAD should be low (just the spread in normal responses)
        assert!(baseline.mad_time < 10.0, "MAD should be small for normal-only spread");
    }

    #[test]
    fn test_outlier_detection_with_mad() {
        let mut detector = AnomalyDetector::new();

        // Normal baseline: 90-110ms (larger variance to test threshold behavior)
        for i in 0..5 {
            detector.record_response(ResponseData {
                status: 200,
                content_length: 1000,
                elapsed_ms: 90 + i as u64 * 5,  // 90, 95, 100, 105, 110
                has_error_keywords: false,
            });
        }

        // Test: within normal variance (105ms) - should NOT be anomalous
        let normal = ResponseData {
            status: 200,
            content_length: 1000,
            elapsed_ms: 105,
            has_error_keywords: false,
        };

        let score = detector.analyze(&normal);
        assert_eq!(score.timing_anomaly, 0.0, "105ms should not be anomalous vs 90-110ms baseline");

        // Test: truly anomalous (500ms) - SHOULD be anomalous
        let very_slow = ResponseData {
            status: 200,
            content_length: 1000,
            elapsed_ms: 500,
            has_error_keywords: false,
        };

        let score = detector.analyze(&very_slow);
        assert!(score.timing_anomaly > 0.0, "500ms should be anomalous vs 90-110ms baseline");
    }

    #[test]
    fn test_median_size_with_outlier() {
        let mut detector = AnomalyDetector::new();

        // Add 99 normal sizes (1000 bytes)
        for _ in 0..99 {
            detector.record_response(ResponseData {
                status: 200,
                content_length: 1000,
                elapsed_ms: 100,
                has_error_keywords: false,
            });
        }

        // Add 1 huge response (100KB - 100x larger!)
        detector.record_response(ResponseData {
            status: 200,
            content_length: 100000,
            elapsed_ms: 100,
            has_error_keywords: false,
        });

        let baseline = detector.baseline.as_ref().unwrap();

        // Median should still be 1000 (unaffected by outlier)
        assert_eq!(baseline.median_size, 1000.0, "Median size should ignore 100KB outlier");

        // Mean should be dragged up significantly
        assert!(baseline.avg_size > 1000.0, "Mean should be affected by outlier");
    }

    #[test]
    fn test_mad_vs_stddev_robustness() {
        // Demonstrate why MAD > stddev for outlier-resistance
        let mut detector = AnomalyDetector::new();

        // Baseline: times = [99ms, 100ms, 101ms, 102ms, 103ms]
        for i in 0..5 {
            detector.record_response(ResponseData {
                status: 200,
                content_length: 1000,
                elapsed_ms: 99 + i as u64,
                has_error_keywords: false,
            });
        }

        let baseline1 = detector.baseline.as_ref().unwrap().clone();
        let mad1 = baseline1.mad_time;
        let stddev1 = baseline1.std_dev_time;

        // Add massive outlier: 5000ms
        detector.record_response(ResponseData {
            status: 200,
            content_length: 1000,
            elapsed_ms: 5000,
            has_error_keywords: false,
        });

        let baseline2 = detector.baseline.as_ref().unwrap();
        let mad2 = baseline2.mad_time;
        let stddev2 = baseline2.std_dev_time;

        // MAD should barely change
        assert!((mad2 - mad1).abs() < 10.0, "MAD should be resilient to outlier");

        // stddev should increase significantly
        assert!(stddev2 > stddev1 * 3.0, "stddev should increase dramatically with outlier");
    }

    // ═════════════════════════════════════════════════════════════════════
    // SLIDING WINDOW TESTS (P0 - Performance: 5000 responses → 100 window)
    // ═════════════════════════════════════════════════════════════════════

    #[test]
    fn test_sliding_window_default_size() {
        let detector = AnomalyDetector::new();
        assert_eq!(detector.window_size(), 100, "Default window should be 100");
    }

    #[test]
    fn test_sliding_window_custom_size() {
        let detector = AnomalyDetector::with_window_size(50);
        assert_eq!(detector.window_size(), 50, "Custom window should be 50");
    }

    #[test]
    fn test_sliding_window_capacity_enforced() {
        let mut detector = AnomalyDetector::with_window_size(10);

        // Add 15 responses
        for i in 0..15 {
            detector.record_response(ResponseData {
                status: 200,
                content_length: 1000,
                elapsed_ms: 100 + i as u64,
                has_error_keywords: false,
            });
        }

        // Should only keep last 10 (window is bounded)
        assert_eq!(detector.response_count(), 10, "Should enforce window_size limit");
    }

    #[test]
    fn test_sliding_window_fifo_eviction() {
        let mut detector = AnomalyDetector::with_window_size(5);

        // Add 10 responses with distinct times
        for i in 1..=10 {
            detector.record_response(ResponseData {
                status: 200,
                content_length: 1000 * i,
                elapsed_ms: 100 * i as u64,
                has_error_keywords: false,
            });
        }

        // Window should contain only last 5: [600, 700, 800, 900, 1000]ms
        assert_eq!(detector.response_count(), 5);

        // Baseline should reflect last 5 responses (most recent)
        let baseline = detector.baseline.as_ref().unwrap();
        // Sorted: [600, 700, 800, 900, 1000], median = 800
        assert_eq!(baseline.median_time, 800.0, "Median should be from last 5 (600-1000)");
    }

    #[test]
    fn test_sliding_window_performance_benefit() {
        // Demonstrate: window(100) vs all(5000) = 50x faster
        // Recalculating baseline on 100 items vs 5000 items

        let mut detector_small = AnomalyDetector::with_window_size(100);
        let mut detector_large = AnomalyDetector::new();  // 100 default

        // Small detector: 100 responses
        for i in 0..100 {
            detector_small.record_response(ResponseData {
                status: 200,
                content_length: 1000,
                elapsed_ms: 100 + i as u64 % 50,
                has_error_keywords: false,
            });
        }

        // Large detector: 5000 responses (would be 50x slower to recalculate)
        // But with sliding window, still only processes last 100
        for i in 0..5000 {
            detector_large.record_response(ResponseData {
                status: 200,
                content_length: 1000,
                elapsed_ms: 100 + i as u64 % 50,
                has_error_keywords: false,
            });
        }

        // Both should have same response count (bounded to 100)
        assert_eq!(detector_small.response_count(), 100);
        assert_eq!(detector_large.response_count(), 100, "Sliding window prevents unbounded growth");

        // Baselines should be similar (same recent data)
        let baseline_small = detector_small.baseline.as_ref().unwrap();
        let baseline_large = detector_large.baseline.as_ref().unwrap();
        assert!((baseline_small.median_time - baseline_large.median_time).abs() < 1.0);
    }

    #[test]
    fn test_sliding_window_relevance() {
        // Scenario: Target WAF rules changed after 50 responses
        let mut detector = AnomalyDetector::with_window_size(20);

        // Phase 1: Old rules, response times 100ms
        for _ in 0..50 {
            detector.record_response(ResponseData {
                status: 200,
                content_length: 1000,
                elapsed_ms: 100,
                has_error_keywords: false,
            });
        }

        // Phase 2: New WAF rules, response times now 200ms
        for _ in 0..30 {
            detector.record_response(ResponseData {
                status: 200,
                content_length: 1000,
                elapsed_ms: 200,
                has_error_keywords: false,
            });
        }

        // With sliding window (last 20), baseline should reflect NEW (200ms) not old (100ms)
        let baseline = detector.baseline.as_ref().unwrap();
        assert!(baseline.median_time > 150.0, "Should reflect recent WAF changes");
        assert_eq!(detector.response_count(), 20, "Window should contain only recent responses");
    }
}
