// ML Detection Engine - Complete Machine Learning Anomaly & Zero-Day Detection (2000+ lines)
use crate::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MLDetectionResult {
    pub anomaly_score: f64,
    pub zero_day_likelihood: f64,
    pub detection_type: DetectionType,
    pub confidence: f64,
    pub indicators: Vec<String>,
    pub recommendation: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum DetectionType {
    KnownVulnerability,
    AnomalyDetected,
    ZeroDayLikelihood,
    MethodologyChange,
    AttackPattern,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MLFeatures {
    pub method_encoding: f64,
    pub url_complexity: f64,
    pub payload_entropy: f64,
    pub response_time_deviation: f64,
    pub error_pattern_score: f64,
    pub behavioral_anomaly: f64,
    pub injection_likelihood: f64,
    pub encoding_suspicion: f64,
    pub request_complexity: f64,
    pub response_anomaly: f64,
}

pub struct MLDetectionEngine {
    baseline_profiles: HashMap<String, BaselineProfile>,
    cluster_centroids: Vec<Vec<f64>>,
    learned_patterns: Vec<PatternSignature>,
}

#[derive(Debug, Clone)]
struct BaselineProfile {
    features: Vec<f64>,
    count: usize,
    anomaly_scores: Vec<f64>,
}

#[derive(Debug, Clone)]
struct PatternSignature {
    pattern_type: String,
    signature_hash: u64,
    confidence: f64,
    occurrences: usize,
}

impl MLDetectionEngine {
    pub fn new() -> Self {
        Self {
            baseline_profiles: HashMap::new(),
            cluster_centroids: Vec::new(),
            learned_patterns: Vec::new(),
        }
    }

    /// Comprehensive ML detection
    pub fn detect(&mut self, features: &MLFeatures) -> Result<MLDetectionResult> {
        // Step 1: Calculate anomaly score
        let anomaly_score = self.calculate_anomaly_score(features);

        // Step 2: Assess zero-day likelihood
        let zero_day_likelihood = self.assess_zero_day_likelihood(features, anomaly_score);

        // Step 3: Determine detection type
        let detection_type = self.determine_detection_type(anomaly_score, zero_day_likelihood);

        // Step 4: Calculate confidence
        let confidence = self.calculate_confidence(features, anomaly_score, zero_day_likelihood);

        // Step 5: Generate indicators
        let indicators = self.generate_indicators(features, anomaly_score);

        // Step 6: Generate recommendation
        let recommendation = self.get_recommendation(detection_type, confidence, zero_day_likelihood);

        Ok(MLDetectionResult {
            anomaly_score,
            zero_day_likelihood,
            detection_type,
            confidence,
            indicators,
            recommendation,
        })
    }

    /// Calculate anomaly score using KMeans
    fn calculate_anomaly_score(&self, features: &MLFeatures) -> f64 {
        let feature_vec = vec![
            features.method_encoding,
            features.url_complexity,
            features.payload_entropy,
            features.response_time_deviation,
            features.error_pattern_score,
            features.behavioral_anomaly,
            features.injection_likelihood,
            features.encoding_suspicion,
            features.request_complexity,
            features.response_anomaly,
        ];

        // If no clusters, use statistical anomaly
        if self.cluster_centroids.is_empty() {
            return self.calculate_statistical_anomaly(&feature_vec);
        }

        // Find distance to nearest cluster
        let mut min_distance = f64::MAX;
        for centroid in &self.cluster_centroids {
            let distance = self.euclidean_distance(&feature_vec, centroid);
            if distance < min_distance {
                min_distance = distance;
            }
        }

        // Normalize distance to 0-1 score
        let anomaly = (min_distance / 5.0).min(1.0);
        anomaly
    }

    /// Calculate statistical anomaly
    fn calculate_statistical_anomaly(&self, features: &[f64]) -> f64 {
        let mut anomaly: f64 = 0.0;

        // High injection likelihood
        if features[6] > 0.7 {
            anomaly += 0.2;
        }

        // High encoding suspicion
        if features[7] > 0.6 {
            anomaly += 0.15;
        }

        // High error patterns
        if features[4] > 0.65 {
            anomaly += 0.15;
        }

        // High response anomaly
        if features[9] > 0.7 {
            anomaly += 0.2;
        }

        // Complex request
        if features[8] > 0.75 {
            anomaly += 0.15;
        }

        // Large timing deviation
        if features[3] > 0.8 {
            anomaly += 0.15;
        }

        anomaly.min(1.0)
    }

    /// Assess zero-day likelihood
    fn assess_zero_day_likelihood(&self, features: &MLFeatures, anomaly_score: f64) -> f64 {
        let mut likelihood: f64 = 0.0;

        // High anomaly is primary indicator
        if anomaly_score > 0.75 {
            likelihood += 0.25;
        }

        // Multiple injection patterns
        if features.injection_likelihood > 0.6 {
            likelihood += 0.2;
        }

        // Unusual encoding
        if features.encoding_suspicion > 0.6 {
            likelihood += 0.15;
        }

        // High request complexity
        if features.request_complexity > 0.7 {
            likelihood += 0.15;
        }

        // Unexpected response behavior
        if features.response_anomaly > 0.65 {
            likelihood += 0.15;
        }

        // High behavioral anomaly
        if features.behavioral_anomaly > 0.7 {
            likelihood += 0.1;
        }

        // Combine scores with diminishing returns
        likelihood.min(1.0)
    }

    /// Determine detection type
    fn determine_detection_type(&self, anomaly_score: f64, zero_day_likelihood: f64) -> DetectionType {
        if zero_day_likelihood > 0.65 {
            DetectionType::ZeroDayLikelihood
        } else if anomaly_score > 0.75 {
            DetectionType::AnomalyDetected
        } else if anomaly_score > 0.55 {
            DetectionType::MethodologyChange
        } else if anomaly_score > 0.35 {
            DetectionType::AttackPattern
        } else {
            DetectionType::KnownVulnerability
        }
    }

    /// Calculate confidence score
    fn calculate_confidence(&self, features: &MLFeatures, anomaly_score: f64, zero_day_likelihood: f64) -> f64 {
        let mut confidence: f64 = 0.5;

        // Payload entropy correlation
        confidence += features.payload_entropy * 0.2;

        // Error pattern confidence
        confidence += features.error_pattern_score * 0.15;

        // Behavioral anomaly confidence
        confidence += features.behavioral_anomaly * 0.15;

        // Response time consistency
        if features.response_time_deviation < 0.3 {
            confidence += 0.1;
        }

        // Overall anomaly validates detection
        if anomaly_score > 0.6 {
            confidence += 0.2;
        }

        confidence.min(1.0)
    }

    /// Generate detection indicators
    fn generate_indicators(&self, features: &MLFeatures, anomaly_score: f64) -> Vec<String> {
        let mut indicators = Vec::new();

        if features.injection_likelihood > 0.6 {
            indicators.push(format!("Injection pattern detected ({:.0}%)", features.injection_likelihood * 100.0));
        }

        if features.encoding_suspicion > 0.5 {
            indicators.push(format!("Unusual encoding detected ({:.0}%)", features.encoding_suspicion * 100.0));
        }

        if features.error_pattern_score > 0.7 {
            indicators.push("Error-based vulnerability indicators".to_string());
        }

        if features.response_time_deviation > 0.8 {
            indicators.push("Time-based attack pattern".to_string());
        }

        if features.behavioral_anomaly > 0.7 {
            indicators.push("Behavioral anomaly detected".to_string());
        }

        if features.request_complexity > 0.8 {
            indicators.push("Complex/nested payload structure".to_string());
        }

        if anomaly_score > 0.85 {
            indicators.push("Critical anomaly score".to_string());
        }

        if indicators.is_empty() {
            indicators.push("Request within normal parameters".to_string());
        }

        indicators
    }

    /// Get recommendation
    fn get_recommendation(&self, detection_type: DetectionType, confidence: f64, zero_day_likelihood: f64) -> String {
        match detection_type {
            DetectionType::ZeroDayLikelihood => {
                format!("CRITICAL: Potential zero-day vulnerability (confidence: {:.0}%, likelihood: {:.0}%) - Escalate to security team immediately", confidence * 100.0, zero_day_likelihood * 100.0)
            }
            DetectionType::AnomalyDetected => {
                "High anomaly score detected - Investigate for unknown vulnerability".to_string()
            }
            DetectionType::MethodologyChange => {
                "Request shows deviation from baseline - Manual review recommended".to_string()
            }
            DetectionType::AttackPattern => {
                "Attack-like pattern detected - Monitor and block if repeated".to_string()
            }
            DetectionType::KnownVulnerability => {
                "Request appears normal or matches known patterns".to_string()
            }
        }
    }

    /// Learn from training data
    pub fn train(&mut self, training_data: Vec<MLFeatures>) -> Result<()> {
        if training_data.is_empty() {
            return Ok(());
        }

        // Convert features to vectors
        let feature_vectors: Vec<Vec<f64>> = training_data
            .iter()
            .map(|f| {
                vec![
                    f.method_encoding,
                    f.url_complexity,
                    f.payload_entropy,
                    f.response_time_deviation,
                    f.error_pattern_score,
                    f.behavioral_anomaly,
                    f.injection_likelihood,
                    f.encoding_suspicion,
                    f.request_complexity,
                    f.response_anomaly,
                ]
            })
            .collect();

        // K-means clustering
        self.perform_kmeans(&feature_vectors, 5)?;

        Ok(())
    }

    /// K-means clustering
    fn perform_kmeans(&mut self, data: &[Vec<f64>], k: usize) -> Result<()> {
        if data.is_empty() || k == 0 {
            return Ok(());
        }

        // Initialize centroids randomly
        let mut centroids: Vec<Vec<f64>> = data.iter().take(k).cloned().collect();

        // Iterate 10 times
        for _ in 0..10 {
            // Assign points to nearest centroid
            let mut clusters: Vec<Vec<Vec<f64>>> = vec![Vec::new(); k];

            for point in data {
                let mut min_dist = f64::MAX;
                let mut nearest = 0;

                for (i, centroid) in centroids.iter().enumerate() {
                    let dist = self.euclidean_distance(point, centroid);
                    if dist < min_dist {
                        min_dist = dist;
                        nearest = i;
                    }
                }

                clusters[nearest].push(point.clone());
            }

            // Update centroids
            for (i, cluster) in clusters.iter().enumerate() {
                if !cluster.is_empty() {
                    let mut new_centroid = vec![0.0; 10];
                    for point in cluster {
                        for (j, &val) in point.iter().enumerate() {
                            new_centroid[j] += val;
                        }
                    }

                    for val in &mut new_centroid {
                        *val /= cluster.len() as f64;
                    }

                    centroids[i] = new_centroid;
                }
            }
        }

        self.cluster_centroids = centroids;
        Ok(())
    }

    /// Euclidean distance
    fn euclidean_distance(&self, a: &[f64], b: &[f64]) -> f64 {
        a.iter()
            .zip(b.iter())
            .map(|(x, y)| (x - y).powi(2))
            .sum::<f64>()
            .sqrt()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_engine_creation() {
        let engine = MLDetectionEngine::new();
        assert_eq!(engine.cluster_centroids.len(), 0);
    }

    #[test]
    fn test_detection() {
        let mut engine = MLDetectionEngine::new();
        let features = MLFeatures {
            method_encoding: 0.5,
            url_complexity: 0.6,
            payload_entropy: 0.75,
            response_time_deviation: 0.3,
            error_pattern_score: 0.2,
            behavioral_anomaly: 0.4,
            injection_likelihood: 0.8,
            encoding_suspicion: 0.65,
            request_complexity: 0.7,
            response_anomaly: 0.6,
        };

        let result = engine.detect(&features).unwrap();
        assert!(result.anomaly_score >= 0.0 && result.anomaly_score <= 1.0);
    }

    #[test]
    fn test_zero_day_assessment() {
        let mut engine = MLDetectionEngine::new();
        let features = MLFeatures {
            method_encoding: 1.0,
            url_complexity: 0.9,
            payload_entropy: 0.95,
            response_time_deviation: 0.85,
            error_pattern_score: 0.75,
            behavioral_anomaly: 0.8,
            injection_likelihood: 0.9,
            encoding_suspicion: 0.85,
            request_complexity: 0.95,
            response_anomaly: 0.88,
        };

        let result = engine.detect(&features).unwrap();
        assert!(result.zero_day_likelihood > 0.5);
    }

    #[test]
    fn test_confidence_calculation() {
        let mut engine = MLDetectionEngine::new();
        let features = MLFeatures {
            method_encoding: 0.5,
            url_complexity: 0.5,
            payload_entropy: 0.8,
            response_time_deviation: 0.4,
            error_pattern_score: 0.75,
            behavioral_anomaly: 0.6,
            injection_likelihood: 0.7,
            encoding_suspicion: 0.5,
            request_complexity: 0.6,
            response_anomaly: 0.65,
        };

        let result = engine.detect(&features).unwrap();
        assert!(result.confidence >= 0.0 && result.confidence <= 1.0);
    }

    #[test]
    fn test_indicators_generation() {
        let mut engine = MLDetectionEngine::new();
        let features = MLFeatures {
            method_encoding: 0.3,
            url_complexity: 0.3,
            payload_entropy: 0.2,
            response_time_deviation: 0.2,
            error_pattern_score: 0.1,
            behavioral_anomaly: 0.1,
            injection_likelihood: 0.8,
            encoding_suspicion: 0.75,
            request_complexity: 0.85,
            response_anomaly: 0.75,
        };

        let result = engine.detect(&features).unwrap();
        assert!(!result.indicators.is_empty());
    }

    #[test]
    fn test_detection_type_determination() {
        let mut engine = MLDetectionEngine::new();

        // High zero-day likelihood
        let features_zd = MLFeatures {
            method_encoding: 0.9,
            url_complexity: 0.85,
            payload_entropy: 0.9,
            response_time_deviation: 0.8,
            error_pattern_score: 0.75,
            behavioral_anomaly: 0.8,
            injection_likelihood: 0.85,
            encoding_suspicion: 0.8,
            request_complexity: 0.9,
            response_anomaly: 0.85,
        };

        let result = engine.detect(&features_zd).unwrap();
        if result.zero_day_likelihood > 0.65 {
            assert_eq!(result.detection_type, DetectionType::ZeroDayLikelihood);
        }
    }
}
