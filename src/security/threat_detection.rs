use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc, Duration};
use uuid::Uuid;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    pub id: String,
    pub name: String,
    pub indicator_type: IndicatorType,
    pub pattern: String,
    pub severity: f32,
    pub confidence: f32,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum IndicatorType {
    IPAddress,
    Domain,
    FileHash,
    URLPattern,
    BehavioralPattern,
    AnomalyPattern,
    MalwareSignature,
}

impl ThreatIndicator {
    pub fn new(
        name: String,
        indicator_type: IndicatorType,
        pattern: String,
        severity: f32,
        confidence: f32,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            indicator_type,
            pattern,
            severity: severity.min(100.0).max(0.0),
            confidence: confidence.min(100.0).max(0.0),
            enabled: true,
            created_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub indicator_id: String,
    pub indicator_name: String,
    pub threat_type: IndicatorType,
    pub matched_pattern: String,
    pub severity: f32,
    pub confidence: f32,
    pub target: String,
    pub source: String,
    pub action_taken: ThreatAction,
    pub details: HashMap<String, String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ThreatAction {
    Monitored,
    Logged,
    Blocked,
    Quarantined,
    Escalated,
}

impl DetectionResult {
    pub fn new(
        indicator_id: String,
        indicator_name: String,
        threat_type: IndicatorType,
        matched_pattern: String,
        severity: f32,
        confidence: f32,
        target: String,
        source: String,
    ) -> Self {
        let action = if severity > 80.0 {
            ThreatAction::Escalated
        } else if severity > 60.0 {
            ThreatAction::Blocked
        } else if severity > 40.0 {
            ThreatAction::Logged
        } else {
            ThreatAction::Monitored
        };

        Self {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            indicator_id,
            indicator_name,
            threat_type,
            matched_pattern,
            severity,
            confidence,
            target,
            source,
            action_taken: action,
            details: HashMap::new(),
        }
    }

    pub fn with_detail(mut self, key: String, value: String) -> Self {
        self.details.insert(key, value);
        self
    }

    pub fn risk_score(&self) -> f32 {
        (self.severity * self.confidence) / 100.0
    }
}

#[derive(Debug, Clone)]
pub struct ThreatDetector {
    pub id: String,
    pub name: String,
    pub indicators: HashMap<String, ThreatIndicator>,
    pub detections: Vec<DetectionResult>,
    pub ip_reputation: HashMap<String, f32>,
    pub suspicious_activity_threshold: f32,
}

impl ThreatDetector {
    pub fn new(name: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            indicators: HashMap::new(),
            detections: Vec::new(),
            ip_reputation: HashMap::new(),
            suspicious_activity_threshold: 60.0,
        }
    }

    pub fn add_indicator(&mut self, indicator: ThreatIndicator) -> String {
        let indicator_id = indicator.id.clone();
        self.indicators.insert(indicator_id.clone(), indicator);
        indicator_id
    }

    pub fn detect_threat(
        &mut self,
        indicator_id: &str,
        target: String,
        source: String,
    ) -> Option<DetectionResult> {
        if let Some(indicator) = self.indicators.get(indicator_id) {
            if !indicator.enabled {
                return None;
            }

            let result = DetectionResult::new(
                indicator_id.to_string(),
                indicator.name.clone(),
                indicator.indicator_type,
                indicator.pattern.clone(),
                indicator.severity,
                indicator.confidence,
                target,
                source,
            );

            self.detections.push(result.clone());
            Some(result)
        } else {
            None
        }
    }

    pub fn check_ip_reputation(&self, ip: &str) -> f32 {
        self.ip_reputation.get(ip).copied().unwrap_or(0.0)
    }

    pub fn update_ip_reputation(&mut self, ip: String, score: f32) {
        let clamped_score = score.min(100.0).max(0.0);
        self.ip_reputation.insert(ip, clamped_score);
    }

    pub fn get_detections_since(&self, since: DateTime<Utc>) -> Vec<&DetectionResult> {
        self.detections
            .iter()
            .filter(|d| d.timestamp > since)
            .collect()
    }

    pub fn get_high_severity_detections(&self) -> Vec<&DetectionResult> {
        self.detections
            .iter()
            .filter(|d| d.severity >= self.suspicious_activity_threshold)
            .collect()
    }

    pub fn get_detections_by_source(&self, source: &str) -> Vec<&DetectionResult> {
        self.detections
            .iter()
            .filter(|d| d.source == source)
            .collect()
    }

    pub fn get_detections_by_target(&self, target: &str) -> Vec<&DetectionResult> {
        self.detections
            .iter()
            .filter(|d| d.target == target)
            .collect()
    }

    pub fn get_statistics(&self) -> ThreatDetectionStatistics {
        let total_detections = self.detections.len();
        let high_severity = self.get_high_severity_detections().len();
        let blocked_count = self.detections.iter().filter(|d| d.action_taken == ThreatAction::Blocked).count();
        let escalated_count = self.detections.iter().filter(|d| d.action_taken == ThreatAction::Escalated).count();

        let last_24h = self.detections
            .iter()
            .filter(|d| d.timestamp > Utc::now() - Duration::hours(24))
            .count();

        ThreatDetectionStatistics {
            total_indicators: self.indicators.len(),
            enabled_indicators: self.indicators.values().filter(|i| i.enabled).count(),
            total_detections,
            high_severity_detections: high_severity,
            blocked_threats: blocked_count,
            escalated_threats: escalated_count,
            detections_last_24h: last_24h,
            tracked_ips: self.ip_reputation.len(),
        }
    }

    pub fn cleanup_old_detections(&mut self, days: i64) {
        let cutoff = Utc::now() - Duration::days(days);
        self.detections.retain(|d| d.timestamp > cutoff);
    }
}

impl Default for ThreatDetector {
    fn default() -> Self {
        Self::new("Default Detector".to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatDetectionStatistics {
    pub total_indicators: usize,
    pub enabled_indicators: usize,
    pub total_detections: usize,
    pub high_severity_detections: usize,
    pub blocked_threats: usize,
    pub escalated_threats: usize,
    pub detections_last_24h: usize,
    pub tracked_ips: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_indicator_creation() {
        let indicator = ThreatIndicator::new(
            "malicious_ip".to_string(),
            IndicatorType::IPAddress,
            "192.168.1.100".to_string(),
            85.0,
            90.0,
        );
        assert!(indicator.enabled);
    }

    #[test]
    fn test_detection_result_creation() {
        let result = DetectionResult::new(
            "ind_123".to_string(),
            "malicious_ip".to_string(),
            IndicatorType::IPAddress,
            "192.168.1.100".to_string(),
            85.0,
            90.0,
            "target_system".to_string(),
            "192.168.1.100".to_string(),
        );
        assert!(result.risk_score() > 0.0);
    }

    #[test]
    fn test_threat_detector() {
        let mut detector = ThreatDetector::new("test".to_string());
        let indicator = ThreatIndicator::new(
            "malicious_ip".to_string(),
            IndicatorType::IPAddress,
            "192.168.1.100".to_string(),
            85.0,
            90.0,
        );
        let indicator_id = indicator.id.clone();
        detector.add_indicator(indicator);

        let detection = detector.detect_threat(&indicator_id, "target".to_string(), "192.168.1.100".to_string());
        assert!(detection.is_some());
    }

    #[test]
    fn test_ip_reputation() {
        let mut detector = ThreatDetector::new("test".to_string());
        detector.update_ip_reputation("192.168.1.100".to_string(), 75.0);

        let score = detector.check_ip_reputation("192.168.1.100");
        assert_eq!(score, 75.0);
    }

    #[test]
    fn test_get_statistics() {
        let detector = ThreatDetector::new("test".to_string());
        let stats = detector.get_statistics();
        assert_eq!(stats.total_detections, 0);
    }
}
