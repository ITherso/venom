//! Confidence metrics (P1 - Explainable anomalies)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConfidenceLevel {
    VeryLow, Low, Medium, High, VeryHigh,
}
impl ConfidenceLevel {
    pub fn as_str(&self) -> &str {
        match self {
            ConfidenceLevel::VeryLow => "VeryLow",
            ConfidenceLevel::Low => "Low",
            ConfidenceLevel::Medium => "Medium",
            ConfidenceLevel::High => "High",
            ConfidenceLevel::VeryHigh => "VeryHigh",
        }
    }
}
#[derive(Debug, Clone)]
pub struct Confidence {
    pub base_score: f32,
    pub signal_count: u32,
    pub signal_agreement: f32,
    pub consistency: f32,
    pub confidence: f32,
    pub level: ConfidenceLevel,
}
impl Confidence {
    pub fn from_signals(base_score: f32, timing: f32, size: f32, error: f32, status: f32) -> Self {
        let scores = [timing, size, error, status];
        let signal_count = scores.iter().filter(|&&s| s > 0.0).count() as u32;
        if signal_count == 0 {
            return Self { base_score: 0.0, signal_count: 0, signal_agreement: 0.0, consistency: 0.0, confidence: 0.0, level: ConfidenceLevel::VeryLow };
        }
        let fired: Vec<f32> = scores.iter().copied().filter(|&s| s > 0.0).collect();
        let max_f = fired.iter().copied().fold(0.0, f32::max);
        let min_f = fired.iter().copied().fold(f32::MAX, f32::min);
        let signal_agreement = if fired.len() > 1 && max_f > 0.0 { (1.0 - (max_f - min_f) / max_f).max(0.0) } else if fired.len() == 1 { 1.0 } else { 0.0 };
        let consistency = match signal_count { 0 => 0.0, 1 => 0.4, 2 => 0.7, 3 => 0.9, _ => 1.0 };
        let confidence = (base_score * signal_agreement * consistency).min(1.0);
        let level = match confidence { c if c < 0.20 => ConfidenceLevel::VeryLow, c if c < 0.40 => ConfidenceLevel::Low, c if c < 0.65 => ConfidenceLevel::Medium, c if c < 0.80 => ConfidenceLevel::High, _ => ConfidenceLevel::VeryHigh };
        Self { base_score, signal_count, signal_agreement, consistency, confidence, level }
    }
    pub fn is_reportable(&self, threshold: f32) -> bool { self.confidence > threshold }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_single_signal() { let c = Confidence::from_signals(0.8, 0.8, 0.0, 0.0, 0.0); assert!(c.confidence < 0.5); }
    #[test]
    fn test_all_signals() { let c = Confidence::from_signals(0.8, 0.8, 0.8, 0.8, 0.8); assert!(c.confidence >= 0.8); }
}
