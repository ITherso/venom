use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationReport {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub module: String,
    pub issues: Vec<OptimizationIssue>,
    pub recommendations: Vec<Recommendation>,
    pub current_score: f32,
    pub potential_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationIssue {
    pub id: String,
    pub severity: IssueSeverity,
    pub title: String,
    pub description: String,
    pub impact: String,
    pub metric: String,
    pub current_value: f64,
    pub baseline_value: f64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum IssueSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub id: String,
    pub issue_id: String,
    pub title: String,
    pub description: String,
    pub estimated_improvement_percent: f32,
    pub implementation_effort: EffortLevel,
    pub priority: i32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum EffortLevel {
    Easy,
    Medium,
    Hard,
    Expert,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceOptimizer {
    pub id: String,
    pub name: String,
    pub baseline_metrics: HashMap<String, f64>,
    pub current_metrics: HashMap<String, f64>,
    pub optimizations_applied: Vec<String>,
    pub improvements: Vec<Improvement>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Improvement {
    pub optimization: String,
    pub before_value: f64,
    pub after_value: f64,
    pub improvement_percent: f32,
    pub applied_at: DateTime<Utc>,
}

impl PerformanceOptimizer {
    pub fn new(name: String) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            baseline_metrics: HashMap::new(),
            current_metrics: HashMap::new(),
            optimizations_applied: Vec::new(),
            improvements: Vec::new(),
        }
    }

    pub fn set_baseline(&mut self, metric: String, value: f64) {
        self.baseline_metrics.insert(metric.clone(), value);
        self.current_metrics.insert(metric, value);
    }

    pub fn update_metric(&mut self, metric: String, value: f64) {
        self.current_metrics.insert(metric, value);
    }

    pub fn apply_optimization(&mut self, optimization_name: String, metric: String, new_value: f64) -> bool {
        if let Some(baseline) = self.baseline_metrics.get(&metric) {
            if let Some(current) = self.current_metrics.get(&metric) {
                let improvement_percent = ((baseline - new_value) / baseline * 100.0) as f32;

                self.improvements.push(Improvement {
                    optimization: optimization_name.clone(),
                    before_value: *current,
                    after_value: new_value,
                    improvement_percent,
                    applied_at: Utc::now(),
                });

                self.optimizations_applied.push(optimization_name);
                self.current_metrics.insert(metric, new_value);
                true
            } else {
                false
            }
        } else {
            false
        }
    }

    pub fn generate_report(&self) -> OptimizationReport {
        let issues = self.detect_issues();
        let recommendations = self.generate_recommendations();

        let current_score = self.calculate_score();
        let potential_score = current_score + (recommendations.iter().map(|r| r.estimated_improvement_percent).sum::<f32>());

        OptimizationReport {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            module: self.name.clone(),
            issues,
            recommendations,
            current_score,
            potential_score,
        }
    }

    fn detect_issues(&self) -> Vec<OptimizationIssue> {
        let mut issues = Vec::new();

        for (metric, current) in &self.current_metrics {
            if let Some(baseline) = self.baseline_metrics.get(metric) {
                let deviation = ((current - baseline) / baseline).abs();

                if deviation > 0.2 {
                    let severity = if deviation > 0.5 {
                        IssueSeverity::Critical
                    } else if deviation > 0.3 {
                        IssueSeverity::High
                    } else {
                        IssueSeverity::Medium
                    };

                    issues.push(OptimizationIssue {
                        id: uuid::Uuid::new_v4().to_string(),
                        severity,
                        title: format!("{} degradation detected", metric),
                        description: format!("{} deviated from baseline by {:.1}%", metric, deviation * 100.0),
                        impact: "Performance impact".to_string(),
                        metric: metric.clone(),
                        current_value: *current,
                        baseline_value: *baseline,
                    });
                }
            }
        }

        issues
    }

    fn generate_recommendations(&self) -> Vec<Recommendation> {
        let issues = self.detect_issues();
        let mut recommendations = Vec::new();
        let mut priority = 1;

        for issue in issues {
            let estimated_improvement = match issue.severity {
                IssueSeverity::Critical => 25.0,
                IssueSeverity::High => 15.0,
                IssueSeverity::Medium => 10.0,
                IssueSeverity::Low => 5.0,
            };

            recommendations.push(Recommendation {
                id: uuid::Uuid::new_v4().to_string(),
                issue_id: issue.id,
                title: format!("Optimize {}", issue.metric),
                description: format!("Apply optimizations to improve {}", issue.metric),
                estimated_improvement_percent: estimated_improvement,
                implementation_effort: EffortLevel::Medium,
                priority,
            });

            priority += 1;
        }

        recommendations
    }

    fn calculate_score(&self) -> f32 {
        let mut score = 100.0;

        for (metric, current) in &self.current_metrics {
            if let Some(baseline) = self.baseline_metrics.get(metric) {
                let deviation = ((current - baseline) / baseline).abs();
                score -= deviation as f32 * 20.0;
            }
        }

        score.max(0.0)
    }

    pub fn get_improvement_summary(&self) -> ImprovementSummary {
        let total_improvements = self.improvements.len();
        let total_improvement_percent: f32 = self.improvements.iter().map(|i| i.improvement_percent).sum();
        let average_improvement = if total_improvements > 0 {
            total_improvement_percent / total_improvements as f32
        } else {
            0.0
        };

        ImprovementSummary {
            total_optimizations: self.optimizations_applied.len(),
            total_improvements,
            average_improvement_percent: average_improvement,
            optimizations_list: self.optimizations_applied.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImprovementSummary {
    pub total_optimizations: usize,
    pub total_improvements: usize,
    pub average_improvement_percent: f32,
    pub optimizations_list: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_optimizer_creation() {
        let optimizer = PerformanceOptimizer::new("test".to_string());
        assert_eq!(optimizer.optimizations_applied.len(), 0);
    }

    #[test]
    fn test_set_baseline() {
        let mut optimizer = PerformanceOptimizer::new("test".to_string());
        optimizer.set_baseline("latency_ms".to_string(), 50.0);
        assert_eq!(optimizer.baseline_metrics.get("latency_ms"), Some(&50.0));
    }

    #[test]
    fn test_apply_optimization() {
        let mut optimizer = PerformanceOptimizer::new("test".to_string());
        optimizer.set_baseline("latency_ms".to_string(), 50.0);
        let success = optimizer.apply_optimization("cache".to_string(), "latency_ms".to_string(), 30.0);
        assert!(success);
        assert_eq!(optimizer.optimizations_applied.len(), 1);
    }

    #[test]
    fn test_generate_report() {
        let mut optimizer = PerformanceOptimizer::new("test".to_string());
        optimizer.set_baseline("latency_ms".to_string(), 50.0);
        optimizer.update_metric("latency_ms".to_string(), 150.0);
        let report = optimizer.generate_report();
        assert!(!report.issues.is_empty());
    }
}
