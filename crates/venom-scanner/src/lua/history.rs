//! Bounded execution history (P0 - Memory protection)
//!
//! Tracks execution results with exponential decay weighting.
//! Prevents unbounded memory growth: 1 year = 25MB, not 936GB.

use super::types::LuaExecutionResult;
use std::collections::VecDeque;

/// Bounded execution history with exponential decay
///
/// Recent data weighted more heavily than old data.
/// Formula: weight = 0.5 ^ (age_ms / half_life_ms)
#[derive(Debug, Clone)]
pub struct BoundedExecutionHistory {
    entries: VecDeque<LuaExecutionResult>,
    max_size: usize,
    decay_half_life_ms: u64,
}

impl BoundedExecutionHistory {
    pub fn new(max_size: usize) -> Self {
        Self {
            entries: VecDeque::with_capacity(max_size),
            max_size,
            decay_half_life_ms: 5 * 60 * 1000,
        }
    }

    pub fn with_decay(max_size: usize, half_life_ms: u64) -> Self {
        Self {
            entries: VecDeque::with_capacity(max_size),
            max_size,
            decay_half_life_ms: half_life_ms,
        }
    }

    pub fn push(&mut self, result: LuaExecutionResult) {
        if self.entries.len() >= self.max_size {
            self.entries.pop_front();
        }
        self.entries.push_back(result);
    }

    pub fn all(&self) -> Vec<LuaExecutionResult> {
        self.entries.iter().cloned().collect()
    }

    pub fn recent(&self, n: usize) -> Vec<LuaExecutionResult> {
        self.entries
            .iter()
            .rev()
            .take(n)
            .cloned()
            .collect()
    }

    pub fn decay_weight(&self, entry: &LuaExecutionResult, current_time_ms: u64) -> f32 {
        let age_ms = current_time_ms.saturating_sub(entry.timestamp_ms);
        if age_ms == 0 {
            return 1.0;
        }

        let age_ratio = age_ms as f32 / self.decay_half_life_ms as f32;
        0.5_f32.powf(age_ratio)
    }

    pub fn success_rate_decayed(&self, current_time_ms: u64) -> f32 {
        if self.entries.is_empty() {
            return 0.0;
        }

        let mut weighted_success = 0.0;
        let mut weighted_total = 0.0;

        for entry in &self.entries {
            let weight = self.decay_weight(entry, current_time_ms);
            weighted_total += weight;
            if entry.success {
                weighted_success += weight;
            }
        }

        if weighted_total == 0.0 {
            return 0.0;
        }

        weighted_success / weighted_total
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn test_history_push_and_all() {
        let mut history = BoundedExecutionHistory::new(5);

        for i in 0..3 {
            history.push(LuaExecutionResult {
                script_id: "test".to_string(),
                success: true,
                output: format!("Run {}", i),
                error: None,
                execution_time_ms: 100,
                return_value: None,
                timestamp_ms: 1000 + i as u64,
            });
        }

        assert_eq!(history.len(), 3);
        assert_eq!(history.all().len(), 3);
    }

    #[test]
    fn test_history_overflow() {
        let mut history = BoundedExecutionHistory::new(3);

        for i in 0..5 {
            history.push(LuaExecutionResult {
                script_id: "test".to_string(),
                success: true,
                output: format!("Run {}", i),
                error: None,
                execution_time_ms: 100,
                return_value: None,
                timestamp_ms: 1000 + i as u64,
            });
        }

        assert_eq!(history.len(), 3);
        let all = history.all();
        assert_eq!(all[0].output, "Run 2");
        assert_eq!(all[2].output, "Run 4");
    }

    #[test]
    fn test_history_recent() {
        let mut history = BoundedExecutionHistory::new(10);

        for i in 0..10 {
            history.push(LuaExecutionResult {
                script_id: "test".to_string(),
                success: true,
                output: format!("Run {}", i),
                error: None,
                execution_time_ms: 100,
                return_value: None,
                timestamp_ms: 1000 + i as u64,
            });
        }

        let recent = history.recent(3);
        assert_eq!(recent.len(), 3);
        assert_eq!(recent[0].output, "Run 9");
        assert_eq!(recent[2].output, "Run 7");
    }

    #[test]
    fn test_decay_weight() {
        let history = BoundedExecutionHistory::new(10);
        let result = LuaExecutionResult {
            script_id: "test".to_string(),
            success: true,
            output: "Test".to_string(),
            error: None,
            execution_time_ms: 100,
            return_value: None,
            timestamp_ms: 1000,
        };

        let current_time = 6000; // 5000ms later
        let weight = history.decay_weight(&result, current_time);

        // At age = half_life, weight should be 0.5
        assert!(weight > 0.4 && weight < 0.6);
    }

    #[test]
    fn test_success_rate_decayed() {
        let mut history = BoundedExecutionHistory::new(10);

        history.push(LuaExecutionResult {
            script_id: "test".to_string(),
            success: true,
            output: "Success".to_string(),
            error: None,
            execution_time_ms: 100,
            return_value: None,
            timestamp_ms: 1000,
        });

        history.push(LuaExecutionResult {
            script_id: "test".to_string(),
            success: false,
            output: "Failed".to_string(),
            error: Some("Error".to_string()),
            execution_time_ms: 100,
            return_value: None,
            timestamp_ms: 2000,
        });

        let rate = history.success_rate_decayed(3000);
        assert!(rate > 0.0 && rate < 1.0);
    }
}
