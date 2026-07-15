use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Instant, Duration};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profiler {
    pub id: String,
    pub name: String,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub memory_samples: Vec<MemoryProfile>,
    pub cpu_samples: Vec<CPUProfile>,
    pub call_stack: Vec<String>,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryProfile {
    pub timestamp: DateTime<Utc>,
    pub heap_usage_mb: f64,
    pub stack_usage_mb: f64,
    pub rss_memory_mb: f64,
    pub allocated_mb: f64,
    pub deallocated_mb: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CPUProfile {
    pub timestamp: DateTime<Utc>,
    pub user_time_ms: f64,
    pub system_time_ms: f64,
    pub cpu_percent: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfilingData {
    pub profile_id: String,
    pub profile_name: String,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub duration_seconds: f64,
    pub peak_memory_mb: f64,
    pub average_memory_mb: f64,
    pub peak_cpu_percent: f64,
    pub average_cpu_percent: f64,
    pub allocations: u64,
    pub deallocations: u64,
    pub function_timings: HashMap<String, FunctionTiming>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionTiming {
    pub function_name: String,
    pub call_count: u64,
    pub total_time_ms: f64,
    pub average_time_ms: f64,
    pub min_time_ms: f64,
    pub max_time_ms: f64,
    pub memory_allocated_mb: f64,
}

impl Profiler {
    pub fn new(name: String) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            start_time: Utc::now(),
            end_time: None,
            memory_samples: Vec::new(),
            cpu_samples: Vec::new(),
            call_stack: Vec::new(),
            is_active: true,
        }
    }

    pub fn start(&mut self) {
        self.is_active = true;
        self.start_time = Utc::now();
    }

    pub fn stop(&mut self) {
        self.is_active = false;
        self.end_time = Some(Utc::now());
    }

    pub fn record_memory(&mut self, heap: f64, stack: f64, rss: f64) {
        self.memory_samples.push(MemoryProfile {
            timestamp: Utc::now(),
            heap_usage_mb: heap,
            stack_usage_mb: stack,
            rss_memory_mb: rss,
            allocated_mb: 0.0,
            deallocated_mb: 0.0,
        });
    }

    pub fn record_cpu(&mut self, user: f64, system: f64, percent: f64) {
        self.cpu_samples.push(CPUProfile {
            timestamp: Utc::now(),
            user_time_ms: user,
            system_time_ms: system,
            cpu_percent: percent,
        });
    }

    pub fn push_call(&mut self, function: String) {
        self.call_stack.push(function);
    }

    pub fn pop_call(&mut self) -> Option<String> {
        self.call_stack.pop()
    }

    pub fn get_data(&self) -> ProfilingData {
        let end_time = self.end_time.unwrap_or_else(Utc::now);
        let duration = (end_time - self.start_time).num_seconds() as f64;

        let (peak_memory, avg_memory) = if self.memory_samples.is_empty() {
            (0.0, 0.0)
        } else {
            let peak = self.memory_samples
                .iter()
                .map(|s| s.heap_usage_mb)
                .fold(f64::NEG_INFINITY, f64::max);
            let avg = self.memory_samples
                .iter()
                .map(|s| s.heap_usage_mb)
                .sum::<f64>() / self.memory_samples.len() as f64;
            (peak, avg)
        };

        let (peak_cpu, avg_cpu) = if self.cpu_samples.is_empty() {
            (0.0, 0.0)
        } else {
            let peak = self.cpu_samples
                .iter()
                .map(|s| s.cpu_percent)
                .fold(f64::NEG_INFINITY, f64::max);
            let avg = self.cpu_samples
                .iter()
                .map(|s| s.cpu_percent)
                .sum::<f64>() / self.cpu_samples.len() as f64;
            (peak, avg)
        };

        ProfilingData {
            profile_id: self.id.clone(),
            profile_name: self.name.clone(),
            start_time: self.start_time,
            end_time,
            duration_seconds: duration,
            peak_memory_mb: peak_memory,
            average_memory_mb: avg_memory,
            peak_cpu_percent: peak_cpu,
            average_cpu_percent: avg_cpu,
            allocations: 0,
            deallocations: 0,
            function_timings: HashMap::new(),
        }
    }
}

pub struct ScopedProfiler {
    profiler: Arc<Profiler>,
    start: Instant,
}

impl ScopedProfiler {
    pub fn new(profiler: Arc<Profiler>, function_name: String) -> Self {
        // Note: We can't mutate through Arc, so function tracking would need a Mutex wrapper
        Self {
            profiler,
            start: Instant::now(),
        }
    }
}

impl Drop for ScopedProfiler {
    fn drop(&mut self) {
        let _duration = self.start.elapsed();
        // Record timing when scope exits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profiler_creation() {
        let profiler = Profiler::new("test".to_string());
        assert!(profiler.is_active);
    }

    #[test]
    fn test_profiler_start_stop() {
        let mut profiler = Profiler::new("test".to_string());
        profiler.start();
        assert!(profiler.is_active);
        profiler.stop();
        assert!(!profiler.is_active);
        assert!(profiler.end_time.is_some());
    }

    #[test]
    fn test_profiler_memory_recording() {
        let mut profiler = Profiler::new("test".to_string());
        profiler.record_memory(512.0, 64.0, 576.0);
        assert_eq!(profiler.memory_samples.len(), 1);
    }

    #[test]
    fn test_profiler_cpu_recording() {
        let mut profiler = Profiler::new("test".to_string());
        profiler.record_cpu(100.0, 50.0, 45.5);
        assert_eq!(profiler.cpu_samples.len(), 1);
    }

    #[test]
    fn test_profiler_get_data() {
        let mut profiler = Profiler::new("test".to_string());
        profiler.record_memory(512.0, 64.0, 576.0);
        let data = profiler.get_data();
        assert_eq!(data.profile_name, "test");
    }
}
