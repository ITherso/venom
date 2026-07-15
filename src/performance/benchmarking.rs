use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::time::{Instant, Duration};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Benchmark {
    pub id: String,
    pub name: String,
    pub description: String,
    pub module: String,
    pub iterations: u32,
    pub enabled: bool,
}

impl Benchmark {
    pub fn new(name: String, module: String, iterations: u32) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            description: String::new(),
            module,
            iterations,
            enabled: true,
        }
    }

    pub fn with_description(mut self, desc: String) -> Self {
        self.description = desc;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResult {
    pub benchmark_id: String,
    pub benchmark_name: String,
    pub timestamp: DateTime<Utc>,
    pub iterations: u32,
    pub total_duration_ms: f64,
    pub average_duration_ms: f64,
    pub min_duration_ms: f64,
    pub max_duration_ms: f64,
    pub p50_duration_ms: f64,
    pub p95_duration_ms: f64,
    pub p99_duration_ms: f64,
    pub throughput_ops_per_sec: f64,
    pub allocated_memory_mb: f64,
    pub peak_memory_mb: f64,
}

impl BenchmarkResult {
    pub fn calculate_percentile(durations: &[f64], percentile: f64) -> f64 {
        if durations.is_empty() {
            return 0.0;
        }

        let index = ((percentile / 100.0) * (durations.len() - 1) as f64) as usize;
        durations[index.min(durations.len() - 1)]
    }

    pub fn is_regression(&self, baseline: &BenchmarkResult) -> bool {
        let regression_threshold = 0.1; // 10% regression
        let increase = (self.average_duration_ms - baseline.average_duration_ms) / baseline.average_duration_ms;
        increase > regression_threshold
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkSuite {
    pub id: String,
    pub name: String,
    pub benchmarks: HashMap<String, Benchmark>,
    pub results: Vec<BenchmarkResult>,
    pub created_at: DateTime<Utc>,
    pub last_run: Option<DateTime<Utc>>,
}

impl BenchmarkSuite {
    pub fn new(name: String) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            benchmarks: HashMap::new(),
            results: Vec::new(),
            created_at: Utc::now(),
            last_run: None,
        }
    }

    pub fn add_benchmark(&mut self, benchmark: Benchmark) -> String {
        let benchmark_id = benchmark.id.clone();
        self.benchmarks.insert(benchmark_id.clone(), benchmark);
        benchmark_id
    }

    pub fn record_result(&mut self, result: BenchmarkResult) {
        self.results.push(result);
        self.last_run = Some(Utc::now());
    }

    pub fn get_baseline(&self, benchmark_id: &str) -> Option<&BenchmarkResult> {
        self.results
            .iter()
            .rfind(|r| r.benchmark_id == benchmark_id)
    }

    pub fn get_results_for_benchmark(&self, benchmark_id: &str) -> Vec<&BenchmarkResult> {
        self.results
            .iter()
            .filter(|r| r.benchmark_id == benchmark_id)
            .collect()
    }

    pub fn get_statistics(&self) -> BenchmarkStatistics {
        let total_runs = self.results.len();
        let avg_throughput = if total_runs > 0 {
            self.results.iter().map(|r| r.throughput_ops_per_sec).sum::<f64>() / total_runs as f64
        } else {
            0.0
        };

        let regressions = self.results
            .windows(2)
            .filter(|w| w[1].is_regression(&w[0]))
            .count();

        BenchmarkStatistics {
            total_benchmarks: self.benchmarks.len(),
            total_runs,
            average_throughput_ops_per_sec: avg_throughput,
            regression_count: regressions,
        }
    }
}

impl Default for BenchmarkSuite {
    fn default() -> Self {
        Self::new("Default Suite".to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkStatistics {
    pub total_benchmarks: usize,
    pub total_runs: usize,
    pub average_throughput_ops_per_sec: f64,
    pub regression_count: usize,
}

pub struct BenchmarkTimer {
    start: Instant,
    durations: Vec<f64>,
}

impl BenchmarkTimer {
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
            durations: Vec::new(),
        }
    }

    pub fn start_iteration(&mut self) {
        self.start = Instant::now();
    }

    pub fn end_iteration(&mut self) {
        let elapsed = self.start.elapsed();
        self.durations.push(elapsed.as_secs_f64() * 1000.0);
    }

    pub fn get_durations(&self) -> &[f64] {
        &self.durations
    }

    pub fn get_average(&self) -> f64 {
        if self.durations.is_empty() {
            return 0.0;
        }
        self.durations.iter().sum::<f64>() / self.durations.len() as f64
    }

    pub fn get_total(&self) -> f64 {
        self.durations.iter().sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_benchmark_creation() {
        let benchmark = Benchmark::new("test".to_string(), "module".to_string(), 100);
        assert_eq!(benchmark.iterations, 100);
    }

    #[test]
    fn test_benchmark_suite_creation() {
        let suite = BenchmarkSuite::new("test_suite".to_string());
        assert_eq!(suite.benchmarks.len(), 0);
    }

    #[test]
    fn test_add_benchmark() {
        let mut suite = BenchmarkSuite::new("test_suite".to_string());
        let bench = Benchmark::new("test".to_string(), "module".to_string(), 100);
        let id = suite.add_benchmark(bench);
        assert!(!id.is_empty());
    }

    #[test]
    fn test_benchmark_timer() {
        let mut timer = BenchmarkTimer::new();
        for _ in 0..10 {
            timer.start_iteration();
            std::thread::sleep(Duration::from_millis(1));
            timer.end_iteration();
        }
        assert_eq!(timer.get_durations().len(), 10);
    }
}
