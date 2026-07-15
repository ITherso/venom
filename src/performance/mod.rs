pub mod benchmarking;
pub mod profiling;
pub mod optimization;
pub mod caching;

pub use benchmarking::{Benchmark, BenchmarkResult, BenchmarkSuite};
pub use profiling::{Profiler, ProfilingData, MemoryProfile};
pub use optimization::{PerformanceOptimizer, OptimizationReport};
pub use caching::{CacheStrategy, CacheMetrics};

#[derive(Debug, Clone)]
pub struct PerformanceConfig {
    pub enable_profiling: bool,
    pub enable_benchmarking: bool,
    pub cache_strategy: CacheStrategy,
    pub memory_limit_mb: u32,
    pub thread_pool_size: usize,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            enable_profiling: true,
            enable_benchmarking: false,
            cache_strategy: CacheStrategy::LRU,
            memory_limit_mb: 2048,
            thread_pool_size: num_cpus::get(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PerformanceMetrics {
    pub total_requests: u64,
    pub average_latency_ms: f64,
    pub p99_latency_ms: f64,
    pub throughput_rps: f64,
    pub cache_hit_ratio: f64,
    pub memory_usage_mb: f64,
    pub cpu_usage_percent: f64,
}
