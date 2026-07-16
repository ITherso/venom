// VENOM Scanner - Professional multi-phase vulnerability scanner
//!
//! A sophisticated, multi-phase vulnerability detection and exploitation framework
//! built in Rust for maximum performance and safety.
//!
//! ## Architecture
//! - **10 Phases**: Sequential vulnerability detection across different categories
//! - **Async/Await**: Native Tokio-based concurrency for high-throughput scanning
//! - **Zero-Copy**: DashMap for efficient, lock-free inter-phase communication
//! - **Type-Safe**: Compile-time guarantees eliminate entire classes of bugs

pub mod adaptive;
pub mod advanced_detection;
pub mod anomaly;
pub mod api;
pub mod auth;
pub mod cache;
pub mod config;
pub mod context;
pub mod dashboard;
pub mod distributed;
pub mod error;
pub mod logging;
pub mod metrics;
pub mod ml;
pub mod monitoring;
pub mod phases;
pub mod plugin;
pub mod realtime;
pub mod reporting;
pub mod runner;
pub mod waf;

pub use adaptive::{AdaptiveEngine, AdaptationStrategy, DetectionPattern, PayloadMutator, ResponseMetrics};
pub use advanced_detection::{BehavioralSignature, BehaviorIndicator, IndicatorType, ComparisonOperator, WafBypassTechnique, BypassCategory, BehavioralAnalyzer, BehavioralAnalysisData, DetectionResult, WafBypassSelector, SignatureEvasionEngine, EversionRule, EversionType};
pub use anomaly::{AnomalyDetector, AnomalyScore, AnomalyInterpreter, SeverityClass, ResponseData};
pub use api::{ApiResponse, ScanStatus, ScanStatusType, StartScanRequest, ScanResultResponse, ApiEndpoints, ApiError};
pub use auth::{User, UserRole, AuthToken, UserManager, UserInfo, LoginRequest, LoginResponse};
pub use cache::{LruCache, CacheEntry, ResponseCache, CacheStats};
pub use config::{ScanConfig, ScanIntensity};
pub use context::ScanContext;
pub use dashboard::{DashboardOverview, DashboardService, DashboardConfig, ScanCard, FindingCard, FindingStatus, WidgetType};
pub use distributed::{WorkerNode, WorkerStatus, ScanTask, TaskStatus, TaskPriority, TaskQueue, WorkerPool, ResultAggregator};
pub use error::{ScannerError, Result};
pub use logging::{LogEntry, LogLevel, Logger};
pub use metrics::{MetricsCollector, MetricsSummary, PhaseMetrics};
pub use ml::{PatternLearner, VulnerabilityPattern, ClusterResult, ExploitBuilder, ExploitationChain, ExploitStage, AnomalyClassifier, AnomalyPattern, AnomalyType};
pub use monitoring::{PhaseProfile, ResourceMetrics, ScanProfile, PerformanceAnalyzer, OptimizationRecommendation, RecommendationCategory, BenchmarkSuite, BenchmarkResult, ScanComparison};
pub use plugin::{ScannerPlugin, PluginRegistry, PluginInfo};
pub use realtime::{RealtimeEvent, EventStream, ConnectionManager, Subscription};
pub use reporting::{VulnerabilityReport, ReportGenerator, ReportFormat};
pub use runner::ScanRunner;
pub use waf::{WafDetector, WafProduct, PayloadEncoder, EvisionTechnique};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanFinding {
    pub phase: u8,
    pub module_name: String,
    pub severity: String, // "CRITICAL", "HIGH", "MEDIUM", "LOW"
    pub description: String,
    pub evidence: String,
}

#[async_trait]
pub trait ScanPhase: Send + Sync {
    /// Phase number (1-10)
    fn phase_number(&self) -> u8;

    /// Phase name
    fn name(&self) -> &'static str;

    /// Execute phase logic
    async fn execute(&self, ctx: &ScanContext) -> Result<Vec<ScanFinding>>;
}
