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
pub mod api_gateway;
pub mod auth;
pub mod cache;
pub mod compliance;
pub mod config;
pub mod config_loader;
pub mod context;
pub mod dashboard;
pub mod distributed;
pub mod error;
pub mod event_bus;
pub mod logging;
pub mod lua_engine;
pub mod metrics;
pub mod ml;
pub mod monitoring;
pub mod persistence;
pub mod phases;
pub mod plugin;
pub mod plugins;
pub mod post_exploitation;
pub mod realtime;
pub mod reporting;
pub mod runner;
pub mod threat_intelligence;
pub mod waf;

pub use adaptive::{AdaptiveEngine, AdaptationStrategy, DetectionPattern, PayloadMutator, ResponseMetrics};
pub use advanced_detection::{BehavioralSignature, BehaviorIndicator, IndicatorType, ComparisonOperator, WafBypassTechnique, BypassCategory, BehavioralAnalyzer, BehavioralAnalysisData, DetectionResult, WafBypassSelector, SignatureEvasionEngine, EversionRule, EversionType};
pub use anomaly::{AnomalyDetector, AnomalyScore, AnomalyInterpreter, SeverityClass, ResponseData};
pub use api::{ApiResponse, ScanStatus, ScanStatusType, StartScanRequest, ScanResultResponse, ApiEndpoints, ApiError};
pub use api_gateway::{RateLimitStrategy, RateLimitPolicy, RateLimitStatus, ApiQuota, RateLimiter, TokenBucket, QuotaManager, RouteConfig, ApiGateway, RequestValidationResult};
pub use auth::{User, UserRole, AuthToken, UserManager, UserInfo, LoginRequest, LoginResponse};
pub use cache::{LruCache, CacheEntry, ResponseCache, CacheStats};
pub use compliance::{ComplianceFramework, ComplianceRequirement, AuditEventType, AuditLogEntry, AuditLogger, ComplianceAssessment, ComplianceAssessor, DataProtectionRecord, DataClassification, DataProtectionManager, ComplianceReport, ComplianceReporter};
pub use config::{ScanConfig, ScanIntensity};
pub use config_loader::{ScanProfile as ScanningProfile, ConfigLoader};
pub use event_bus::{EventBus, Event, EventType, EventSeverity, EventHandler};
pub use lua_engine::{LuaScript, LuaContext, LuaExecutionResult, LuaScriptStatus, LuaScriptRegistry};
pub use context::ScanContext;
pub use dashboard::{DashboardOverview, DashboardService, DashboardConfig, ScanCard, FindingCard, FindingStatus, WidgetType};
pub use distributed::{WorkerNode, WorkerStatus, ScanTask, TaskStatus, TaskPriority, TaskQueue, WorkerPool, ResultAggregator};
pub use error::{ScannerError, Result};
pub use logging::{LogEntry, LogLevel, Logger};
pub use metrics::{MetricsCollector, MetricsSummary, PhaseMetrics};
pub use ml::{PatternLearner, VulnerabilityPattern, ClusterResult, ExploitBuilder, ExploitationChain, ExploitStage, AnomalyClassifier, AnomalyPattern, AnomalyType};
pub use monitoring::{PhaseProfile, ResourceMetrics, ScanProfile, PerformanceAnalyzer, OptimizationRecommendation, RecommendationCategory, BenchmarkSuite, BenchmarkResult, ScanComparison};
pub use persistence::{DbConfig, EntityType, ScanRecord, FindingRecord, EndpointRecord, QueryBuilder, SchemaManager, TableSchema, ColumnDef, IndexDef, ConnectionPool, TransactionManager, Transaction, TransactionStatus, QueryResult};
pub use plugin::{Plugin, PluginRegistry, PluginMetadata, PluginConfig, PluginCategory, PluginError, PluginExecutionResult};
pub use plugins::{XSSPlugin, SQLiPlugin, LFIPlugin, XXEPlugin, SSRFPlugin, SSTIPlugin};
pub use post_exploitation::{PayloadType, ReverseShell, Webshell, PersistenceMechanism, PersistenceTechnique, ExploitPayload, PostExploitSession, PrivilegeLevel, LateralTarget, PostExploitationManager};
pub use realtime::{RealtimeEvent, EventStream, ConnectionManager, Subscription};
pub use reporting::{VulnerabilityReport, ReportGenerator, ReportFormat};
pub use runner::ScanRunner;
pub use threat_intelligence::{ThreatFeedSource, CVERecord, ThreatFeedEntry, ThreatSeverity, CVECorrelator, ThreatFeedManager, AlertRule, AlertAction, AlertEngine, SecurityAlert, ThreatActorProfile, ThreatIntelligenceRepo};
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
