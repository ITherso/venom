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

// Core modules (always compiled)
pub mod error;
pub mod config;
pub mod config_loader;
pub mod context;
pub mod logging;
pub mod metrics;
pub mod cache;
pub mod auth;
pub mod api;
pub mod api_gateway;

// Scanning engine (feature: scanning)
#[cfg(feature = "scanning")]
pub mod phases;

#[cfg(feature = "scanning")]
pub mod runner;

#[cfg(feature = "scanning")]
pub mod waf;

#[cfg(feature = "scanning")]
pub mod adaptive;

// Detection capabilities (feature: detection)
#[cfg(feature = "detection")]
pub mod advanced_detection;

#[cfg(feature = "detection")]
pub mod anomaly;

// Machine learning (feature: ml)
#[cfg(feature = "ml")]
pub mod ml;

// Distributed scaling (feature: distributed)
#[cfg(feature = "distributed")]
pub mod distributed;

// Monitoring (feature: monitoring)
#[cfg(feature = "monitoring")]
pub mod monitoring;

// Compliance (feature: compliance)
#[cfg(feature = "compliance")]
pub mod compliance;

// Threat intelligence (feature: threat-intel)
#[cfg(feature = "threat-intel")]
pub mod threat_intelligence;

// Post-exploitation (included with scanning)
#[cfg(feature = "scanning")]
pub mod post_exploitation;

// Plugin system (feature: plugins)
#[cfg(feature = "plugins")]
pub mod plugin;

#[cfg(feature = "plugins")]
pub mod plugins;

#[cfg(feature = "plugins")]
pub mod lua_engine;

// Persistence & reporting (included with scanning)
#[cfg(feature = "scanning")]
pub mod persistence;

#[cfg(feature = "scanning")]
pub mod reporting;

#[cfg(feature = "scanning")]
pub mod realtime;

#[cfg(feature = "scanning")]
pub mod dashboard;

// Event bus (included with core for observability)
pub mod event_bus;

// Core exports (always available)
pub use api::{ApiResponse, ScanStatus, ScanStatusType, StartScanRequest, ScanResultResponse, ApiEndpoints, ApiError};
pub use api_gateway::{RateLimitStrategy, RateLimitPolicy, RateLimitStatus, ApiQuota, RateLimiter, TokenBucket, QuotaManager, RouteConfig, ApiGateway, RequestValidationResult};
pub use auth::{User, UserRole, AuthToken, UserManager, UserInfo, LoginRequest, LoginResponse};
pub use cache::{LruCache, CacheEntry, ResponseCache, CacheStats};
pub use config::{ScanConfig, ScanIntensity};
pub use config_loader::{ScanProfile as ScanningProfile, ConfigLoader};
pub use context::ScanContext;
pub use error::{ScannerError, Result};
pub use logging::{LogEntry, LogLevel, Logger};
pub use metrics::{MetricsCollector, MetricsSummary, PhaseMetrics};
pub use event_bus::{EventBus, Event, EventType, EventSeverity, EventHandler};

// Scanning engine exports (feature: scanning)
// Note: phases module is re-exported automatically

#[cfg(feature = "scanning")]
pub use runner::ScanRunner;

#[cfg(feature = "scanning")]
pub use waf::{WafDetector, WafProduct, PayloadEncoder, EvisionTechnique};

#[cfg(feature = "scanning")]
pub use adaptive::{AdaptiveEngine, AdaptationStrategy, DetectionPattern, PayloadMutator, ResponseMetrics};

#[cfg(feature = "scanning")]
pub use persistence::{DbConfig, EntityType, ScanRecord, FindingRecord, EndpointRecord, QueryBuilder, SchemaManager, TableSchema, ColumnDef, IndexDef, ConnectionPool, TransactionManager, Transaction, TransactionStatus, QueryResult};

#[cfg(feature = "scanning")]
pub use post_exploitation::{PayloadType, ReverseShell, Webshell, PersistenceMechanism, PersistenceTechnique, ExploitPayload, PostExploitSession, PrivilegeLevel, LateralTarget, PostExploitationManager};

#[cfg(feature = "scanning")]
pub use reporting::{VulnerabilityReport, ReportGenerator, ReportFormat};

#[cfg(feature = "scanning")]
pub use realtime::{RealtimeEvent, EventStream, ConnectionManager, Subscription};

#[cfg(feature = "scanning")]
pub use dashboard::{DashboardOverview, DashboardService, DashboardConfig, ScanCard, FindingCard, FindingStatus, WidgetType};

// Detection exports (feature: detection)
#[cfg(feature = "detection")]
pub use advanced_detection::{BehavioralSignature, BehaviorIndicator, IndicatorType, ComparisonOperator, WafBypassTechnique, BypassCategory, BehavioralAnalyzer, BehavioralAnalysisData, DetectionResult, WafBypassSelector, SignatureEvasionEngine, EversionRule, EversionType};

#[cfg(feature = "detection")]
pub use anomaly::{AnomalyDetector, AnomalyScore, AnomalyInterpreter, SeverityClass, ResponseData};

// Machine learning exports (feature: ml)
#[cfg(feature = "ml")]
pub use ml::{PatternLearner, VulnerabilityPattern, ClusterResult, ExploitBuilder, ExploitationChain, ExploitStage, AnomalyClassifier, AnomalyPattern, AnomalyType};

// Distributed scaling exports (feature: distributed)
#[cfg(feature = "distributed")]
pub use distributed::{WorkerNode, WorkerStatus, ScanTask, TaskStatus, TaskPriority, TaskQueue, WorkerPool, ResultAggregator};

// Monitoring exports (feature: monitoring)
#[cfg(feature = "monitoring")]
pub use monitoring::{PhaseProfile, ResourceMetrics, ScanProfile, PerformanceAnalyzer, OptimizationRecommendation, RecommendationCategory, BenchmarkSuite, BenchmarkResult, ScanComparison};

// Compliance exports (feature: compliance)
#[cfg(feature = "compliance")]
pub use compliance::{ComplianceFramework, ComplianceRequirement, AuditEventType, AuditLogEntry, AuditLogger, ComplianceAssessment, ComplianceAssessor, DataProtectionRecord, DataClassification, DataProtectionManager, ComplianceReport, ComplianceReporter};

// Threat intelligence exports (feature: threat-intel)
#[cfg(feature = "threat-intel")]
pub use threat_intelligence::{ThreatFeedSource, CVERecord, ThreatFeedEntry, ThreatSeverity, CVECorrelator, ThreatFeedManager, AlertRule, AlertAction, AlertEngine, SecurityAlert, ThreatActorProfile, ThreatIntelligenceRepo};

// Plugin system exports (feature: plugins)
#[cfg(feature = "plugins")]
pub use plugin::{Plugin, PluginRegistry, PluginMetadata, PluginConfig, PluginCategory, PluginError, PluginExecutionResult};

#[cfg(feature = "plugins")]
pub use plugins::{XSSPlugin, SQLiPlugin, LFIPlugin, XXEPlugin, SSRFPlugin, SSTIPlugin};

#[cfg(feature = "plugins")]
pub use lua_engine::{LuaScript, LuaContext, LuaExecutionResult, LuaScriptStatus, LuaScriptRegistry};

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
