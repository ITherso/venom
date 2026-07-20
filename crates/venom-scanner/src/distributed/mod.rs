//! Distributed module (refactored Sprint 1)
pub mod protocol;
pub mod worker;
pub mod heartbeat;
pub mod scheduler;
pub mod queue;
pub mod retry;
pub mod result;
pub use protocol::{WorkerMessage, SchedulerCommand, WorkerStatus};
pub use worker::{Worker, WorkerState};
pub use heartbeat::HeartbeatMonitor;
pub use scheduler::Scheduler;
pub use queue::{TaskQueue, Priority};
pub use retry::RetryPolicy;
pub use result::{ResultAggregator, ScanResult};
