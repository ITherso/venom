//! Protocol: Message definitions (NEW - Message format separation)
use std::collections::HashMap;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerStatus { Idle, Running, Dead, Recovering }
impl WorkerStatus { pub fn as_str(&self) -> &str { match self { WorkerStatus::Idle => "idle", WorkerStatus::Running => "running", WorkerStatus::Dead => "dead", WorkerStatus::Recovering => "recovering" } } }
#[derive(Debug, Clone)]
pub enum SchedulerCommand {
    AssignTask { task_id: String, payload: String },
    CancelTask { task_id: String },
    UpdateConfig { max_concurrent: u32 },
    Shutdown { graceful: bool },
}
#[derive(Debug, Clone)]
pub enum WorkerMessage {
    Heartbeat { worker_id: String, status: WorkerStatus, cpu_usage: f32, mem_usage: f32, active_tasks: u32 },
    TaskStarted { task_id: String, worker_id: String, timestamp: u64 },
    TaskCompleted { task_id: String, worker_id: String, result: TaskResult, timestamp: u64 },
    TaskFailed { task_id: String, worker_id: String, error: String, retry_count: u32, timestamp: u64 },
    WorkerReady { worker_id: String, capacity: u32, tags: Vec<String> },
}
#[derive(Debug, Clone)]
pub struct TaskResult {
    pub findings: Vec<u8>,
    pub metrics: TaskMetrics,
}
#[derive(Debug, Clone)]
pub struct TaskMetrics {
    pub duration_ms: u64,
    pub memory_peak_mb: u32,
    pub requests_sent: u32,
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_worker_status() { assert_eq!(WorkerStatus::Idle.as_str(), "idle"); }
}
