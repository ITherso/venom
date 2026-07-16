//! Distributed Scanning Architecture
//!
//! Multi-worker coordination, task queuing, and result aggregation
//! for horizontal scaling across multiple nodes.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use dashmap::DashMap;

/// Worker node in distributed system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerNode {
    pub worker_id: String,
    pub hostname: String,
    pub address: String,
    pub port: u16,
    pub status: WorkerStatus,
    pub capacity: u32,
    pub current_tasks: u32,
    pub completed_tasks: u64,
    pub last_heartbeat: u64,
}

/// Worker status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkerStatus {
    #[serde(rename = "healthy")]
    Healthy,
    #[serde(rename = "busy")]
    Busy,
    #[serde(rename = "degraded")]
    Degraded,
    #[serde(rename = "offline")]
    Offline,
}

impl WorkerStatus {
    pub fn as_str(&self) -> &str {
        match self {
            WorkerStatus::Healthy => "healthy",
            WorkerStatus::Busy => "busy",
            WorkerStatus::Degraded => "degraded",
            WorkerStatus::Offline => "offline",
        }
    }
}

/// Scan task for distributed execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanTask {
    pub task_id: String,
    pub scan_id: String,
    pub target: String,
    pub phases: Vec<u8>,
    pub assigned_to: Option<String>,
    pub status: TaskStatus,
    pub created_at: u64,
    pub started_at: Option<u64>,
    pub completed_at: Option<u64>,
    pub priority: TaskPriority,
}

/// Task status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskStatus {
    #[serde(rename = "queued")]
    Queued,
    #[serde(rename = "assigned")]
    Assigned,
    #[serde(rename = "running")]
    Running,
    #[serde(rename = "completed")]
    Completed,
    #[serde(rename = "failed")]
    Failed,
}

impl TaskStatus {
    pub fn as_str(&self) -> &str {
        match self {
            TaskStatus::Queued => "queued",
            TaskStatus::Assigned => "assigned",
            TaskStatus::Running => "running",
            TaskStatus::Completed => "completed",
            TaskStatus::Failed => "failed",
        }
    }
}

/// Task priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TaskPriority {
    #[serde(rename = "low")]
    Low = 1,
    #[serde(rename = "normal")]
    Normal = 2,
    #[serde(rename = "high")]
    High = 3,
    #[serde(rename = "critical")]
    Critical = 4,
}

/// Task queue for managing distributed work
pub struct TaskQueue {
    tasks: Arc<DashMap<String, ScanTask>>,
    queue: Arc<DashMap<u8, Vec<String>>>, // priority -> task_ids
}

impl TaskQueue {
    pub fn new() -> Self {
        Self {
            tasks: Arc::new(DashMap::new()),
            queue: Arc::new(DashMap::new()),
        }
    }

    pub fn enqueue(&self, task: ScanTask) {
        let task_id = task.task_id.clone();
        let priority = task.priority as u8;

        self.tasks.insert(task_id.clone(), task);
        self.queue
            .entry(priority)
            .or_insert_with(Vec::new)
            .push(task_id);
    }

    pub fn dequeue(&self) -> Option<ScanTask> {
        // Get highest priority task
        for priority in (1..=4).rev() {
            if let Some(mut queue) = self.queue.get_mut(&priority) {
                if let Some(task_id) = queue.pop() {
                    if let Some((_, task)) = self.tasks.remove(&task_id) {
                        return Some(task);
                    }
                }
            }
        }
        None
    }

    pub fn get_task(&self, task_id: &str) -> Option<ScanTask> {
        self.tasks.get(task_id).map(|t| t.clone())
    }

    pub fn update_task(&self, task: ScanTask) {
        self.tasks.insert(task.task_id.clone(), task);
    }

    pub fn queue_size(&self) -> usize {
        self.tasks.len()
    }
}

impl Default for TaskQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Worker pool for managing multiple scanning nodes
pub struct WorkerPool {
    workers: Arc<DashMap<String, WorkerNode>>,
    pub task_queue: TaskQueue,
}

impl WorkerPool {
    pub fn new() -> Self {
        Self {
            workers: Arc::new(DashMap::new()),
            task_queue: TaskQueue::new(),
        }
    }

    pub fn register_worker(&self, worker: WorkerNode) {
        self.workers.insert(worker.worker_id.clone(), worker);
    }

    pub fn deregister_worker(&self, worker_id: &str) {
        self.workers.remove(worker_id);
    }

    pub fn get_available_worker(&self) -> Option<WorkerNode> {
        self.workers
            .iter()
            .filter(|entry| {
                let worker = entry.value();
                worker.status == WorkerStatus::Healthy
                    && worker.current_tasks < worker.capacity
            })
            .min_by_key(|entry| entry.value().current_tasks)
            .map(|entry| entry.value().clone())
    }

    pub fn assign_task(&self, task_id: &str, worker_id: &str) -> bool {
        if let Some(mut task) = self.task_queue.get_task(task_id) {
            task.assigned_to = Some(worker_id.to_string());
            task.status = TaskStatus::Assigned;
            self.task_queue.update_task(task);

            if let Some(mut worker) = self.workers.get_mut(worker_id) {
                worker.current_tasks += 1;
            }
            true
        } else {
            false
        }
    }

    pub fn complete_task(&self, task_id: &str) {
        if let Some(mut task) = self.task_queue.get_task(task_id) {
            if let Some(worker_id) = task.assigned_to.clone() {
                task.status = TaskStatus::Completed;
                task.completed_at = Some(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                );
                self.task_queue.update_task(task);

                if let Some(mut worker) = self.workers.get_mut(&worker_id) {
                    worker.current_tasks = worker.current_tasks.saturating_sub(1);
                    worker.completed_tasks += 1;
                }
            }
        }
    }

    pub fn worker_count(&self) -> usize {
        self.workers.len()
    }

    pub fn healthy_worker_count(&self) -> usize {
        self.workers
            .iter()
            .filter(|w| w.value().status == WorkerStatus::Healthy)
            .count()
    }

    pub fn get_workers(&self) -> Vec<WorkerNode> {
        self.workers.iter().map(|entry| entry.value().clone()).collect()
    }
}

impl Default for WorkerPool {
    fn default() -> Self {
        Self::new()
    }
}

/// Result aggregator for combining worker results
pub struct ResultAggregator {
    results: Arc<DashMap<String, Vec<u8>>>,
}

impl ResultAggregator {
    pub fn new() -> Self {
        Self {
            results: Arc::new(DashMap::new()),
        }
    }

    pub fn store_result(&self, task_id: &str, result: Vec<u8>) {
        self.results.insert(task_id.to_string(), result);
    }

    pub fn get_result(&self, task_id: &str) -> Option<Vec<u8>> {
        self.results.get(task_id).map(|r| r.clone())
    }

    pub fn aggregate_results(&self, task_ids: &[&str]) -> Vec<Vec<u8>> {
        task_ids
            .iter()
            .filter_map(|id| self.get_result(id))
            .collect()
    }
}

impl Default for ResultAggregator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_worker_node_creation() {
        let worker = WorkerNode {
            worker_id: "w1".to_string(),
            hostname: "scanner-1".to_string(),
            address: "192.168.1.10".to_string(),
            port: 8000,
            status: WorkerStatus::Healthy,
            capacity: 10,
            current_tasks: 0,
            completed_tasks: 0,
            last_heartbeat: 1000,
        };

        assert_eq!(worker.worker_id, "w1");
        assert_eq!(worker.status, WorkerStatus::Healthy);
    }

    #[test]
    fn test_task_creation() {
        let task = ScanTask {
            task_id: "t1".to_string(),
            scan_id: "s1".to_string(),
            target: "https://example.com".to_string(),
            phases: vec![1, 2, 3],
            assigned_to: None,
            status: TaskStatus::Queued,
            created_at: 1000,
            started_at: None,
            completed_at: None,
            priority: TaskPriority::Normal,
        };

        assert_eq!(task.priority, TaskPriority::Normal);
    }

    #[test]
    fn test_task_priority_ordering() {
        assert!(TaskPriority::Critical > TaskPriority::High);
        assert!(TaskPriority::High > TaskPriority::Normal);
        assert!(TaskPriority::Normal > TaskPriority::Low);
    }

    #[test]
    fn test_task_queue() {
        let queue = TaskQueue::new();
        let task = ScanTask {
            task_id: "t1".to_string(),
            scan_id: "s1".to_string(),
            target: "https://example.com".to_string(),
            phases: vec![1],
            assigned_to: None,
            status: TaskStatus::Queued,
            created_at: 1000,
            started_at: None,
            completed_at: None,
            priority: TaskPriority::Normal,
        };

        queue.enqueue(task);
        assert_eq!(queue.queue_size(), 1);
    }

    #[test]
    fn test_worker_pool() {
        let pool = WorkerPool::new();
        let worker = WorkerNode {
            worker_id: "w1".to_string(),
            hostname: "scanner-1".to_string(),
            address: "192.168.1.10".to_string(),
            port: 8000,
            status: WorkerStatus::Healthy,
            capacity: 10,
            current_tasks: 0,
            completed_tasks: 0,
            last_heartbeat: 1000,
        };

        pool.register_worker(worker);
        assert_eq!(pool.worker_count(), 1);
    }

    #[test]
    fn test_available_worker() {
        let pool = WorkerPool::new();
        let worker = WorkerNode {
            worker_id: "w1".to_string(),
            hostname: "scanner-1".to_string(),
            address: "192.168.1.10".to_string(),
            port: 8000,
            status: WorkerStatus::Healthy,
            capacity: 10,
            current_tasks: 0,
            completed_tasks: 0,
            last_heartbeat: 1000,
        };

        pool.register_worker(worker);
        let available = pool.get_available_worker();
        assert!(available.is_some());
    }

    #[test]
    fn test_result_aggregator() {
        let agg = ResultAggregator::new();
        let result = vec![1, 2, 3, 4, 5];

        agg.store_result("t1", result.clone());
        assert_eq!(agg.get_result("t1"), Some(result));
    }
}
