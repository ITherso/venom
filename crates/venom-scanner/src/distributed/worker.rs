//! Worker: Node state and lifecycle
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerState { Initializing, Ready, Busy, Dead, Draining }
impl WorkerState {
    pub fn as_str(&self) -> &str {
        match self {
            WorkerState::Initializing => "initializing",
            WorkerState::Ready => "ready",
            WorkerState::Busy => "busy",
            WorkerState::Dead => "dead",
            WorkerState::Draining => "draining",
        }
    }
}
#[derive(Debug, Clone)]
pub struct WorkerMetrics {
    pub cpu_usage: f32,
    pub memory_usage: f32,
    pub disk_usage: f32,
    pub network_usage: f32,
}
#[derive(Debug, Clone)]
pub struct Worker {
    pub id: String,
    pub state: WorkerState,
    pub capacity: u32,
    pub active_tasks: u32,
    pub completed_tasks: u64,
    pub failed_tasks: u64,
    pub last_heartbeat: u64,
    pub metrics: WorkerMetrics,
    pub tags: Vec<String>,
}
impl Worker {
    pub fn new(id: String, capacity: u32) -> Self {
        Self {
            id,
            state: WorkerState::Initializing,
            capacity,
            active_tasks: 0,
            completed_tasks: 0,
            failed_tasks: 0,
            last_heartbeat: 0,
            metrics: WorkerMetrics { cpu_usage: 0.0, memory_usage: 0.0, disk_usage: 0.0, network_usage: 0.0 },
            tags: Vec::new(),
        }
    }
    pub fn is_ready(&self) -> bool { self.state == WorkerState::Ready && self.active_tasks < self.capacity }
    pub fn available_slots(&self) -> u32 { (self.capacity - self.active_tasks).max(0) }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_worker() { let w = Worker::new("w1".to_string(), 10); assert!(w.is_ready()); }
}
