//! Scheduler: Task assignment
use super::worker::{Worker, WorkerState};
use std::collections::HashMap;
#[derive(Debug)]
pub struct Scheduler {
    workers: HashMap<String, Worker>,
}
impl Scheduler {
    pub fn new() -> Self { Self { workers: HashMap::new() } }
    pub fn register_worker(&mut self, worker: Worker) { self.workers.insert(worker.id.clone(), worker); }
    pub fn get_worker(&self, id: &str) -> Option<&Worker> { self.workers.get(id) }
    pub fn find_available_worker(&self) -> Option<&Worker> {
        self.workers.values().filter(|w| w.is_ready()).next()
    }
    pub fn assign_task(&mut self, task_id: &str) -> Option<String> {
        let worker = self.find_available_worker()?;
        Some(worker.id.clone())
    }
    pub fn get_workers(&self) -> Vec<&Worker> { self.workers.values().collect() }
}
impl Default for Scheduler {
    fn default() -> Self { Self::new() }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_scheduler() { let mut s = Scheduler::new(); let w = Worker::new("w1".to_string(), 5); s.register_worker(w); assert!(s.find_available_worker().is_some()); }
}
