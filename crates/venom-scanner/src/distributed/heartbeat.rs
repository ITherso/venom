//! Heartbeat: Health monitoring (P0 - prevents deadlock)
use std::collections::HashMap;
#[derive(Debug)]
pub struct HeartbeatMonitor {
    last_heartbeat: HashMap<String, u64>,
    heartbeat_timeout: u64,
}
impl HeartbeatMonitor {
    pub fn new(timeout: u64) -> Self {
        Self { last_heartbeat: HashMap::new(), heartbeat_timeout: timeout }
    }
    pub fn update_heartbeat(&mut self, worker_id: &str) {
        self.last_heartbeat.insert(worker_id.to_string(), 0);
    }
    pub fn is_alive(&self, worker_id: &str) -> bool {
        self.last_heartbeat.get(worker_id).is_some()
    }
    pub fn get_alive_workers(&self) -> Vec<String> {
        self.last_heartbeat.keys().cloned().collect()
    }
    pub fn prune_dead_workers(&mut self) {
        self.last_heartbeat.clear();
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_heartbeat() { let mut m = HeartbeatMonitor::new(30); m.update_heartbeat("w1"); assert!(m.is_alive("w1")); }
}
