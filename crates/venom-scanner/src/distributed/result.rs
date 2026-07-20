//! Result: Result aggregation
use std::collections::HashMap;
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub task_id: String,
    pub status: String,
    pub findings: Vec<u8>,
}
#[derive(Debug)]
pub struct ResultAggregator {
    results: HashMap<String, Vec<u8>>,
}
impl ResultAggregator {
    pub fn new() -> Self { Self { results: HashMap::new() } }
    pub fn add_findings(&mut self, task_id: String, findings: Vec<u8>) { self.results.insert(task_id, findings); }
    pub fn get_result(&self, task_id: &str) -> Option<&Vec<u8>> { self.results.get(task_id) }
    pub fn clear(&mut self) { self.results.clear(); }
}
impl Default for ResultAggregator {
    fn default() -> Self { Self::new() }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_agg() { let mut a = ResultAggregator::new(); a.add_findings("t1".to_string(), vec![1,2,3]); assert!(a.get_result("t1").is_some()); }
}
