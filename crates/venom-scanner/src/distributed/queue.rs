//! Queue: Priority task queue
use std::collections::VecDeque;
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority { Low = 1, Normal = 2, High = 3, Critical = 4 }
#[derive(Debug)]
pub struct TaskQueue {
    critical: VecDeque<String>,
    high: VecDeque<String>,
    normal: VecDeque<String>,
    low: VecDeque<String>,
}
impl TaskQueue {
    pub fn new() -> Self { Self { critical: VecDeque::new(), high: VecDeque::new(), normal: VecDeque::new(), low: VecDeque::new() } }
    pub fn enqueue(&mut self, task_id: String, priority: Priority) {
        match priority {
            Priority::Critical => self.critical.push_back(task_id),
            Priority::High => self.high.push_back(task_id),
            Priority::Normal => self.normal.push_back(task_id),
            Priority::Low => self.low.push_back(task_id),
        }
    }
    pub fn dequeue(&mut self) -> Option<String> {
        self.critical.pop_front().or_else(|| self.high.pop_front()).or_else(|| self.normal.pop_front()).or_else(|| self.low.pop_front())
    }
    pub fn len(&self) -> usize { self.critical.len() + self.high.len() + self.normal.len() + self.low.len() }
}
impl Default for TaskQueue {
    fn default() -> Self { Self::new() }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_queue() { let mut q = TaskQueue::new(); q.enqueue("t1".to_string(), Priority::Normal); assert_eq!(q.len(), 1); }
}
