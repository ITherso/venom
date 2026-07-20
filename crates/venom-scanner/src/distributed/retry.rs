//! Retry: Exponential backoff (P1)
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub initial_delay_ms: u64,
    pub max_delay_ms: u64,
    pub multiplier: f32,
}
impl RetryPolicy {
    pub fn new(max_attempts: u32) -> Self {
        Self { max_attempts, initial_delay_ms: 100, max_delay_ms: 30000, multiplier: 2.0 }
    }
    pub fn calculate_delay(&self, attempt: u32) -> u64 {
        if attempt == 0 { return 0; }
        let base = (self.initial_delay_ms as f32 * self.multiplier.powi(attempt as i32 - 1)) as u64;
        base.min(self.max_delay_ms)
    }
    pub fn should_retry(&self, attempt: u32, is_transient: bool) -> bool {
        is_transient && attempt < self.max_attempts
    }
}
impl Default for RetryPolicy {
    fn default() -> Self { Self::new(3) }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_retry() { let p = RetryPolicy::new(3); assert!(p.should_retry(0, true)); assert!(!p.should_retry(3, true)); }
}
