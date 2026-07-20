//! Detection rules (P1 - Flexible evaluation)
use std::collections::HashSet;
#[derive(Debug, Clone)]
pub struct StatusWhitelist {
    codes: HashSet<u16>,
}
impl StatusWhitelist {
    pub fn new(codes: Vec<u16>) -> Self { Self { codes: codes.into_iter().collect() } }
    pub fn common() -> Self { Self::new(vec![200, 201, 204, 301, 302, 304, 307, 308]) }
    pub fn strict() -> Self { Self::new(vec![200]) }
    pub fn is_normal(&self, status: u16) -> bool { self.codes.contains(&status) }
    pub fn add(&mut self, status: u16) { self.codes.insert(status); }
}
impl Default for StatusWhitelist {
    fn default() -> Self { Self::common() }
}
#[derive(Debug, Clone)]
pub struct ErrorKeywordMatcher {
    keywords: Vec<String>,
}
impl ErrorKeywordMatcher {
    pub fn new(keywords: Vec<&str>) -> Self {
        Self { keywords: keywords.into_iter().map(|s| s.to_string()).collect() }
    }
    pub fn contains_error(&self, text: &str) -> bool {
        self.keywords.iter().any(|k| text.contains(k))
    }
}
impl Default for ErrorKeywordMatcher {
    fn default() -> Self {
        Self::new(vec!["error", "exception", "failed", "stack trace", "timeout", "denied"])
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_whitelist() { let w = StatusWhitelist::common(); assert!(w.is_normal(200)); assert!(!w.is_normal(500)); }
    #[test]
    fn test_matcher() { let m = ErrorKeywordMatcher::default(); assert!(m.contains_error("error found")); }
}
