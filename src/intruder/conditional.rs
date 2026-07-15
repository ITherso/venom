use serde::{Deserialize, Serialize};
use regex::Regex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConditionalPayload {
    pub id: String,
    pub condition: PayloadCondition,
    pub payload: String,
    pub description: Option<String>,
    pub priority: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PayloadCondition {
    Always,
    IfStatusCode(u16),
    IfResponseContains(String),
    IfResponseMatches(String),
    IfResponseNotContains(String),
    IfHeaderPresent(String),
    IfContentType(String),
    IfResponseSize { min: usize, max: usize },
    IfResponseTime { min: u128, max: u128 },
    And(Box<PayloadCondition>, Box<PayloadCondition>),
    Or(Box<PayloadCondition>, Box<PayloadCondition>),
    Not(Box<PayloadCondition>),
}

#[derive(Debug, Clone)]
pub struct ResponseContext {
    pub status_code: u16,
    pub body: String,
    pub headers: Vec<(String, String)>,
    pub response_time_ms: u128,
}

impl PayloadCondition {
    pub fn evaluate(&self, context: &ResponseContext) -> bool {
        match self {
            PayloadCondition::Always => true,
            PayloadCondition::IfStatusCode(code) => context.status_code == *code,
            PayloadCondition::IfResponseContains(text) => context.body.contains(text),
            PayloadCondition::IfResponseMatches(pattern) => {
                if let Ok(re) = Regex::new(pattern) {
                    re.is_match(&context.body)
                } else {
                    false
                }
            }
            PayloadCondition::IfResponseNotContains(text) => !context.body.contains(text),
            PayloadCondition::IfHeaderPresent(header) => {
                context
                    .headers
                    .iter()
                    .any(|(k, _)| k.to_lowercase() == header.to_lowercase())
            }
            PayloadCondition::IfContentType(content_type) => {
                context
                    .headers
                    .iter()
                    .any(|(k, v)| {
                        k.to_lowercase() == "content-type"
                            && v.contains(content_type)
                    })
            }
            PayloadCondition::IfResponseSize { min, max } => {
                let size = context.body.len();
                size >= *min && size <= *max
            }
            PayloadCondition::IfResponseTime { min, max } => {
                context.response_time_ms >= *min && context.response_time_ms <= *max
            }
            PayloadCondition::And(left, right) => {
                left.evaluate(context) && right.evaluate(context)
            }
            PayloadCondition::Or(left, right) => {
                left.evaluate(context) || right.evaluate(context)
            }
            PayloadCondition::Not(condition) => !condition.evaluate(context),
        }
    }
}

impl ConditionalPayload {
    pub fn new(id: String, condition: PayloadCondition, payload: String) -> Self {
        Self {
            id,
            condition,
            payload,
            description: None,
            priority: 0,
        }
    }

    pub fn with_description(mut self, desc: String) -> Self {
        self.description = Some(desc);
        self
    }

    pub fn with_priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }

    pub fn matches(&self, context: &ResponseContext) -> bool {
        self.condition.evaluate(context)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConditionalPayloadSet {
    payloads: Vec<ConditionalPayload>,
}

impl ConditionalPayloadSet {
    pub fn new() -> Self {
        Self {
            payloads: Vec::new(),
        }
    }

    pub fn add(&mut self, payload: ConditionalPayload) {
        self.payloads.push(payload);
        self.payloads.sort_by_key(|p| std::cmp::Reverse(p.priority));
    }

    pub fn get_matching(&self, context: &ResponseContext) -> Vec<&ConditionalPayload> {
        self.payloads
            .iter()
            .filter(|p| p.matches(context))
            .collect()
    }

    pub fn get_next_payload(&self, context: &ResponseContext) -> Option<&str> {
        self.get_matching(context)
            .first()
            .map(|p| p.payload.as_str())
    }

    pub fn count(&self) -> usize {
        self.payloads.len()
    }
}

impl Default for ConditionalPayloadSet {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptivePayloadEngine {
    payload_sets: std::collections::HashMap<String, ConditionalPayloadSet>,
}

impl AdaptivePayloadEngine {
    pub fn new() -> Self {
        Self {
            payload_sets: std::collections::HashMap::new(),
        }
    }

    pub fn register_set(&mut self, name: String, set: ConditionalPayloadSet) {
        self.payload_sets.insert(name, set);
    }

    pub fn get_set(&self, name: &str) -> Option<&ConditionalPayloadSet> {
        self.payload_sets.get(name)
    }

    pub fn get_payload(
        &self,
        set_name: &str,
        context: &ResponseContext,
    ) -> Option<String> {
        self.get_set(set_name)
            .and_then(|set| set.get_next_payload(context))
            .map(|s| s.to_string())
    }

    pub fn get_all_matching(
        &self,
        set_name: &str,
        context: &ResponseContext,
    ) -> Vec<String> {
        self.get_set(set_name)
            .map(|set| {
                set.get_matching(context)
                    .into_iter()
                    .map(|p| p.payload.clone())
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl Default for AdaptivePayloadEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_condition_always() {
        let condition = PayloadCondition::Always;
        let context = ResponseContext {
            status_code: 200,
            body: "test".to_string(),
            headers: vec![],
            response_time_ms: 100,
        };

        assert!(condition.evaluate(&context));
    }

    #[test]
    fn test_status_code_condition() {
        let condition = PayloadCondition::IfStatusCode(200);
        let context = ResponseContext {
            status_code: 200,
            body: "".to_string(),
            headers: vec![],
            response_time_ms: 0,
        };

        assert!(condition.evaluate(&context));

        let context_404 = ResponseContext {
            status_code: 404,
            body: "".to_string(),
            headers: vec![],
            response_time_ms: 0,
        };

        assert!(!condition.evaluate(&context_404));
    }

    #[test]
    fn test_response_contains_condition() {
        let condition = PayloadCondition::IfResponseContains("success".to_string());
        let context = ResponseContext {
            status_code: 200,
            body: "Operation success".to_string(),
            headers: vec![],
            response_time_ms: 0,
        };

        assert!(condition.evaluate(&context));
    }

    #[test]
    fn test_and_condition() {
        let condition = PayloadCondition::And(
            Box::new(PayloadCondition::IfStatusCode(200)),
            Box::new(PayloadCondition::IfResponseContains("success".to_string())),
        );

        let context = ResponseContext {
            status_code: 200,
            body: "success".to_string(),
            headers: vec![],
            response_time_ms: 0,
        };

        assert!(condition.evaluate(&context));

        let context_fail = ResponseContext {
            status_code: 404,
            body: "success".to_string(),
            headers: vec![],
            response_time_ms: 0,
        };

        assert!(!condition.evaluate(&context_fail));
    }

    #[test]
    fn test_conditional_payload_set() {
        let mut set = ConditionalPayloadSet::new();

        set.add(ConditionalPayload::new(
            "1".to_string(),
            PayloadCondition::IfStatusCode(200),
            "payload1".to_string(),
        ));

        let context = ResponseContext {
            status_code: 200,
            body: "".to_string(),
            headers: vec![],
            response_time_ms: 0,
        };

        let matching = set.get_matching(&context);
        assert_eq!(matching.len(), 1);
    }
}
