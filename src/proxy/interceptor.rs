use crate::Result;
use super::http_parser::{HttpRequest, HttpResponse};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct InterceptionRule {
    pub id: String,
    pub enabled: bool,
    pub condition: InterceptionCondition,
    pub action: InterceptionAction,
}

#[derive(Debug, Clone)]
pub enum InterceptionCondition {
    UrlContains(String),
    MethodEquals(String),
    HeaderExists(String),
    All,
}

#[derive(Debug, Clone)]
pub enum InterceptionAction {
    DropRequest,
    DropResponse,
    ModifyRequest(HashMap<String, String>),
    ModifyResponse(HashMap<String, String>),
    LogOnly,
}

pub struct RequestInterceptor {
    rules: Vec<InterceptionRule>,
    active: bool,
}

impl RequestInterceptor {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            active: true,
        }
    }

    pub fn add_rule(&mut self, rule: InterceptionRule) {
        self.rules.push(rule);
    }

    pub fn remove_rule(&mut self, rule_id: &str) {
        self.rules.retain(|r| r.id != rule_id);
    }

    pub fn enable(&mut self) {
        self.active = true;
    }

    pub fn disable(&mut self) {
        self.active = false;
    }

    pub fn should_intercept_request(&self, req: &HttpRequest) -> bool {
        if !self.active {
            return false;
        }

        self.rules.iter().any(|rule| {
            rule.enabled && self.matches_condition(req, &rule.condition)
        })
    }

    pub fn should_intercept_response(&self, res: &HttpResponse) -> bool {
        if !self.active {
            return false;
        }

        self.rules.iter().any(|rule| {
            rule.enabled && matches!(rule.action, InterceptionAction::ModifyResponse(_))
        })
    }

    pub fn apply_request_modifications(&self, req: &mut HttpRequest) -> Result<()> {
        for rule in &self.rules {
            if !rule.enabled || !self.matches_condition(req, &rule.condition) {
                continue;
            }

            match &rule.action {
                InterceptionAction::ModifyRequest(mods) => {
                    for (key, value) in mods {
                        if key == "method" {
                            req.method = value.clone();
                        } else if key == "path" {
                            req.path = value.clone();
                        } else {
                            req.headers.insert(key.to_lowercase(), value.clone());
                        }
                    }
                }
                InterceptionAction::DropRequest => {
                    return Err(crate::Error::ProxyError("Request dropped by rule".into()));
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub fn apply_response_modifications(&self, res: &mut HttpResponse) -> Result<()> {
        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            match &rule.action {
                InterceptionAction::ModifyResponse(mods) => {
                    for (key, value) in mods {
                        if key == "status" {
                            res.status_code = value.parse().unwrap_or(200);
                        } else {
                            res.headers.insert(key.to_lowercase(), value.clone());
                        }
                    }
                }
                InterceptionAction::DropResponse => {
                    return Err(crate::Error::ProxyError("Response dropped by rule".into()));
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn matches_condition(&self, req: &HttpRequest, condition: &InterceptionCondition) -> bool {
        match condition {
            InterceptionCondition::UrlContains(pattern) => req.path.contains(pattern),
            InterceptionCondition::MethodEquals(method) => req.method == *method,
            InterceptionCondition::HeaderExists(header) => req.headers.contains_key(&header.to_lowercase()),
            InterceptionCondition::All => true,
        }
    }

    pub fn list_rules(&self) -> Vec<&InterceptionRule> {
        self.rules.iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_intercept_url() {
        let mut interceptor = RequestInterceptor::new();
        interceptor.add_rule(InterceptionRule {
            id: "1".to_string(),
            enabled: true,
            condition: InterceptionCondition::UrlContains("/api".to_string()),
            action: InterceptionAction::LogOnly,
        });

        let req = HttpRequest {
            method: "GET".to_string(),
            path: "/api/users".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: HashMap::new(),
            body: Vec::new(),
        };

        assert!(interceptor.should_intercept_request(&req));
    }
}
