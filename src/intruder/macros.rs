use serde::{Deserialize, Serialize};
use regex::Regex;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Macro {
    pub name: String,
    pub description: Option<String>,
    pub steps: Vec<MacroStep>,
    pub variables: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacroStep {
    pub step_type: MacroStepType,
    pub request: String,
    pub assertions: Vec<Assertion>,
    pub extractions: Vec<Extraction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MacroStepType {
    Request,
    Condition,
    Loop,
    SetVariable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Assertion {
    pub assertion_type: AssertionType,
    pub expected: String,
    pub actual: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AssertionType {
    StatusCode,
    ResponseContains,
    ResponseMatches,
    HeaderPresent,
    JsonPath,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Extraction {
    pub name: String,
    pub extraction_type: ExtractionType,
    pub pattern: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExtractionType {
    Regex,
    JsonPath,
    XPath,
    Header,
}

impl Macro {
    pub fn new(name: String) -> Self {
        Self {
            name,
            description: None,
            steps: Vec::new(),
            variables: HashMap::new(),
        }
    }

    pub fn add_step(&mut self, step: MacroStep) {
        self.steps.push(step);
    }

    pub fn set_variable(&mut self, name: String, value: String) {
        self.variables.insert(name, value);
    }

    pub fn get_variable(&self, name: &str) -> Option<&String> {
        self.variables.get(name)
    }

    pub fn resolve_variables(&self, text: &str) -> String {
        let mut result = text.to_string();

        for (name, value) in &self.variables {
            let placeholder = format!("${{{}}}", name);
            result = result.replace(&placeholder, value);
        }

        result
    }
}

impl MacroStep {
    pub fn new(step_type: MacroStepType, request: String) -> Self {
        Self {
            step_type,
            request,
            assertions: Vec::new(),
            extractions: Vec::new(),
        }
    }

    pub fn add_assertion(&mut self, assertion: Assertion) {
        self.assertions.push(assertion);
    }

    pub fn add_extraction(&mut self, extraction: Extraction) {
        self.extractions.push(extraction);
    }
}

impl Assertion {
    pub fn new(assertion_type: AssertionType, expected: String) -> Self {
        Self {
            assertion_type,
            expected,
            actual: None,
        }
    }

    pub fn verify(&mut self, actual: String) -> bool {
        self.actual = Some(actual.clone());

        match self.assertion_type {
            AssertionType::StatusCode => {
                if let Ok(expected_code) = self.expected.parse::<u16>() {
                    if let Ok(actual_code) = actual.parse::<u16>() {
                        return expected_code == actual_code;
                    }
                }
                false
            }
            AssertionType::ResponseContains => actual.contains(&self.expected),
            AssertionType::ResponseMatches => {
                if let Ok(re) = Regex::new(&self.expected) {
                    re.is_match(&actual)
                } else {
                    false
                }
            }
            AssertionType::HeaderPresent => actual.contains(&format!("{}: ", self.expected)),
            AssertionType::JsonPath => actual.contains(&self.expected),
        }
    }
}

impl Extraction {
    pub fn new(name: String, extraction_type: ExtractionType, pattern: String) -> Self {
        Self {
            name,
            extraction_type,
            pattern,
        }
    }

    pub fn extract(&self, response: &str) -> Option<String> {
        match self.extraction_type {
            ExtractionType::Regex => {
                if let Ok(re) = Regex::new(&self.pattern) {
                    if let Some(cap) = re.captures(response) {
                        return cap.get(1).map(|m| m.as_str().to_string());
                    }
                }
                None
            }
            ExtractionType::JsonPath => {
                if response.contains(&self.pattern) {
                    Some(self.pattern.clone())
                } else {
                    None
                }
            }
            ExtractionType::XPath => {
                if response.contains(&self.pattern) {
                    Some(self.pattern.clone())
                } else {
                    None
                }
            }
            ExtractionType::Header => {
                let header_pattern = format!("{}: ", self.pattern);
                if let Some(pos) = response.find(&header_pattern) {
                    let start = pos + header_pattern.len();
                    let end = response[start..].find('\n').unwrap_or(response.len() - start);
                    Some(response[start..start + end].to_string())
                } else {
                    None
                }
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacroExecutor {
    macros: HashMap<String, Macro>,
}

impl MacroExecutor {
    pub fn new() -> Self {
        Self {
            macros: HashMap::new(),
        }
    }

    pub fn register_macro(&mut self, macro_def: Macro) {
        self.macros.insert(macro_def.name.clone(), macro_def);
    }

    pub fn get_macro(&self, name: &str) -> Option<&Macro> {
        self.macros.get(name)
    }

    pub fn list_macros(&self) -> Vec<&str> {
        self.macros.keys().map(|k| k.as_str()).collect()
    }

    pub fn execute(&self, macro_name: &str, _base_url: &str) -> Result<MacroResult, String> {
        let macro_def = self.get_macro(macro_name).ok_or("Macro not found")?;

        let mut result = MacroResult {
            macro_name: macro_name.to_string(),
            success: true,
            steps_executed: 0,
            assertions_passed: 0,
            assertions_failed: 0,
            extracted_variables: HashMap::new(),
            errors: Vec::new(),
        };

        for step in &macro_def.steps {
            result.steps_executed += 1;

            for assertion in &step.assertions {
                let mut test_assertion = assertion.clone();
                if test_assertion.verify(String::new()) {
                    result.assertions_passed += 1;
                } else {
                    result.assertions_failed += 1;
                    result.success = false;
                }
            }

            for extraction in &step.extractions {
                if let Some(value) = extraction.extract("") {
                    result.extracted_variables.insert(extraction.name.clone(), value);
                }
            }
        }

        Ok(result)
    }
}

impl Default for MacroExecutor {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacroResult {
    pub macro_name: String,
    pub success: bool,
    pub steps_executed: usize,
    pub assertions_passed: usize,
    pub assertions_failed: usize,
    pub extracted_variables: HashMap<String, String>,
    pub errors: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_macro_creation() {
        let macro_def = Macro::new("login_flow".to_string());
        assert_eq!(macro_def.name, "login_flow");
        assert_eq!(macro_def.steps.len(), 0);
    }

    #[test]
    fn test_variable_resolution() {
        let mut macro_def = Macro::new("test".to_string());
        macro_def.set_variable("username".to_string(), "admin".to_string());

        let resolved = macro_def.resolve_variables("User: ${username}");
        assert_eq!(resolved, "User: admin");
    }

    #[test]
    fn test_assertion_verification() {
        let mut assertion = Assertion::new(AssertionType::StatusCode, "200".to_string());
        assert!(assertion.verify("200".to_string()));
        assert!(!assertion.verify("404".to_string()));
    }

    #[test]
    fn test_regex_assertion() {
        let mut assertion =
            Assertion::new(AssertionType::ResponseMatches, "success.*complete".to_string());
        assert!(assertion.verify("operation success and complete".to_string()));
    }

    #[test]
    fn test_extraction() {
        let extraction = Extraction::new(
            "token".to_string(),
            ExtractionType::Regex,
            "token=([a-f0-9]+)".to_string(),
        );

        let response = "token=abc123def456";
        let value = extraction.extract(response);
        assert!(value.is_some());
    }

    #[test]
    fn test_macro_executor() {
        let executor = MacroExecutor::new();
        assert_eq!(executor.list_macros().len(), 0);
    }
}
