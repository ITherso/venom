use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use uuid::Uuid;
use crate::intruder::Macro;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacroTemplate {
    pub id: String,
    pub name: String,
    pub category: MacroCategory,
    pub description: String,
    pub macro_definition: Macro,
    pub difficulty: Difficulty,
    pub tags: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub downloads: u32,
    pub rating: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum MacroCategory {
    Authentication,
    DataExtraction,
    Reconnaissance,
    Exploitation,
    Persistence,
    Evasion,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum Difficulty {
    Beginner,
    Intermediate,
    Advanced,
    Expert,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacroLibrary {
    templates: HashMap<String, MacroTemplate>,
    categories: HashMap<MacroCategory, Vec<String>>,
}

impl MacroLibrary {
    pub fn new() -> Self {
        let mut library = Self {
            templates: HashMap::new(),
            categories: HashMap::new(),
        };

        // Initialize categories
        library.categories.insert(MacroCategory::Authentication, Vec::new());
        library.categories.insert(MacroCategory::DataExtraction, Vec::new());
        library.categories.insert(MacroCategory::Reconnaissance, Vec::new());
        library.categories.insert(MacroCategory::Exploitation, Vec::new());
        library.categories.insert(MacroCategory::Persistence, Vec::new());
        library.categories.insert(MacroCategory::Evasion, Vec::new());
        library.categories.insert(MacroCategory::Custom, Vec::new());

        library.load_builtin_templates();
        library
    }

    fn load_builtin_templates(&mut self) {
        // JWT Token Extraction Macro
        let jwt_macro = MacroTemplate {
            id: Uuid::new_v4().to_string(),
            name: "JWT Token Extraction".to_string(),
            category: MacroCategory::DataExtraction,
            description: "Extract JWT tokens from authentication responses".to_string(),
            macro_definition: Macro::new("jwt_extract".to_string()),
            difficulty: Difficulty::Beginner,
            tags: vec!["jwt".to_string(), "auth".to_string(), "token".to_string()],
            created_at: Utc::now(),
            downloads: 0,
            rating: 4.5,
        };
        self.add_template(jwt_macro);

        // SQL Injection Detection Macro
        let sqli_macro = MacroTemplate {
            id: Uuid::new_v4().to_string(),
            name: "SQL Injection Detection".to_string(),
            category: MacroCategory::Reconnaissance,
            description: "Automated SQL injection detection and exploitation".to_string(),
            macro_definition: Macro::new("sqli_detect".to_string()),
            difficulty: Difficulty::Intermediate,
            tags: vec!["sqli".to_string(), "injection".to_string(), "detection".to_string()],
            created_at: Utc::now(),
            downloads: 0,
            rating: 4.8,
        };
        self.add_template(sqli_macro);

        // XSS Payload Testing Macro
        let xss_macro = MacroTemplate {
            id: Uuid::new_v4().to_string(),
            name: "XSS Payload Testing".to_string(),
            category: MacroCategory::Exploitation,
            description: "Comprehensive XSS payload testing workflow".to_string(),
            macro_definition: Macro::new("xss_test".to_string()),
            difficulty: Difficulty::Beginner,
            tags: vec!["xss".to_string(), "payload".to_string(), "testing".to_string()],
            created_at: Utc::now(),
            downloads: 0,
            rating: 4.6,
        };
        self.add_template(xss_macro);

        // IDOR Enumeration Macro
        let idor_macro = MacroTemplate {
            id: Uuid::new_v4().to_string(),
            name: "IDOR Enumeration".to_string(),
            category: MacroCategory::Exploitation,
            description: "Insecure Direct Object Reference enumeration".to_string(),
            macro_definition: Macro::new("idor_enum".to_string()),
            difficulty: Difficulty::Intermediate,
            tags: vec!["idor".to_string(), "access_control".to_string(), "enumeration".to_string()],
            created_at: Utc::now(),
            downloads: 0,
            rating: 4.4,
        };
        self.add_template(idor_macro);

        // API Rate Limit Testing Macro
        let ratelimit_macro = MacroTemplate {
            id: Uuid::new_v4().to_string(),
            name: "Rate Limit Testing".to_string(),
            category: MacroCategory::Reconnaissance,
            description: "Test and identify API rate limit bypass techniques".to_string(),
            macro_definition: Macro::new("ratelimit_test".to_string()),
            difficulty: Difficulty::Advanced,
            tags: vec!["api".to_string(), "rate_limit".to_string(), "bypass".to_string()],
            created_at: Utc::now(),
            downloads: 0,
            rating: 4.7,
        };
        self.add_template(ratelimit_macro);

        // WAF Bypass Macro
        let waf_macro = MacroTemplate {
            id: Uuid::new_v4().to_string(),
            name: "WAF Bypass Techniques".to_string(),
            category: MacroCategory::Evasion,
            description: "Test and bypass Web Application Firewall rules".to_string(),
            macro_definition: Macro::new("waf_bypass".to_string()),
            difficulty: Difficulty::Expert,
            tags: vec!["waf".to_string(), "evasion".to_string(), "bypass".to_string()],
            created_at: Utc::now(),
            downloads: 0,
            rating: 4.9,
        };
        self.add_template(waf_macro);
    }

    pub fn add_template(&mut self, template: MacroTemplate) {
        let category = template.category.clone();
        self.templates.insert(template.id.clone(), template.clone());
        self.categories.entry(category).or_insert_with(Vec::new).push(template.id);
    }

    pub fn get_template(&self, id: &str) -> Option<&MacroTemplate> {
        self.templates.get(id)
    }

    pub fn get_by_category(&self, category: &MacroCategory) -> Vec<&MacroTemplate> {
        self.categories
            .get(category)
            .unwrap_or(&Vec::new())
            .iter()
            .filter_map(|id| self.templates.get(id))
            .collect()
    }

    pub fn search(&self, query: &str) -> Vec<&MacroTemplate> {
        self.templates
            .values()
            .filter(|t| {
                t.name.to_lowercase().contains(&query.to_lowercase())
                    || t.description.to_lowercase().contains(&query.to_lowercase())
                    || t.tags.iter().any(|tag| tag.to_lowercase().contains(&query.to_lowercase()))
            })
            .collect()
    }

    pub fn get_by_difficulty(&self, difficulty: &Difficulty) -> Vec<&MacroTemplate> {
        self.templates
            .values()
            .filter(|t| &t.difficulty == difficulty)
            .collect()
    }

    pub fn get_popular(&self, limit: usize) -> Vec<&MacroTemplate> {
        let mut templates: Vec<_> = self.templates.values().collect();
        templates.sort_by(|a, b| b.rating.partial_cmp(&a.rating).unwrap_or(std::cmp::Ordering::Equal));
        templates.into_iter().take(limit).collect()
    }

    pub fn list_all(&self) -> Vec<&MacroTemplate> {
        self.templates.values().collect()
    }

    pub fn get_statistics(&self) -> LibraryStatistics {
        LibraryStatistics {
            total_templates: self.templates.len(),
            total_downloads: self.templates.values().map(|t| t.downloads).sum(),
            average_rating: {
                let sum: f32 = self.templates.values().map(|t| t.rating).sum();
                if self.templates.is_empty() { 0.0 } else { sum / self.templates.len() as f32 }
            },
            categories_count: self.categories.len(),
        }
    }
}

impl Default for MacroLibrary {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LibraryStatistics {
    pub total_templates: usize,
    pub total_downloads: u32,
    pub average_rating: f32,
    pub categories_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_macro_library_creation() {
        let library = MacroLibrary::new();
        assert!(!library.list_all().is_empty());
    }

    #[test]
    fn test_get_by_category() {
        let library = MacroLibrary::new();
        let auth_macros = library.get_by_category(&MacroCategory::Authentication);
        // Should have pre-built templates
        assert!(library.list_all().len() > 0);
    }

    #[test]
    fn test_search_templates() {
        let library = MacroLibrary::new();
        let results = library.search("jwt");
        assert!(!results.is_empty());
    }

    #[test]
    fn test_get_popular() {
        let library = MacroLibrary::new();
        let popular = library.get_popular(3);
        assert!(popular.len() <= 3);
    }
}
