use crate::Result;
use reqwest::Client;

pub struct Intruder {
    client: Client,
    target: String,
}

impl Intruder {
    pub fn new(target: String) -> Self {
        Self {
            client: Client::new(),
            target,
        }
    }

    pub async fn fuzz(&self, payloads: Vec<&str>, param: &str) -> Result<Vec<(String, u16)>> {
        let mut results = Vec::new();

        for payload in payloads {
            let url = format!("{}?{}={}", self.target, param, urlencoding::encode(payload));
            if let Ok(resp) = self.client.get(&url).send().await {
                let code = resp.status().as_u16();
                results.push((payload.to_string(), code));
            }
        }

        Ok(results)
    }
}
