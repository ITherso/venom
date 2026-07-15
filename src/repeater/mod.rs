use crate::Result;
use reqwest::Client;

pub struct Repeater {
    client: Client,
}

impl Repeater {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
        }
    }

    pub async fn send(&self, url: &str, method: &str, body: Option<&str>) -> Result<String> {
        let response = match method {
            "GET" => self.client.get(url).send().await?,
            "POST" => {
                let req = self.client.post(url);
                if let Some(b) = body {
                    req.body(b.to_string()).send().await?
                } else {
                    req.send().await?
                }
            }
            _ => return Err(crate::Error::ProxyError("Unsupported method".into())),
        };

        Ok(response.text().await?)
    }
}
