pub mod proxy;
pub mod scanner;
pub mod postexploit;
pub mod repeater;
pub mod intruder;
pub mod decoder;
pub mod database;
pub mod api;
pub mod reporting;
pub mod error;

pub use error::{Error, Result};

#[derive(Debug, Clone)]
pub struct Config {
    pub proxy_host: String,
    pub proxy_port: u16,
    pub db_path: String,
    pub api_port: u16,
    pub threads: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            proxy_host: "127.0.0.1".to_string(),
            proxy_port: 8080,
            db_path: "./webpwn.db".to_string(),
            api_port: 3000,
            threads: num_cpus::get(),
        }
    }
}
