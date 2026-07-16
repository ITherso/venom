// VENOM Core - Shared models, error types, and utilities
pub mod error;
pub mod models;

pub use error::{Error, Result};

#[derive(Debug)]
pub struct Config {
    pub target: String,
    pub aggressive: bool,
    pub timeout_secs: u64,
}
