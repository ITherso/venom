// VENOM API - REST/GraphQL endpoints for scan management
use axum::{routing::get, Router};
use venom_core::Result;

pub async fn health() -> &'static str {
    "OK"
}

pub fn router() -> Router {
    Router::new().route("/health", get(health))
}

pub async fn start_api(addr: &str) -> Result<()> {
    println!("API starting on {}", addr);
    Ok(())
}
