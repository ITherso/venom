use crate::Result;
use super::metrics::MetricsCollector;
use super::prometheus::PrometheusExporter;
use axum::{
    extract::State,
    response::IntoResponse,
    routing::get,
    Router,
    http::StatusCode,
};
use std::sync::Arc;

pub struct MetricsExporter {
    metrics: Arc<MetricsCollector>,
    host: String,
    port: u16,
}

impl MetricsExporter {
    pub fn new(metrics: Arc<MetricsCollector>, host: &str, port: u16) -> Self {
        Self {
            metrics,
            host: host.to_string(),
            port,
        }
    }

    pub async fn start(&self) -> Result<()> {
        let metrics = Arc::clone(&self.metrics);

        let app = Router::new()
            .route("/metrics", get(metrics_handler))
            .route("/health", get(health_handler))
            .route("/summary", get(summary_handler))
            .with_state(metrics);

        let addr = format!("{}:{}", self.host, self.port)
            .parse::<std::net::SocketAddr>()
            .map_err(|e| crate::Error::ProxyError(format!("Invalid address: {}", e)))?;

        println!("[+] Metrics Exporter listening on http://{}", addr);
        println!("[+] Prometheus metrics at: http://{}/metrics", addr);
        println!("[+] Health check at: http://{}/health", addr);
        println!("[+] Summary at: http://{}/summary", addr);

        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| crate::Error::ProxyError(format!("Bind error: {}", e)))?;

        axum::serve(listener, app)
            .await
            .map_err(|e| crate::Error::ProxyError(format!("Server error: {}", e)))?;

        Ok(())
    }
}

// Handler functions
async fn metrics_handler(
    State(metrics): State<Arc<MetricsCollector>>,
) -> impl IntoResponse {
    let exporter = PrometheusExporter::new((*metrics).clone());
    (StatusCode::OK, exporter.export())
}

async fn health_handler() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

async fn summary_handler(
    State(metrics): State<Arc<MetricsCollector>>,
) -> impl IntoResponse {
    (StatusCode::OK, metrics.summary())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_exporter_creation() {
        let collector = MetricsCollector::new();
        let _exporter = MetricsExporter::new(Arc::new(collector), "127.0.0.1", 9090);
    }

    #[tokio::test]
    async fn test_metrics_handler() {
        let metrics = Arc::new(MetricsCollector::new());
        metrics.proxy.record_request();

        let exporter = PrometheusExporter::new((*metrics).clone());
        let output = exporter.export();

        assert!(output.contains("venom_proxy_requests_total 1"));
    }
}
