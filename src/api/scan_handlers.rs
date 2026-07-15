use axum::{
    extract::{Path, State, Query},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRequest {
    pub target: String,
    pub scan_type: String,
    pub intensity: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStatus {
    pub id: String,
    pub target: String,
    pub status: String,
    pub progress: u32,
    pub findings: u32,
    pub vulnerabilities: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingsSummary {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub info: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryParams {
    pub status: Option<String>,
    pub severity: Option<String>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

#[derive(Clone)]
pub struct ScanState {
    pub scans: std::sync::Arc<tokio::sync::RwLock<HashMap<String, ScanStatus>>>,
    pub findings: std::sync::Arc<tokio::sync::RwLock<HashMap<String, Vec<ScanFinding>>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanFinding {
    pub id: String,
    pub scan_id: String,
    pub title: String,
    pub severity: String,
    pub description: String,
    pub cvss_score: f32,
}

impl ScanState {
    pub fn new() -> Self {
        Self {
            scans: std::sync::Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            findings: std::sync::Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }
}

pub async fn start_scan(
    State(state): State<ScanState>,
    Json(payload): Json<ScanRequest>,
) -> impl IntoResponse {
    let scan_id = uuid::Uuid::new_v4().to_string();

    let scan = ScanStatus {
        id: scan_id.clone(),
        target: payload.target,
        status: "running".to_string(),
        progress: 0,
        findings: 0,
        vulnerabilities: 0,
    };

    let mut scans = state.scans.write().await;
    scans.insert(scan_id.clone(), scan);

    (
        StatusCode::ACCEPTED,
        Json(json!({
            "scan_id": scan_id,
            "status": "started"
        })),
    )
}

pub async fn get_scan_status(
    State(state): State<ScanState>,
    Path(scan_id): Path<String>,
) -> impl IntoResponse {
    let scans = state.scans.read().await;

    match scans.get(&scan_id) {
        Some(scan) => (
            StatusCode::OK,
            Json(json!({
                "id": scan.id,
                "target": scan.target,
                "status": scan.status,
                "progress": scan.progress,
                "findings": scan.findings,
                "vulnerabilities": scan.vulnerabilities
            })),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Scan not found"})),
        ),
    }
}

pub async fn list_scans(
    State(state): State<ScanState>,
    Query(params): Query<QueryParams>,
) -> impl IntoResponse {
    let scans = state.scans.read().await;
    let limit = params.limit.unwrap_or(10).min(100) as usize;
    let offset = params.offset.unwrap_or(0) as usize;

    let mut scan_list: Vec<_> = scans
        .values()
        .filter(|s| {
            if let Some(ref status_filter) = params.status {
                s.status == *status_filter
            } else {
                true
            }
        })
        .skip(offset)
        .take(limit)
        .map(|s| {
            json!({
                "id": s.id,
                "target": s.target,
                "status": s.status,
                "progress": s.progress
            })
        })
        .collect();

    (
        StatusCode::OK,
        Json(json!({
            "scans": scan_list,
            "total": scans.len(),
            "limit": limit,
            "offset": offset
        })),
    )
}

pub async fn cancel_scan(
    State(state): State<ScanState>,
    Path(scan_id): Path<String>,
) -> impl IntoResponse {
    let mut scans = state.scans.write().await;

    if let Some(scan) = scans.get_mut(&scan_id) {
        scan.status = "cancelled".to_string();
        (
            StatusCode::OK,
            Json(json!({
                "status": "cancelled",
                "scan_id": scan_id
            })),
        )
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Scan not found"})),
        )
    }
}

pub async fn get_findings(
    State(state): State<ScanState>,
    Path(scan_id): Path<String>,
    Query(params): Query<QueryParams>,
) -> impl IntoResponse {
    let findings = state.findings.read().await;

    if let Some(scan_findings) = findings.get(&scan_id) {
        let filtered: Vec<_> = scan_findings
            .iter()
            .filter(|f| {
                if let Some(ref severity) = params.severity {
                    f.severity == *severity
                } else {
                    true
                }
            })
            .map(|f| {
                json!({
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity,
                    "cvss_score": f.cvss_score
                })
            })
            .collect();

        (StatusCode::OK, Json(json!({ "findings": filtered })))
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Scan not found"})),
        )
    }
}

pub async fn get_findings_summary(
    State(state): State<ScanState>,
    Path(scan_id): Path<String>,
) -> impl IntoResponse {
    let findings = state.findings.read().await;

    if let Some(scan_findings) = findings.get(&scan_id) {
        let mut summary = FindingsSummary {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
        };

        for finding in scan_findings {
            match finding.severity.as_str() {
                "critical" => summary.critical += 1,
                "high" => summary.high += 1,
                "medium" => summary.medium += 1,
                "low" => summary.low += 1,
                "info" => summary.info += 1,
                _ => {}
            }
        }

        (StatusCode::OK, Json(serde_json::to_value(summary).unwrap()))
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Scan not found"})),
        )
    }
}

pub async fn export_scan_results(
    State(state): State<ScanState>,
    Path((scan_id, format)): Path<(String, String)>,
) -> impl IntoResponse {
    let scans = state.scans.read().await;
    let findings = state.findings.read().await;

    if let Some(scan) = scans.get(&scan_id) {
        let export_data = match format.as_str() {
            "json" => {
                json!({
                    "scan_id": scan.id,
                    "target": scan.target,
                    "status": scan.status,
                    "findings": findings.get(&scan_id).unwrap_or(&vec![])
                })
            }
            "csv" => {
                json!({
                    "format": "csv",
                    "message": "Export data available"
                })
            }
            _ => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "Unsupported format"})),
                ).into_response()
            }
        };

        (StatusCode::OK, Json(export_data)).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Scan not found"})),
        ).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_state_creation() {
        let state = ScanState::new();
        assert!(state.scans.try_read().is_ok());
    }

    #[test]
    fn test_findings_summary() {
        let summary = FindingsSummary {
            critical: 2,
            high: 5,
            medium: 10,
            low: 20,
            info: 100,
        };

        assert_eq!(summary.critical, 2);
    }
}
