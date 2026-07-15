use crate::Result;
use axum::{
    extract::{Path, State, Json},
    http::StatusCode,
    routing::{get, post, put},
    Router,
};
use serde_json::json;
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::cors::CorsLayer;

use super::handlers::{ApiHandlers, CreateTaskRequest, UpdateTaskRequest};
use super::tasks::TaskManager;
use super::websocket::WebSocketBroadcaster;

pub struct ApiServer {
    host: String,
    port: u16,
    task_manager: Arc<TaskManager>,
    broadcaster: Arc<WebSocketBroadcaster>,
    handlers: Arc<ApiHandlers>,
}

impl ApiServer {
    pub fn new(host: &str, port: u16) -> Self {
        let task_manager = Arc::new(TaskManager::new());
        let broadcaster = Arc::new(WebSocketBroadcaster::new(1000));
        let handlers = Arc::new(ApiHandlers::new(Arc::clone(&task_manager)));

        Self {
            host: host.to_string(),
            port,
            task_manager,
            broadcaster,
            handlers,
        }
    }

    pub async fn start(&self) -> Result<()> {
        let app = self.build_router();
        let addr = format!("{}:{}", self.host, self.port)
            .parse::<std::net::SocketAddr>()
            .map_err(|e| crate::Error::ProxyError(format!("Invalid address: {}", e)))?;

        println!("[+] API Server starting on http://{}", addr);

        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| crate::Error::ProxyError(format!("Bind error: {}", e)))?;

        axum::serve(listener, app)
            .await
            .map_err(|e| crate::Error::ProxyError(format!("Server error: {}", e)))?;

        Ok(())
    }

    fn build_router(&self) -> Router {
        let task_manager = Arc::clone(&self.task_manager);
        let handlers = Arc::clone(&self.handlers);
        let broadcaster = Arc::clone(&self.broadcaster);

        Router::new()
            .route("/api/health", get(health_check))
            .route("/api/tasks", post(create_task))
            .route("/api/tasks", get(list_tasks))
            .route("/api/tasks/:task_id", get(get_task))
            .route("/api/tasks/:task_id", put(update_task))
            .route("/api/tasks/status/:status", get(get_tasks_by_status))
            .route("/api/stats", get(get_stats))
            .with_state((task_manager, handlers, broadcaster))
            .layer(ServiceBuilder::new().layer(CorsLayer::permissive()))
    }

    pub fn get_broadcaster(&self) -> Arc<WebSocketBroadcaster> {
        Arc::clone(&self.broadcaster)
    }

    pub fn get_task_manager(&self) -> Arc<TaskManager> {
        Arc::clone(&self.task_manager)
    }
}

// Handlers
async fn health_check(
    State((_, handlers, _)): State<(Arc<TaskManager>, Arc<ApiHandlers>, Arc<WebSocketBroadcaster>)>,
) -> (StatusCode, Json<serde_json::Value>) {
    match handlers.health_check().await {
        Ok(health) => (
            StatusCode::OK,
            Json(json!({
                "success": true,
                "data": health,
                "error": null
            })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "data": null,
                "error": e.to_string()
            })),
        ),
    }
}

async fn create_task(
    State((_, handlers, broadcaster)): State<(Arc<TaskManager>, Arc<ApiHandlers>, Arc<WebSocketBroadcaster>)>,
    Json(req): Json<CreateTaskRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    match handlers.create_task(req).await {
        Ok(resp) => {
            let _ = broadcaster.broadcast_task_update(&resp.task_id, "created", 0.0);
            (
                StatusCode::CREATED,
                Json(json!({
                    "success": true,
                    "data": resp,
                    "error": null
                })),
            )
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "data": null,
                "error": e.to_string()
            })),
        ),
    }
}

async fn list_tasks(
    State((_, handlers, _)): State<(Arc<TaskManager>, Arc<ApiHandlers>, Arc<WebSocketBroadcaster>)>,
) -> (StatusCode, Json<serde_json::Value>) {
    match handlers.list_tasks().await {
        Ok(tasks) => (
            StatusCode::OK,
            Json(json!({
                "success": true,
                "data": tasks,
                "error": null
            })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "data": null,
                "error": e.to_string()
            })),
        ),
    }
}

async fn get_task(
    State((_, handlers, _)): State<(Arc<TaskManager>, Arc<ApiHandlers>, Arc<WebSocketBroadcaster>)>,
    Path(task_id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    match handlers.get_task(&task_id).await {
        Ok(Some(task)) => (
            StatusCode::OK,
            Json(json!({
                "success": true,
                "data": task,
                "error": null
            })),
        ),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "success": false,
                "data": null,
                "error": "Task not found"
            })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "data": null,
                "error": e.to_string()
            })),
        ),
    }
}

async fn update_task(
    State((_, handlers, broadcaster)): State<(Arc<TaskManager>, Arc<ApiHandlers>, Arc<WebSocketBroadcaster>)>,
    Path(task_id): Path<String>,
    Json(req): Json<UpdateTaskRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    match handlers.update_task(&task_id, req.clone()).await {
        Ok(_) => {
            let _ = broadcaster.broadcast_task_update(
                &task_id,
                &req.status,
                req.progress.unwrap_or(0.0),
            );
            (
                StatusCode::OK,
                Json(json!({
                    "success": true,
                    "data": { "task_id": task_id },
                    "error": null
                })),
            )
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "data": null,
                "error": e.to_string()
            })),
        ),
    }
}

async fn get_tasks_by_status(
    State((_, handlers, _)): State<(Arc<TaskManager>, Arc<ApiHandlers>, Arc<WebSocketBroadcaster>)>,
    Path(status): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    match handlers.get_tasks_by_status(&status).await {
        Ok(tasks) => (
            StatusCode::OK,
            Json(json!({
                "success": true,
                "data": tasks,
                "error": null
            })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "data": null,
                "error": e.to_string()
            })),
        ),
    }
}

async fn get_stats(
    State((_, handlers, _)): State<(Arc<TaskManager>, Arc<ApiHandlers>, Arc<WebSocketBroadcaster>)>,
) -> (StatusCode, Json<serde_json::Value>) {
    match handlers.get_stats().await {
        Ok(stats) => (
            StatusCode::OK,
            Json(json!({
                "success": true,
                "data": stats,
                "error": null
            })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "data": null,
                "error": e.to_string()
            })),
        ),
    }
}
