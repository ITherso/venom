use crate::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use super::tasks::TaskManager;

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateTaskRequest {
    pub task_type: String,
    pub target: String,
    pub payload: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateTaskResponse {
    pub task_id: String,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UpdateTaskRequest {
    pub status: String,
    pub progress: Option<f32>,
    pub output: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse<T: Serialize> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

pub struct ApiHandlers {
    pub task_manager: Arc<TaskManager>,
}

impl ApiHandlers {
    pub fn new(task_manager: Arc<TaskManager>) -> Self {
        Self { task_manager }
    }

    /// Create new task
    pub async fn create_task(&self, req: CreateTaskRequest) -> Result<CreateTaskResponse> {
        let task_id = self
            .task_manager
            .create_task(&req.task_type, &req.target, req.payload)
            .await?;

        Ok(CreateTaskResponse {
            task_id,
            status: "pending".to_string(),
        })
    }

    /// Get task
    pub async fn get_task(&self, task_id: &str) -> Result<Option<super::tasks::Task>> {
        self.task_manager.get_task(task_id).await
    }

    /// List all tasks
    pub async fn list_tasks(&self) -> Result<Vec<super::tasks::Task>> {
        self.task_manager.list_tasks().await
    }

    /// Update task
    pub async fn update_task(
        &self,
        task_id: &str,
        req: UpdateTaskRequest,
    ) -> Result<()> {
        self.task_manager
            .update_task_status(task_id, &req.status, req.progress.unwrap_or(0.0))
            .await?;

        if let Some(output) = req.output {
            self.task_manager.set_task_output(task_id, output).await?;
        }

        if let Some(error) = req.error {
            self.task_manager.set_task_error(task_id, error).await?;
        }

        Ok(())
    }

    /// Get task statistics
    pub async fn get_stats(&self) -> Result<super::tasks::TaskStats> {
        self.task_manager.get_stats().await
    }

    /// Get tasks by status
    pub async fn get_tasks_by_status(&self, status: &str) -> Result<Vec<super::tasks::Task>> {
        self.task_manager.get_tasks_by_status(status).await
    }

    /// Health check
    pub async fn health_check(&self) -> Result<HealthResponse> {
        Ok(HealthResponse {
            status: "ok".to_string(),
            version: "0.5.0".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        })
    }
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub timestamp: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_task_handler() {
        let task_manager = Arc::new(TaskManager::new());
        let handlers = ApiHandlers::new(task_manager);

        let req = CreateTaskRequest {
            task_type: "scan".to_string(),
            target: "http://example.com".to_string(),
            payload: None,
        };

        let resp = handlers.create_task(req).await.unwrap();
        assert_eq!(resp.status, "pending");
        assert!(!resp.task_id.is_empty());
    }

    #[tokio::test]
    async fn test_health_check() {
        let task_manager = Arc::new(TaskManager::new());
        let handlers = ApiHandlers::new(task_manager);

        let health = handlers.health_check().await.unwrap();
        assert_eq!(health.status, "ok");
    }
}
