use crate::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub id: String,
    pub task_type: String, // "scan", "exploit", "payloadgen", "c2_command"
    pub status: String,     // "pending", "running", "completed", "failed"
    pub target: String,
    pub payload: Option<String>,
    pub output: Option<String>,
    pub error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub progress: f32, // 0.0 - 1.0
}

pub struct TaskManager {
    tasks: Arc<RwLock<HashMap<String, Task>>>,
}

impl TaskManager {
    pub fn new() -> Self {
        Self {
            tasks: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create new task
    pub async fn create_task(
        &self,
        task_type: &str,
        target: &str,
        payload: Option<String>,
    ) -> Result<String> {
        let task_id = uuid::Uuid::new_v4().to_string();
        let task = Task {
            id: task_id.clone(),
            task_type: task_type.to_string(),
            status: "pending".to_string(),
            target: target.to_string(),
            payload,
            output: None,
            error: None,
            created_at: Utc::now(),
            started_at: None,
            completed_at: None,
            progress: 0.0,
        };

        let mut tasks = self.tasks.write().await;
        tasks.insert(task_id.clone(), task);

        Ok(task_id)
    }

    /// Get task by ID
    pub async fn get_task(&self, task_id: &str) -> Result<Option<Task>> {
        let tasks = self.tasks.read().await;
        Ok(tasks.get(task_id).cloned())
    }

    /// List all tasks
    pub async fn list_tasks(&self) -> Result<Vec<Task>> {
        let tasks = self.tasks.read().await;
        Ok(tasks.values().cloned().collect())
    }

    /// Update task status
    pub async fn update_task_status(
        &self,
        task_id: &str,
        status: &str,
        progress: f32,
    ) -> Result<()> {
        let mut tasks = self.tasks.write().await;
        if let Some(task) = tasks.get_mut(task_id) {
            task.status = status.to_string();
            task.progress = progress.min(1.0);

            if status == "running" && task.started_at.is_none() {
                task.started_at = Some(Utc::now());
            }

            if status == "completed" || status == "failed" {
                task.completed_at = Some(Utc::now());
            }
        }

        Ok(())
    }

    /// Set task output
    pub async fn set_task_output(&self, task_id: &str, output: String) -> Result<()> {
        let mut tasks = self.tasks.write().await;
        if let Some(task) = tasks.get_mut(task_id) {
            task.output = Some(output);
        }
        Ok(())
    }

    /// Set task error
    pub async fn set_task_error(&self, task_id: &str, error: String) -> Result<()> {
        let mut tasks = self.tasks.write().await;
        if let Some(task) = tasks.get_mut(task_id) {
            task.error = Some(error);
        }
        Ok(())
    }

    /// Get tasks by status
    pub async fn get_tasks_by_status(&self, status: &str) -> Result<Vec<Task>> {
        let tasks = self.tasks.read().await;
        Ok(tasks
            .values()
            .filter(|t| t.status == status)
            .cloned()
            .collect())
    }

    /// Get tasks by type
    pub async fn get_tasks_by_type(&self, task_type: &str) -> Result<Vec<Task>> {
        let tasks = self.tasks.read().await;
        Ok(tasks
            .values()
            .filter(|t| t.task_type == task_type)
            .cloned()
            .collect())
    }

    /// Delete completed tasks
    pub async fn cleanup_old_tasks(&self) -> Result<usize> {
        let mut tasks = self.tasks.write().await;
        let before_count = tasks.len();

        tasks.retain(|_, task| {
            if task.status == "completed" || task.status == "failed" {
                if let Some(completed_at) = task.completed_at {
                    let age = Utc::now().signed_duration_since(completed_at);
                    age.num_hours() < 24 // Keep tasks for 24 hours
                } else {
                    true
                }
            } else {
                true
            }
        });

        Ok(before_count - tasks.len())
    }

    /// Get task statistics
    pub async fn get_stats(&self) -> Result<TaskStats> {
        let tasks = self.tasks.read().await;

        let total = tasks.len();
        let pending = tasks.values().filter(|t| t.status == "pending").count();
        let running = tasks.values().filter(|t| t.status == "running").count();
        let completed = tasks.values().filter(|t| t.status == "completed").count();
        let failed = tasks.values().filter(|t| t.status == "failed").count();

        Ok(TaskStats {
            total,
            pending,
            running,
            completed,
            failed,
            success_rate: if completed + failed > 0 {
                (completed as f32) / ((completed + failed) as f32)
            } else {
                0.0
            },
        })
    }
}

#[derive(Debug, Serialize)]
pub struct TaskStats {
    pub total: usize,
    pub pending: usize,
    pub running: usize,
    pub completed: usize,
    pub failed: usize,
    pub success_rate: f32,
}

impl Default for TaskManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_task_creation() {
        let manager = TaskManager::new();
        let task_id = manager
            .create_task("scan", "http://example.com", None)
            .await
            .unwrap();

        assert!(!task_id.is_empty());

        let task = manager.get_task(&task_id).await.unwrap();
        assert!(task.is_some());
        assert_eq!(task.unwrap().status, "pending");
    }

    #[tokio::test]
    async fn test_task_status_update() {
        let manager = TaskManager::new();
        let task_id = manager
            .create_task("scan", "http://example.com", None)
            .await
            .unwrap();

        manager
            .update_task_status(&task_id, "running", 0.5)
            .await
            .unwrap();

        let task = manager.get_task(&task_id).await.unwrap().unwrap();
        assert_eq!(task.status, "running");
        assert_eq!(task.progress, 0.5);
    }
}
