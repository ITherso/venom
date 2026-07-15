pub mod team;
pub mod sharing;
pub mod permissions;

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

pub use team::{Team, TeamMember, TeamRole};
pub use sharing::{ScanShare, SharePermission};
pub use permissions::{PermissionSet, Permission};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: String,
    pub created_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
    pub api_key: Option<String>,
    pub is_active: bool,
}

impl User {
    pub fn new(username: String, email: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            username,
            email,
            created_at: Utc::now(),
            last_login: None,
            api_key: None,
            is_active: true,
        }
    }

    pub fn generate_api_key() -> String {
        Uuid::new_v4().to_string()
    }

    pub fn update_last_login(&mut self) {
        self.last_login = Some(Utc::now());
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanMetadata {
    pub id: String,
    pub owner_id: String,
    pub team_id: Option<String>,
    pub name: String,
    pub description: Option<String>,
    pub target: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub status: ScanStatus,
    pub visibility: ScanVisibility,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScanStatus {
    Created,
    Running,
    Paused,
    Completed,
    Failed,
    Archived,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScanVisibility {
    Private,
    TeamOnly,
    Shared,
    Public,
}

impl ScanMetadata {
    pub fn new(owner_id: String, name: String, target: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            owner_id,
            team_id: None,
            name,
            description: None,
            target,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            status: ScanStatus::Created,
            visibility: ScanVisibility::Private,
            tags: Vec::new(),
        }
    }

    pub fn with_team(mut self, team_id: String) -> Self {
        self.team_id = Some(team_id);
        self
    }

    pub fn with_visibility(mut self, visibility: ScanVisibility) -> Self {
        self.visibility = visibility;
        self
    }

    pub fn with_description(mut self, description: String) -> Self {
        self.description = Some(description);
        self
    }

    pub fn add_tag(&mut self, tag: String) {
        if !self.tags.contains(&tag) {
            self.tags.push(tag);
        }
    }

    pub fn mark_complete(&mut self) {
        self.status = ScanStatus::Completed;
        self.updated_at = Utc::now();
    }

    pub fn mark_failed(&mut self) {
        self.status = ScanStatus::Failed;
        self.updated_at = Utc::now();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollaborationEvent {
    pub id: String,
    pub scan_id: String,
    pub user_id: String,
    pub event_type: EventType,
    pub timestamp: DateTime<Utc>,
    pub details: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventType {
    ScanCreated,
    ScanShared,
    ScanUnshared,
    ScanViewed,
    ScanModified,
    CommentAdded,
    FindingMarked,
    ReportGenerated,
}

impl CollaborationEvent {
    pub fn new(scan_id: String, user_id: String, event_type: EventType) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            scan_id,
            user_id,
            event_type,
            timestamp: Utc::now(),
            details: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanComment {
    pub id: String,
    pub scan_id: String,
    pub user_id: String,
    pub content: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub replies: Vec<String>,
}

impl ScanComment {
    pub fn new(scan_id: String, user_id: String, content: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            scan_id,
            user_id,
            content,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            replies: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_creation() {
        let user = User::new("testuser".to_string(), "test@example.com".to_string());
        assert_eq!(user.username, "testuser");
        assert!(user.is_active);
    }

    #[test]
    fn test_scan_metadata_creation() {
        let scan = ScanMetadata::new(
            "user1".to_string(),
            "Test Scan".to_string(),
            "https://example.com".to_string(),
        );
        assert_eq!(scan.status, ScanStatus::Created);
        assert_eq!(scan.visibility, ScanVisibility::Private);
    }

    #[test]
    fn test_scan_visibility_change() {
        let scan = ScanMetadata::new(
            "user1".to_string(),
            "Test Scan".to_string(),
            "https://example.com".to_string(),
        )
        .with_visibility(ScanVisibility::Shared);

        assert_eq!(scan.visibility, ScanVisibility::Shared);
    }

    #[test]
    fn test_scan_tagging() {
        let mut scan = ScanMetadata::new(
            "user1".to_string(),
            "Test Scan".to_string(),
            "https://example.com".to_string(),
        );

        scan.add_tag("critical".to_string());
        scan.add_tag("api".to_string());

        assert_eq!(scan.tags.len(), 2);
        assert!(scan.tags.contains(&"critical".to_string()));
    }
}
