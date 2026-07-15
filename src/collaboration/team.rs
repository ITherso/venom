use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TeamRole {
    Owner,
    Admin,
    Member,
    Viewer,
}

impl Default for TeamRole {
    fn default() -> Self {
        TeamRole::Member
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Team {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub owner_id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub members: HashMap<String, TeamMember>,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamMember {
    pub user_id: String,
    pub role: TeamRole,
    pub joined_at: DateTime<Utc>,
    pub last_active: Option<DateTime<Utc>>,
}

impl Team {
    pub fn new(name: String, owner_id: String) -> Self {
        let mut team = Self {
            id: Uuid::new_v4().to_string(),
            name,
            description: None,
            owner_id: owner_id.clone(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            members: HashMap::new(),
            is_active: true,
        };

        team.members.insert(
            owner_id.clone(),
            TeamMember {
                user_id: owner_id,
                role: TeamRole::Owner,
                joined_at: Utc::now(),
                last_active: None,
            },
        );

        team
    }

    pub fn add_member(&mut self, user_id: String, role: TeamRole) -> bool {
        if !self.members.contains_key(&user_id) {
            self.members.insert(
                user_id.clone(),
                TeamMember {
                    user_id,
                    role,
                    joined_at: Utc::now(),
                    last_active: None,
                },
            );
            self.updated_at = Utc::now();
            true
        } else {
            false
        }
    }

    pub fn remove_member(&mut self, user_id: &str) -> bool {
        if self.members.remove(user_id).is_some() {
            self.updated_at = Utc::now();
            true
        } else {
            false
        }
    }

    pub fn update_member_role(&mut self, user_id: &str, role: TeamRole) -> bool {
        if let Some(member) = self.members.get_mut(user_id) {
            member.role = role;
            self.updated_at = Utc::now();
            true
        } else {
            false
        }
    }

    pub fn get_member(&self, user_id: &str) -> Option<&TeamMember> {
        self.members.get(user_id)
    }

    pub fn member_count(&self) -> usize {
        self.members.len()
    }

    pub fn can_manage_members(&self, user_id: &str) -> bool {
        if let Some(member) = self.get_member(user_id) {
            matches!(member.role, TeamRole::Owner | TeamRole::Admin)
        } else {
            false
        }
    }

    pub fn can_view_scans(&self, user_id: &str) -> bool {
        self.members.contains_key(user_id)
    }

    pub fn can_run_scans(&self, user_id: &str) -> bool {
        if let Some(member) = self.get_member(user_id) {
            matches!(member.role, TeamRole::Owner | TeamRole::Admin | TeamRole::Member)
        } else {
            false
        }
    }

    pub fn with_description(mut self, description: String) -> Self {
        self.description = Some(description);
        self
    }
}

impl TeamMember {
    pub fn update_activity(&mut self) {
        self.last_active = Some(Utc::now());
    }

    pub fn is_owner(&self) -> bool {
        matches!(self.role, TeamRole::Owner)
    }

    pub fn is_admin(&self) -> bool {
        matches!(self.role, TeamRole::Admin)
    }

    pub fn is_privileged(&self) -> bool {
        matches!(self.role, TeamRole::Owner | TeamRole::Admin)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_team_creation() {
        let team = Team::new("Security Team".to_string(), "user1".to_string());
        assert_eq!(team.name, "Security Team");
        assert_eq!(team.member_count(), 1);
    }

    #[test]
    fn test_add_member() {
        let mut team = Team::new("Security Team".to_string(), "user1".to_string());
        assert!(team.add_member("user2".to_string(), TeamRole::Member));
        assert_eq!(team.member_count(), 2);
    }

    #[test]
    fn test_duplicate_member() {
        let mut team = Team::new("Security Team".to_string(), "user1".to_string());
        assert!(team.add_member("user2".to_string(), TeamRole::Member));
        assert!(!team.add_member("user2".to_string(), TeamRole::Admin));
    }

    #[test]
    fn test_remove_member() {
        let mut team = Team::new("Security Team".to_string(), "user1".to_string());
        team.add_member("user2".to_string(), TeamRole::Member);
        assert!(team.remove_member("user2"));
        assert_eq!(team.member_count(), 1);
    }

    #[test]
    fn test_role_management() {
        let mut team = Team::new("Security Team".to_string(), "user1".to_string());
        team.add_member("user2".to_string(), TeamRole::Member);

        assert!(team.update_member_role("user2", TeamRole::Admin));
        assert_eq!(
            team.get_member("user2").unwrap().role,
            TeamRole::Admin
        );
    }

    #[test]
    fn test_permissions() {
        let team = Team::new("Security Team".to_string(), "user1".to_string());
        assert!(team.can_manage_members("user1"));
        assert!(!team.can_manage_members("user2"));
    }
}
