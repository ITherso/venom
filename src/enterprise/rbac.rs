use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Permission {
    Read,
    Write,
    Delete,
    Execute,
    Admin,
    Audit,
    UserManagement,
    RoleManagement,
    BackupRestore,
    DisasterRecovery,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub id: String,
    pub name: String,
    pub description: String,
    pub permissions: HashSet<Permission>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Role {
    pub fn new(name: String, description: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            description,
            permissions: HashSet::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    pub fn add_permission(&mut self, permission: Permission) {
        self.permissions.insert(permission);
        self.updated_at = Utc::now();
    }

    pub fn remove_permission(&mut self, permission: &Permission) {
        self.permissions.remove(permission);
        self.updated_at = Utc::now();
    }

    pub fn has_permission(&self, permission: &Permission) -> bool {
        self.permissions.contains(permission) || self.permissions.contains(&Permission::Admin)
    }

    pub fn add_permissions(&mut self, permissions: Vec<Permission>) {
        for perm in permissions {
            self.permissions.insert(perm);
        }
        self.updated_at = Utc::now();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subject {
    pub id: String,
    pub name: String,
    pub subject_type: SubjectType,
    pub roles: Vec<String>,
    pub direct_permissions: HashSet<Permission>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SubjectType {
    User,
    ServiceAccount,
    Group,
}

impl Subject {
    pub fn new(name: String, subject_type: SubjectType) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            subject_type,
            roles: Vec::new(),
            direct_permissions: HashSet::new(),
            is_active: true,
            created_at: Utc::now(),
        }
    }

    pub fn add_role(&mut self, role_id: String) {
        if !self.roles.contains(&role_id) {
            self.roles.push(role_id);
        }
    }

    pub fn remove_role(&mut self, role_id: &str) {
        self.roles.retain(|r| r != role_id);
    }

    pub fn add_permission(&mut self, permission: Permission) {
        self.direct_permissions.insert(permission);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RBACManager {
    roles: HashMap<String, Role>,
    subjects: HashMap<String, Subject>,
    role_hierarchy: HashMap<String, Vec<String>>,
}

impl RBACManager {
    pub fn new() -> Self {
        let mut manager = Self {
            roles: HashMap::new(),
            subjects: HashMap::new(),
            role_hierarchy: HashMap::new(),
        };

        manager.create_default_roles();
        manager
    }

    fn create_default_roles(&mut self) {
        // Admin role
        let mut admin_role = Role::new("Admin".to_string(), "Full system access".to_string());
        admin_role.add_permission(Permission::Admin);
        self.roles.insert(admin_role.id.clone(), admin_role);

        // Security Analyst role
        let mut analyst_role = Role::new("SecurityAnalyst".to_string(), "Security analysis and auditing".to_string());
        analyst_role.add_permissions(vec![
            Permission::Read,
            Permission::Execute,
            Permission::Audit,
        ]);
        self.roles.insert(analyst_role.id.clone(), analyst_role);

        // Operator role
        let mut operator_role = Role::new("Operator".to_string(), "System operation and monitoring".to_string());
        operator_role.add_permissions(vec![
            Permission::Read,
            Permission::Write,
            Permission::Execute,
            Permission::BackupRestore,
        ]);
        self.roles.insert(operator_role.id.clone(), operator_role);

        // Auditor role
        let mut auditor_role = Role::new("Auditor".to_string(), "Audit and compliance".to_string());
        auditor_role.add_permissions(vec![
            Permission::Read,
            Permission::Audit,
        ]);
        self.roles.insert(auditor_role.id.clone(), auditor_role);

        // User role
        let mut user_role = Role::new("User".to_string(), "Standard user access".to_string());
        user_role.add_permission(Permission::Read);
        self.roles.insert(user_role.id.clone(), user_role);
    }

    pub fn create_role(&mut self, name: String, description: String) -> String {
        let role = Role::new(name, description);
        let role_id = role.id.clone();
        self.roles.insert(role_id.clone(), role);
        role_id
    }

    pub fn get_role(&self, role_id: &str) -> Option<&Role> {
        self.roles.get(role_id)
    }

    pub fn get_role_mut(&mut self, role_id: &str) -> Option<&mut Role> {
        self.roles.get_mut(role_id)
    }

    pub fn get_role_by_name(&self, name: &str) -> Option<&Role> {
        self.roles.values().find(|r| r.name == name)
    }

    pub fn delete_role(&mut self, role_id: &str) -> bool {
        self.roles.remove(role_id).is_some()
    }

    pub fn create_subject(&mut self, name: String, subject_type: SubjectType) -> String {
        let subject = Subject::new(name, subject_type);
        let subject_id = subject.id.clone();
        self.subjects.insert(subject_id.clone(), subject);
        subject_id
    }

    pub fn get_subject(&self, subject_id: &str) -> Option<&Subject> {
        self.subjects.get(subject_id)
    }

    pub fn get_subject_mut(&mut self, subject_id: &str) -> Option<&mut Subject> {
        self.subjects.get_mut(subject_id)
    }

    pub fn assign_role(&mut self, subject_id: &str, role_id: &str) -> bool {
        if let Some(subject) = self.get_subject_mut(subject_id) {
            subject.add_role(role_id.to_string());
            true
        } else {
            false
        }
    }

    pub fn revoke_role(&mut self, subject_id: &str, role_id: &str) -> bool {
        if let Some(subject) = self.get_subject_mut(subject_id) {
            subject.remove_role(role_id);
            true
        } else {
            false
        }
    }

    pub fn has_permission(&self, subject_id: &str, permission: &Permission) -> bool {
        if let Some(subject) = self.get_subject(subject_id) {
            if !subject.is_active {
                return false;
            }

            // Check direct permissions
            if subject.direct_permissions.contains(permission) {
                return true;
            }

            // Check role permissions
            for role_id in &subject.roles {
                if let Some(role) = self.get_role(role_id) {
                    if role.has_permission(permission) {
                        return true;
                    }
                }
            }
        }
        false
    }

    pub fn get_subject_permissions(&self, subject_id: &str) -> HashSet<Permission> {
        let mut permissions = HashSet::new();

        if let Some(subject) = self.get_subject(subject_id) {
            // Direct permissions
            for perm in &subject.direct_permissions {
                permissions.insert(perm.clone());
            }

            // Role permissions
            for role_id in &subject.roles {
                if let Some(role) = self.get_role(role_id) {
                    for perm in &role.permissions {
                        permissions.insert(perm.clone());
                    }
                }
            }
        }

        permissions
    }

    pub fn list_roles(&self) -> Vec<&Role> {
        self.roles.values().collect()
    }

    pub fn list_subjects(&self) -> Vec<&Subject> {
        self.subjects.values().collect()
    }

    pub fn deactivate_subject(&mut self, subject_id: &str) -> bool {
        if let Some(subject) = self.get_subject_mut(subject_id) {
            subject.is_active = false;
            true
        } else {
            false
        }
    }

    pub fn get_statistics(&self) -> RBACStatistics {
        RBACStatistics {
            total_roles: self.roles.len(),
            total_subjects: self.subjects.len(),
            active_subjects: self.subjects.values().filter(|s| s.is_active).count(),
            users: self.subjects.values().filter(|s| s.subject_type == SubjectType::User).count(),
            service_accounts: self.subjects.values().filter(|s| s.subject_type == SubjectType::ServiceAccount).count(),
        }
    }
}

impl Default for RBACManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RBACStatistics {
    pub total_roles: usize,
    pub total_subjects: usize,
    pub active_subjects: usize,
    pub users: usize,
    pub service_accounts: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_creation() {
        let role = Role::new("Test".to_string(), "Test role".to_string());
        assert_eq!(role.name, "Test");
    }

    #[test]
    fn test_add_permission() {
        let mut role = Role::new("Test".to_string(), "Test role".to_string());
        role.add_permission(Permission::Read);
        assert!(role.has_permission(&Permission::Read));
    }

    #[test]
    fn test_rbac_manager_creation() {
        let manager = RBACManager::new();
        assert!(!manager.list_roles().is_empty());
    }

    #[test]
    fn test_create_subject_and_assign_role() {
        let mut manager = RBACManager::new();
        let subject_id = manager.create_subject("testuser".to_string(), SubjectType::User);
        let role = manager.get_role_by_name("Operator").unwrap();
        manager.assign_role(&subject_id, &role.id);

        assert!(manager.has_permission(&subject_id, &Permission::Read));
    }

    #[test]
    fn test_permission_check() {
        let mut manager = RBACManager::new();
        let subject_id = manager.create_subject("testuser".to_string(), SubjectType::User);
        let admin_role = manager.get_role_by_name("Admin").unwrap();
        manager.assign_role(&subject_id, &admin_role.id);

        assert!(manager.has_permission(&subject_id, &Permission::Admin));
    }

    #[test]
    fn test_deactivate_subject() {
        let mut manager = RBACManager::new();
        let subject_id = manager.create_subject("testuser".to_string(), SubjectType::User);
        manager.deactivate_subject(&subject_id);

        assert!(!manager.has_permission(&subject_id, &Permission::Read));
    }
}
