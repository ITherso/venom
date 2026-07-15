use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Permission {
    // Scan permissions
    ViewScans,
    CreateScans,
    EditScans,
    DeleteScans,
    RunScans,
    ExportScans,

    // Team permissions
    ManageTeam,
    ManageMembers,
    ManageRoles,
    ViewTeamScans,

    // Report permissions
    GenerateReports,
    ExportReports,
    ShareReports,

    // Admin permissions
    ManageUsers,
    ManageTeams,
    SystemSettings,
    ViewLogs,
    ManageApiKeys,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionSet {
    permissions: HashSet<Permission>,
}

impl PermissionSet {
    pub fn new() -> Self {
        Self {
            permissions: HashSet::new(),
        }
    }

    pub fn viewer() -> Self {
        let mut set = Self::new();
        set.grant(Permission::ViewScans);
        set
    }

    pub fn member() -> Self {
        let mut set = Self::viewer();
        set.grant(Permission::CreateScans);
        set.grant(Permission::RunScans);
        set.grant(Permission::ViewTeamScans);
        set
    }

    pub fn admin() -> Self {
        let mut set = Self::member();
        set.grant(Permission::EditScans);
        set.grant(Permission::DeleteScans);
        set.grant(Permission::ExportScans);
        set.grant(Permission::GenerateReports);
        set.grant(Permission::ExportReports);
        set.grant(Permission::ManageTeam);
        set.grant(Permission::ManageMembers);
        set.grant(Permission::ManageRoles);
        set
    }

    pub fn owner() -> Self {
        let mut set = Self::admin();
        set.grant(Permission::ManageUsers);
        set.grant(Permission::ManageTeams);
        set.grant(Permission::SystemSettings);
        set.grant(Permission::ViewLogs);
        set.grant(Permission::ManageApiKeys);
        set.grant(Permission::ShareReports);
        set
    }

    pub fn grant(&mut self, permission: Permission) {
        self.permissions.insert(permission);
    }

    pub fn revoke(&mut self, permission: &Permission) {
        self.permissions.remove(permission);
    }

    pub fn has(&self, permission: &Permission) -> bool {
        self.permissions.contains(permission)
    }

    pub fn has_all(&self, permissions: &[Permission]) -> bool {
        permissions.iter().all(|p| self.has(p))
    }

    pub fn has_any(&self, permissions: &[Permission]) -> bool {
        permissions.iter().any(|p| self.has(p))
    }

    pub fn list(&self) -> Vec<&Permission> {
        self.permissions.iter().collect()
    }

    pub fn merge(&mut self, other: &PermissionSet) {
        for perm in &other.permissions {
            self.grant(perm.clone());
        }
    }

    pub fn clear(&mut self) {
        self.permissions.clear();
    }
}

impl Default for PermissionSet {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessControl {
    pub user_permissions: std::collections::HashMap<String, PermissionSet>,
}

impl AccessControl {
    pub fn new() -> Self {
        Self {
            user_permissions: std::collections::HashMap::new(),
        }
    }

    pub fn grant_permissions(&mut self, user_id: String, permissions: PermissionSet) {
        self.user_permissions.insert(user_id, permissions);
    }

    pub fn has_permission(&self, user_id: &str, permission: &Permission) -> bool {
        self.user_permissions
            .get(user_id)
            .map(|ps| ps.has(permission))
            .unwrap_or(false)
    }

    pub fn get_permissions(&self, user_id: &str) -> Option<&PermissionSet> {
        self.user_permissions.get(user_id)
    }

    pub fn revoke_user(&mut self, user_id: &str) {
        self.user_permissions.remove(user_id);
    }
}

impl Default for AccessControl {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permission_set_creation() {
        let perms = PermissionSet::viewer();
        assert!(perms.has(&Permission::ViewScans));
        assert!(!perms.has(&Permission::CreateScans));
    }

    #[test]
    fn test_member_permissions() {
        let perms = PermissionSet::member();
        assert!(perms.has(&Permission::ViewScans));
        assert!(perms.has(&Permission::CreateScans));
        assert!(perms.has(&Permission::RunScans));
        assert!(!perms.has(&Permission::ManageTeam));
    }

    #[test]
    fn test_admin_permissions() {
        let perms = PermissionSet::admin();
        assert!(perms.has(&Permission::EditScans));
        assert!(perms.has(&Permission::DeleteScans));
        assert!(perms.has(&Permission::ManageTeam));
        assert!(!perms.has(&Permission::ManageUsers));
    }

    #[test]
    fn test_grant_revoke() {
        let mut perms = PermissionSet::new();
        assert!(!perms.has(&Permission::ViewScans));

        perms.grant(Permission::ViewScans);
        assert!(perms.has(&Permission::ViewScans));

        perms.revoke(&Permission::ViewScans);
        assert!(!perms.has(&Permission::ViewScans));
    }

    #[test]
    fn test_has_all() {
        let mut perms = PermissionSet::new();
        perms.grant(Permission::ViewScans);
        perms.grant(Permission::CreateScans);

        assert!(perms.has_all(&[
            Permission::ViewScans,
            Permission::CreateScans
        ]));
        assert!(!perms.has_all(&[
            Permission::ViewScans,
            Permission::EditScans
        ]));
    }

    #[test]
    fn test_access_control() {
        let mut ac = AccessControl::new();
        let perms = PermissionSet::member();

        ac.grant_permissions("user1".to_string(), perms);
        assert!(ac.has_permission("user1", &Permission::ViewScans));
        assert!(!ac.has_permission("user1", &Permission::ManageTeam));
    }
}
