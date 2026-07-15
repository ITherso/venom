use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SharePermission {
    View,
    Comment,
    Edit,
    Share,
    Download,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanShare {
    pub id: String,
    pub scan_id: String,
    pub shared_by: String,
    pub shared_with: String,
    pub permission: SharePermission,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub is_active: bool,
}

impl ScanShare {
    pub fn new(
        scan_id: String,
        shared_by: String,
        shared_with: String,
        permission: SharePermission,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            scan_id,
            shared_by,
            shared_with,
            permission,
            created_at: Utc::now(),
            expires_at: None,
            is_active: true,
        }
    }

    pub fn with_expiry(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    pub fn is_expired(&self) -> bool {
        if let Some(expiry) = self.expires_at {
            Utc::now() > expiry
        } else {
            false
        }
    }

    pub fn can_view(&self) -> bool {
        self.is_active
            && !self.is_expired()
            && matches!(
                self.permission,
                SharePermission::View
                    | SharePermission::Comment
                    | SharePermission::Edit
                    | SharePermission::Share
                    | SharePermission::Download
            )
    }

    pub fn can_comment(&self) -> bool {
        self.is_active
            && !self.is_expired()
            && matches!(
                self.permission,
                SharePermission::Comment
                    | SharePermission::Edit
                    | SharePermission::Share
                    | SharePermission::Download
            )
    }

    pub fn can_edit(&self) -> bool {
        self.is_active
            && !self.is_expired()
            && matches!(
                self.permission,
                SharePermission::Edit | SharePermission::Share | SharePermission::Download
            )
    }

    pub fn can_share(&self) -> bool {
        self.is_active && !self.is_expired() && matches!(self.permission, SharePermission::Share)
    }

    pub fn can_download(&self) -> bool {
        self.is_active
            && !self.is_expired()
            && matches!(self.permission, SharePermission::Download)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareManager {
    pub shares: HashMap<String, ScanShare>,
}

impl ShareManager {
    pub fn new() -> Self {
        Self {
            shares: HashMap::new(),
        }
    }

    pub fn add_share(&mut self, share: ScanShare) {
        self.shares.insert(share.id.clone(), share);
    }

    pub fn remove_share(&mut self, share_id: &str) -> Option<ScanShare> {
        self.shares.remove(share_id)
    }

    pub fn get_share(&self, share_id: &str) -> Option<&ScanShare> {
        self.shares.get(share_id)
    }

    pub fn get_shares_for_scan(&self, scan_id: &str) -> Vec<&ScanShare> {
        self.shares
            .values()
            .filter(|s| s.scan_id == scan_id && s.is_active)
            .collect()
    }

    pub fn get_shares_for_user(&self, user_id: &str) -> Vec<&ScanShare> {
        self.shares
            .values()
            .filter(|s| s.shared_with == user_id && s.is_active && !s.is_expired())
            .collect()
    }

    pub fn revoke_share(&mut self, share_id: &str) -> bool {
        if let Some(share) = self.shares.get_mut(share_id) {
            share.is_active = false;
            true
        } else {
            false
        }
    }

    pub fn revoke_all_shares(&mut self, scan_id: &str) {
        for share in self.shares.values_mut() {
            if share.scan_id == scan_id {
                share.is_active = false;
            }
        }
    }

    pub fn cleanup_expired(&mut self) {
        self.shares.retain(|_, share| !share.is_expired());
    }
}

impl Default for ShareManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_share_creation() {
        let share = ScanShare::new(
            "scan1".to_string(),
            "user1".to_string(),
            "user2".to_string(),
            SharePermission::View,
        );
        assert!(share.is_active);
        assert!(share.can_view());
    }

    #[test]
    fn test_share_permissions() {
        let view_share = ScanShare::new(
            "scan1".to_string(),
            "user1".to_string(),
            "user2".to_string(),
            SharePermission::View,
        );

        assert!(view_share.can_view());
        assert!(!view_share.can_edit());
        assert!(!view_share.can_share());

        let edit_share = ScanShare::new(
            "scan1".to_string(),
            "user1".to_string(),
            "user2".to_string(),
            SharePermission::Edit,
        );

        assert!(edit_share.can_view());
        assert!(edit_share.can_edit());
        assert!(!edit_share.can_share());
    }

    #[test]
    fn test_share_manager() {
        let mut manager = ShareManager::new();
        let share = ScanShare::new(
            "scan1".to_string(),
            "user1".to_string(),
            "user2".to_string(),
            SharePermission::View,
        );

        manager.add_share(share);
        assert_eq!(manager.shares.len(), 1);
    }

    #[test]
    fn test_revoke_share() {
        let mut manager = ShareManager::new();
        let share = ScanShare::new(
            "scan1".to_string(),
            "user1".to_string(),
            "user2".to_string(),
            SharePermission::View,
        );

        let share_id = share.id.clone();
        manager.add_share(share);

        assert!(manager.revoke_share(&share_id));
        let revoked = manager.get_share(&share_id).unwrap();
        assert!(!revoked.is_active);
    }
}
