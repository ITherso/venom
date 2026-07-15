pub mod updater;
pub mod exploit_db;
pub mod sources;

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

pub use updater::ZeroDayUpdater;
pub use exploit_db::{ExploitDatabase, Exploit};
pub use sources::{DataSource, SourceType};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZeroDayFeed {
    pub id: String,
    pub name: String,
    pub url: String,
    pub source_type: SourceType,
    pub update_frequency: UpdateFrequency,
    pub last_updated: Option<DateTime<Utc>>,
    pub exploit_count: usize,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UpdateFrequency {
    Hourly,
    Daily,
    Weekly,
    Monthly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZeroDayMetrics {
    pub total_exploits: usize,
    pub exploits_this_week: usize,
    pub exploits_this_month: usize,
    pub active_feeds: usize,
    pub last_update: Option<DateTime<Utc>>,
    pub update_success_rate: f32,
}

impl ZeroDayFeed {
    pub fn new(name: String, url: String, source_type: SourceType) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            url,
            source_type,
            update_frequency: UpdateFrequency::Daily,
            last_updated: None,
            exploit_count: 0,
            is_active: true,
        }
    }

    pub fn with_frequency(mut self, frequency: UpdateFrequency) -> Self {
        self.update_frequency = frequency;
        self
    }

    pub fn should_update(&self) -> bool {
        if !self.is_active {
            return false;
        }

        if let Some(last_update) = self.last_updated {
            let duration = Utc::now() - last_update;
            match self.update_frequency {
                UpdateFrequency::Hourly => duration.num_hours() >= 1,
                UpdateFrequency::Daily => duration.num_days() >= 1,
                UpdateFrequency::Weekly => duration.num_weeks() >= 1,
                UpdateFrequency::Monthly => duration.num_days() >= 30,
            }
        } else {
            true
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZeroDayManager {
    pub feeds: HashMap<String, ZeroDayFeed>,
    pub database: ExploitDatabase,
}

impl ZeroDayManager {
    pub fn new() -> Self {
        Self {
            feeds: HashMap::new(),
            database: ExploitDatabase::new(),
        }
    }

    pub fn add_feed(&mut self, feed: ZeroDayFeed) {
        self.feeds.insert(feed.id.clone(), feed);
    }

    pub fn get_feed(&self, feed_id: &str) -> Option<&ZeroDayFeed> {
        self.feeds.get(feed_id)
    }

    pub fn get_feed_mut(&mut self, feed_id: &str) -> Option<&mut ZeroDayFeed> {
        self.feeds.get_mut(feed_id)
    }

    pub fn remove_feed(&mut self, feed_id: &str) -> Option<ZeroDayFeed> {
        self.feeds.remove(feed_id)
    }

    pub fn enable_feed(&mut self, feed_id: &str) -> bool {
        if let Some(feed) = self.get_feed_mut(feed_id) {
            feed.is_active = true;
            true
        } else {
            false
        }
    }

    pub fn disable_feed(&mut self, feed_id: &str) -> bool {
        if let Some(feed) = self.get_feed_mut(feed_id) {
            feed.is_active = false;
            true
        } else {
            false
        }
    }

    pub fn feeds_requiring_update(&self) -> Vec<&ZeroDayFeed> {
        self.feeds.values().filter(|f| f.should_update()).collect()
    }

    pub fn get_metrics(&self) -> ZeroDayMetrics {
        let now = Utc::now();
        let week_ago = now - chrono::Duration::days(7);
        let month_ago = now - chrono::Duration::days(30);

        let exploits_this_week = self
            .database
            .list_exploits()
            .iter()
            .filter(|e| e.discovered_date > week_ago)
            .count();

        let exploits_this_month = self
            .database
            .list_exploits()
            .iter()
            .filter(|e| e.discovered_date > month_ago)
            .count();

        ZeroDayMetrics {
            total_exploits: self.database.exploit_count(),
            exploits_this_week,
            exploits_this_month,
            active_feeds: self.feeds.values().filter(|f| f.is_active).count(),
            last_update: self.feeds.values().filter_map(|f| f.last_updated).max(),
            update_success_rate: 0.95,
        }
    }
}

impl Default for ZeroDayManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feed_creation() {
        let feed = ZeroDayFeed::new(
            "ExploitDB".to_string(),
            "https://exploitdb.com".to_string(),
            SourceType::ExploitDB,
        );

        assert_eq!(feed.name, "ExploitDB");
        assert!(feed.is_active);
    }

    #[test]
    fn test_feed_should_update() {
        let feed = ZeroDayFeed::new(
            "Test".to_string(),
            "http://test.com".to_string(),
            SourceType::ExploitDB,
        );

        assert!(feed.should_update());
    }

    #[test]
    fn test_zero_day_manager() {
        let mut manager = ZeroDayManager::new();
        let feed = ZeroDayFeed::new(
            "Test".to_string(),
            "http://test.com".to_string(),
            SourceType::ExploitDB,
        );

        let feed_id = feed.id.clone();
        manager.add_feed(feed);

        assert!(manager.get_feed(&feed_id).is_some());
    }

    #[test]
    fn test_feed_enable_disable() {
        let mut manager = ZeroDayManager::new();
        let feed = ZeroDayFeed::new(
            "Test".to_string(),
            "http://test.com".to_string(),
            SourceType::ExploitDB,
        );

        let feed_id = feed.id.clone();
        manager.add_feed(feed);

        assert!(manager.disable_feed(&feed_id));
        assert!(!manager.get_feed(&feed_id).unwrap().is_active);

        assert!(manager.enable_feed(&feed_id));
        assert!(manager.get_feed(&feed_id).unwrap().is_active);
    }
}
