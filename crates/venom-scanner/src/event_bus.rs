//! Event Bus - Publish/Subscribe Event System
//!
//! Central event infrastructure for scanning lifecycle and plugin coordination.

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::any::Any;

/// Event types in the scanning lifecycle
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EventType {
    #[serde(rename = "scan_started")]
    ScanStarted,
    #[serde(rename = "scan_completed")]
    ScanCompleted,
    #[serde(rename = "scan_failed")]
    ScanFailed,
    #[serde(rename = "finding_found")]
    FindingFound,
    #[serde(rename = "finding_dismissed")]
    FindingDismissed,
    #[serde(rename = "proxy_request")]
    ProxyRequest,
    #[serde(rename = "proxy_response")]
    ProxyResponse,
    #[serde(rename = "worker_started")]
    WorkerStarted,
    #[serde(rename = "worker_finished")]
    WorkerFinished,
    #[serde(rename = "worker_failed")]
    WorkerFailed,
    #[serde(rename = "plugin_loaded")]
    PluginLoaded,
    #[serde(rename = "plugin_executed")]
    PluginExecuted,
    #[serde(rename = "phase_started")]
    PhaseStarted,
    #[serde(rename = "phase_completed")]
    PhaseCompleted,
    #[serde(rename = "alert_triggered")]
    AlertTriggered,
    #[serde(rename = "config_reloaded")]
    ConfigReloaded,
}

impl EventType {
    pub fn as_str(&self) -> &str {
        match self {
            EventType::ScanStarted => "scan_started",
            EventType::ScanCompleted => "scan_completed",
            EventType::ScanFailed => "scan_failed",
            EventType::FindingFound => "finding_found",
            EventType::FindingDismissed => "finding_dismissed",
            EventType::ProxyRequest => "proxy_request",
            EventType::ProxyResponse => "proxy_response",
            EventType::WorkerStarted => "worker_started",
            EventType::WorkerFinished => "worker_finished",
            EventType::WorkerFailed => "worker_failed",
            EventType::PluginLoaded => "plugin_loaded",
            EventType::PluginExecuted => "plugin_executed",
            EventType::PhaseStarted => "phase_started",
            EventType::PhaseCompleted => "phase_completed",
            EventType::AlertTriggered => "alert_triggered",
            EventType::ConfigReloaded => "config_reloaded",
        }
    }
}

/// Event data with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub event_type: EventType,
    pub timestamp: u64,
    pub source: String,
    pub data: std::collections::HashMap<String, String>,
    pub severity: EventSeverity,
}

impl Event {
    pub fn new(event_type: EventType, source: impl Into<String>) -> Self {
        Self {
            event_type,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            source: source.into(),
            data: std::collections::HashMap::new(),
            severity: EventSeverity::Info,
        }
    }

    pub fn with_data(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.data.insert(key.into(), value.into());
        self
    }

    pub fn with_severity(mut self, severity: EventSeverity) -> Self {
        self.severity = severity;
        self
    }
}

/// Event severity levels
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum EventSeverity {
    #[serde(rename = "debug")]
    Debug = 0,
    #[serde(rename = "info")]
    Info = 1,
    #[serde(rename = "warning")]
    Warning = 2,
    #[serde(rename = "error")]
    Error = 3,
    #[serde(rename = "critical")]
    Critical = 4,
}

/// Event handler callback type
pub type EventHandler = Arc<dyn Fn(&Event) + Send + Sync>;

/// Event subscription
pub struct Subscription {
    pub event_type: EventType,
    pub handler_id: String,
}

/// Event Bus - Central publish/subscribe system
pub struct EventBus {
    subscribers: Arc<DashMap<EventType, Vec<(String, EventHandler)>>>,
    event_history: Arc<DashMap<String, Vec<Event>>>,
    event_count: Arc<std::sync::atomic::AtomicU64>,
}

impl EventBus {
    /// Creates new event bus
    pub fn new() -> Self {
        Self {
            subscribers: Arc::new(DashMap::new()),
            event_history: Arc::new(DashMap::new()),
            event_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Subscribes to an event type
    pub fn subscribe(
        &self,
        event_type: EventType,
        handler_id: impl Into<String>,
        handler: EventHandler,
    ) {
        let handler_id = handler_id.into();
        self.subscribers
            .entry(event_type.clone())
            .or_insert_with(Vec::new)
            .push((handler_id, handler));
    }

    /// Unsubscribes from an event type
    pub fn unsubscribe(&self, event_type: &EventType, handler_id: &str) {
        if let Some(mut handlers) = self.subscribers.get_mut(event_type) {
            handlers.retain(|(id, _)| id != handler_id);
        }
    }

    /// Publishes event to all subscribers
    pub fn publish(&self, event: Event) {
        self.event_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        // Store in history
        self.event_history
            .entry(event.event_type.as_str().to_string())
            .or_insert_with(Vec::new)
            .push(event.clone());

        // Call subscribers
        if let Some(handlers) = self.subscribers.get(&event.event_type) {
            for (_, handler) in handlers.iter() {
                handler(&event);
            }
        }
    }

    /// Gets subscriber count for event type
    pub fn subscriber_count(&self, event_type: &EventType) -> usize {
        self.subscribers
            .get(event_type)
            .map(|h| h.len())
            .unwrap_or(0)
    }

    /// Gets event history for type
    pub fn get_history(&self, event_type: &EventType) -> Vec<Event> {
        self.event_history
            .get(event_type.as_str())
            .map(|h| h.clone())
            .unwrap_or_default()
    }

    /// Gets total event count
    pub fn total_events(&self) -> u64 {
        self.event_count.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Clears event history
    pub fn clear_history(&self) {
        self.event_history.clear();
    }

    /// Gets all events
    pub fn get_all_events(&self) -> Vec<Event> {
        self.event_history
            .iter()
            .flat_map(|ref_multi| ref_multi.value().clone())
            .collect()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::sync::Mutex;

    #[test]
    fn test_event_creation() {
        let event = Event::new(EventType::ScanStarted, "scanner");
        assert_eq!(event.event_type, EventType::ScanStarted);
        assert_eq!(event.source, "scanner");
    }

    #[test]
    fn test_event_with_data() {
        let event = Event::new(EventType::FindingFound, "plugin")
            .with_data("severity", "HIGH")
            .with_data("type", "XSS");

        assert_eq!(event.data.get("severity"), Some(&"HIGH".to_string()));
        assert_eq!(event.data.get("type"), Some(&"XSS".to_string()));
    }

    #[test]
    fn test_event_severity() {
        let event = Event::new(EventType::ScanFailed, "worker")
            .with_severity(EventSeverity::Critical);

        assert_eq!(event.severity, EventSeverity::Critical);
    }

    #[test]
    fn test_event_bus_creation() {
        let bus = EventBus::new();
        assert_eq!(bus.total_events(), 0);
    }

    #[test]
    fn test_event_publishing() {
        let bus = EventBus::new();
        let event = Event::new(EventType::ScanStarted, "test");

        bus.publish(event);
        assert_eq!(bus.total_events(), 1);
    }

    #[test]
    fn test_event_subscription() {
        let bus = EventBus::new();
        let called = Arc::new(AtomicBool::new(false));
        let called_clone = called.clone();

        bus.subscribe(
            EventType::ScanStarted,
            "test_handler",
            Arc::new(move |_| {
                called_clone.store(true, std::sync::atomic::Ordering::SeqCst);
            }),
        );

        assert_eq!(bus.subscriber_count(&EventType::ScanStarted), 1);

        let event = Event::new(EventType::ScanStarted, "test");
        bus.publish(event);

        assert!(called.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn test_multiple_subscribers() {
        let bus = EventBus::new();
        let count = Arc::new(std::sync::atomic::AtomicU32::new(0));

        for i in 0..3 {
            let count_clone = count.clone();
            bus.subscribe(
                EventType::FindingFound,
                format!("handler_{}", i),
                Arc::new(move |_| {
                    count_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }),
            );
        }

        assert_eq!(bus.subscriber_count(&EventType::FindingFound), 3);

        let event = Event::new(EventType::FindingFound, "test");
        bus.publish(event);

        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 3);
    }

    #[test]
    fn test_event_unsubscribe() {
        let bus = EventBus::new();

        bus.subscribe(
            EventType::ScanCompleted,
            "handler1",
            Arc::new(|_| {}),
        );
        bus.subscribe(
            EventType::ScanCompleted,
            "handler2",
            Arc::new(|_| {}),
        );

        assert_eq!(bus.subscriber_count(&EventType::ScanCompleted), 2);

        bus.unsubscribe(&EventType::ScanCompleted, "handler1");
        assert_eq!(bus.subscriber_count(&EventType::ScanCompleted), 1);
    }

    #[test]
    fn test_event_history() {
        let bus = EventBus::new();

        for i in 0..5 {
            let event = Event::new(EventType::WorkerFinished, format!("worker_{}", i));
            bus.publish(event);
        }

        let history = bus.get_history(&EventType::WorkerFinished);
        assert_eq!(history.len(), 5);
    }

    #[test]
    fn test_event_severity_ordering() {
        assert!(EventSeverity::Critical > EventSeverity::Error);
        assert!(EventSeverity::Error > EventSeverity::Warning);
        assert!(EventSeverity::Warning > EventSeverity::Info);
        assert!(EventSeverity::Info > EventSeverity::Debug);
    }

    #[test]
    fn test_get_all_events() {
        let bus = EventBus::new();

        bus.publish(Event::new(EventType::ScanStarted, "test"));
        bus.publish(Event::new(EventType::FindingFound, "test"));
        bus.publish(Event::new(EventType::WorkerFinished, "test"));

        let all = bus.get_all_events();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_clear_history() {
        let bus = EventBus::new();

        bus.publish(Event::new(EventType::ScanStarted, "test"));
        bus.publish(Event::new(EventType::FindingFound, "test"));

        assert!(bus.total_events() > 0);

        bus.clear_history();
        assert_eq!(bus.get_all_events().len(), 0);
    }
}
