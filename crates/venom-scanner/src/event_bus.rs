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

/// Event data with complete metadata including versioning and correlation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Event type (ScanStarted, FindingFound, etc.)
    pub event_type: EventType,

    /// Event schema version (allows evolution: v1, v2, v3)
    pub version: u16,

    /// Unix timestamp in milliseconds (precise for dashboard/replay/metrics)
    pub timestamp_ms: u64,

    /// Correlation ID (scan_id to link all events from same scan)
    pub correlation_id: String,

    /// Event source (component that emitted: scanner, proxy, worker, plugin)
    pub source: String,

    /// Custom event data as key-value pairs
    pub data: std::collections::HashMap<String, String>,

    /// Event severity level
    pub severity: EventSeverity,

    /// Unique event ID (for deduplication and tracking)
    pub event_id: String,
}

impl Event {
    /// Creates new event with auto-generated timestamp and event ID
    pub fn new(event_type: EventType, source: impl Into<String>) -> Self {
        Self {
            event_type,
            version: 1,
            timestamp_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            correlation_id: uuid::Uuid::new_v4().to_string(),
            source: source.into(),
            data: std::collections::HashMap::new(),
            severity: EventSeverity::Info,
            event_id: uuid::Uuid::new_v4().to_string(),
        }
    }

    /// Creates event builder for fluent API
    pub fn builder(event_type: EventType, source: impl Into<String>) -> EventBuilder {
        EventBuilder::new(event_type, source)
    }

    /// Sets correlation ID (links events from same scan)
    pub fn with_correlation_id(mut self, scan_id: impl Into<String>) -> Self {
        self.correlation_id = scan_id.into();
        self
    }

    /// Adds custom data field
    pub fn with_data(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.data.insert(key.into(), value.into());
        self
    }

    /// Sets event severity
    pub fn with_severity(mut self, severity: EventSeverity) -> Self {
        self.severity = severity;
        self
    }

    /// Sets event version (for schema evolution)
    pub fn with_version(mut self, version: u16) -> Self {
        self.version = version;
        self
    }

    /// Gets timestamp as readable string
    pub fn timestamp_str(&self) -> String {
        let secs = self.timestamp_ms / 1000;
        let millis = self.timestamp_ms % 1000;
        format!("{}.{:03}", secs, millis)
    }
}

/// Builder for creating events with fluent API
pub struct EventBuilder {
    event_type: EventType,
    version: u16,
    timestamp_ms: u64,
    correlation_id: String,
    source: String,
    data: std::collections::HashMap<String, String>,
    severity: EventSeverity,
    event_id: String,
}

impl EventBuilder {
    /// Creates new builder
    pub fn new(event_type: EventType, source: impl Into<String>) -> Self {
        Self {
            event_type,
            version: 1,
            timestamp_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            correlation_id: uuid::Uuid::new_v4().to_string(),
            source: source.into(),
            data: std::collections::HashMap::new(),
            severity: EventSeverity::Info,
            event_id: uuid::Uuid::new_v4().to_string(),
        }
    }

    /// Sets correlation ID (scan ID)
    pub fn correlation_id(mut self, scan_id: impl Into<String>) -> Self {
        self.correlation_id = scan_id.into();
        self
    }

    /// Sets event version
    pub fn version(mut self, version: u16) -> Self {
        self.version = version;
        self
    }

    /// Adds custom data
    pub fn data(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.data.insert(key.into(), value.into());
        self
    }

    /// Sets severity
    pub fn severity(mut self, severity: EventSeverity) -> Self {
        self.severity = severity;
        self
    }

    /// Sets custom timestamp (ms since epoch)
    pub fn timestamp_ms(mut self, ms: u64) -> Self {
        self.timestamp_ms = ms;
        self
    }

    /// Builds the event
    pub fn build(self) -> Event {
        Event {
            event_type: self.event_type,
            version: self.version,
            timestamp_ms: self.timestamp_ms,
            correlation_id: self.correlation_id,
            source: self.source,
            data: self.data,
            severity: self.severity,
            event_id: self.event_id,
        }
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

    /// Gets all events for a specific correlation ID (scan)
    pub fn get_events_by_correlation(
        &self,
        correlation_id: &str,
    ) -> Vec<Event> {
        self.get_all_events()
            .into_iter()
            .filter(|e| e.correlation_id == correlation_id)
            .collect()
    }

    /// Gets events for correlation ID within time range (ms)
    pub fn get_events_by_correlation_and_time(
        &self,
        correlation_id: &str,
        start_ms: u64,
        end_ms: u64,
    ) -> Vec<Event> {
        self.get_all_events()
            .into_iter()
            .filter(|e| {
                e.correlation_id == correlation_id
                    && e.timestamp_ms >= start_ms
                    && e.timestamp_ms <= end_ms
            })
            .collect()
    }

    /// Gets all events sorted by timestamp
    pub fn get_events_sorted(&self) -> Vec<Event> {
        let mut events = self.get_all_events();
        events.sort_by(|a, b| a.timestamp_ms.cmp(&b.timestamp_ms));
        events
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
        assert_eq!(event.version, 1);
        assert!(!event.correlation_id.is_empty());
        assert!(!event.event_id.is_empty());
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
    fn test_event_versioning() {
        let event = Event::new(EventType::ScanStarted, "scanner")
            .with_version(2);

        assert_eq!(event.version, 2);
    }

    #[test]
    fn test_event_correlation_id() {
        let scan_id = "scan_12345";
        let event = Event::new(EventType::FindingFound, "scanner")
            .with_correlation_id(scan_id);

        assert_eq!(event.correlation_id, scan_id);
    }

    #[test]
    fn test_event_builder() {
        let scan_id = "scan_abc";
        let event = Event::builder(EventType::ScanStarted, "scanner")
            .correlation_id(scan_id)
            .version(1)
            .severity(EventSeverity::Info)
            .data("target", "http://example.com")
            .build();

        assert_eq!(event.correlation_id, scan_id);
        assert_eq!(event.version, 1);
        assert_eq!(event.severity, EventSeverity::Info);
        assert_eq!(event.data.get("target"), Some(&"http://example.com".to_string()));
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

    #[test]
    fn test_events_by_correlation_id() {
        let bus = EventBus::new();
        let scan_id = "scan_001";

        // Create events for same scan
        bus.publish(Event::new(EventType::ScanStarted, "test")
            .with_correlation_id(scan_id));
        bus.publish(Event::new(EventType::FindingFound, "test")
            .with_correlation_id(scan_id));
        bus.publish(Event::new(EventType::FindingFound, "test")
            .with_correlation_id(scan_id));

        // Create events for different scan
        bus.publish(Event::new(EventType::ScanStarted, "test")
            .with_correlation_id("scan_002"));

        let events = bus.get_events_by_correlation(scan_id);
        assert_eq!(events.len(), 3);
        assert!(events.iter().all(|e| e.correlation_id == scan_id));
    }

    #[test]
    fn test_events_by_correlation_and_time() {
        let bus = EventBus::new();
        let scan_id = "scan_001";
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        // Event at current time
        let event1 = Event::builder(EventType::ScanStarted, "test")
            .correlation_id(scan_id)
            .timestamp_ms(now)
            .build();
        bus.publish(event1);

        // Event 1 second later
        let event2 = Event::builder(EventType::FindingFound, "test")
            .correlation_id(scan_id)
            .timestamp_ms(now + 1000)
            .build();
        bus.publish(event2);

        // Query events within time range
        let events = bus.get_events_by_correlation_and_time(scan_id, now, now + 1000);
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn test_events_sorted_by_timestamp() {
        let bus = EventBus::new();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        // Add events in random order
        bus.publish(Event::builder(EventType::FindingFound, "test")
            .timestamp_ms(now + 2000)
            .build());
        bus.publish(Event::builder(EventType::ScanStarted, "test")
            .timestamp_ms(now)
            .build());
        bus.publish(Event::builder(EventType::WorkerFinished, "test")
            .timestamp_ms(now + 1000)
            .build());

        let sorted = bus.get_events_sorted();
        assert_eq!(sorted.len(), 3);
        assert!(sorted[0].timestamp_ms <= sorted[1].timestamp_ms);
        assert!(sorted[1].timestamp_ms <= sorted[2].timestamp_ms);
    }

    #[test]
    fn test_event_uniqueness() {
        let event1 = Event::new(EventType::ScanStarted, "test");
        let event2 = Event::new(EventType::ScanStarted, "test");

        // Each event has unique ID and correlation ID
        assert_ne!(event1.event_id, event2.event_id);
        assert_ne!(event1.correlation_id, event2.correlation_id);
    }

    #[test]
    fn test_timestamp_str() {
        let event = Event::builder(EventType::ScanStarted, "test")
            .timestamp_ms(1234567890123)
            .build();

        assert_eq!(event.timestamp_str(), "1234567890.123");
    }
}
