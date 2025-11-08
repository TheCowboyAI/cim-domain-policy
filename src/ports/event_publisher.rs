//! Event publisher port - defines the interface for publishing policy events

use crate::events::PolicyEvent;
use async_trait::async_trait;
use cim_domain::DomainEvent;
use thiserror::Error;
use uuid::Uuid;

/// Errors that can occur during event publishing
#[derive(Debug, Error)]
pub enum PublishError {
    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Publishing error: {0}")]
    Publishing(String),
}

/// Errors that can occur during event querying
#[derive(Debug, Error)]
pub enum QueryError {
    #[error("Query error: {0}")]
    Query(String),

    #[error("Deserialization error: {0}")]
    Deserialization(String),
}

/// Port for publishing policy events
///
/// This trait defines the interface that event publishers must implement.
/// It follows the hexagonal architecture pattern, allowing different
/// implementations (NATS, Kafka, in-memory, etc.) without changing the domain logic.
#[async_trait]
pub trait EventPublisher: Send + Sync {
    /// Publish a single policy event
    async fn publish(&self, event: &PolicyEvent) -> Result<(), PublishError>;

    /// Publish multiple events in a batch
    async fn publish_batch(&self, events: &[PolicyEvent]) -> Result<(), PublishError>;

    /// Query events by correlation ID
    async fn query_by_correlation(&self, correlation_id: Uuid) -> Result<Vec<PolicyEvent>, QueryError>;

    /// Query events by aggregate ID
    async fn query_by_aggregate(&self, aggregate_id: Uuid) -> Result<Vec<PolicyEvent>, QueryError>;

    /// Query events within a time range
    async fn query_by_time_range(
        &self,
        start: chrono::DateTime<chrono::Utc>,
        end: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<PolicyEvent>, QueryError>;
}

/// Helper function to convert a policy event to a NATS subject
///
/// Subject pattern: events.policy.{aggregate_id}.{event_type}
///
/// Examples:
/// - events.policy.550e8400-e29b-41d4-a716-446655440000.created
/// - events.policy.550e8400-e29b-41d4-a716-446655440000.approved
/// - events.policy.550e8400-e29b-41d4-a716-446655440000.activated
pub fn event_to_subject(event: &PolicyEvent) -> String {
    let aggregate_id = event.aggregate_id();
    let event_type = event.event_type().to_lowercase();

    format!("events.policy.{}.{}", aggregate_id, event_type)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{PolicyCreated, PolicyEvent};
    use crate::value_objects::PolicyId;
    use chrono::Utc;
    use cim_domain::MessageIdentity;

    #[test]
    fn test_event_to_subject() {
        let policy_id = PolicyId::new();
        let event = PolicyEvent::PolicyCreated(PolicyCreated {
            event_id: Uuid::now_v7(),
            identity: MessageIdentity::new(),
            policy_id,
            name: "Test Policy".to_string(),
            description: "Test Description".to_string(),
            policy_type: "Access".to_string(),
            created_by: "test-user".to_string(),
            created_at: Utc::now(),
        });

        let subject = event_to_subject(&event);
        assert!(subject.starts_with("events.policy."));
        assert!(subject.ends_with(".policycreated"));
    }
}
