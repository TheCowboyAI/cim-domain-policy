//! NATS JetStream integration for policy event sourcing

use crate::events::PolicyEvent;
use async_nats::jetstream::{self, stream::Stream};
use cim_domain::DomainEvent;
use futures::StreamExt;
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

/// Errors that can occur during NATS operations
#[derive(Debug, Error)]
pub enum NatsError {
    #[error("NATS connection error: {0}")]
    Connection(String),

    #[error("JetStream error: {0}")]
    JetStream(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Event not found: {0}")]
    EventNotFound(String),
}

impl From<async_nats::Error> for NatsError {
    fn from(err: async_nats::Error) -> Self {
        NatsError::Connection(err.to_string())
    }
}

impl From<async_nats::jetstream::context::CreateStreamError> for NatsError {
    fn from(err: async_nats::jetstream::context::CreateStreamError) -> Self {
        NatsError::JetStream(err.to_string())
    }
}

impl From<async_nats::jetstream::context::PublishError> for NatsError {
    fn from(err: async_nats::jetstream::context::PublishError) -> Self {
        NatsError::JetStream(err.to_string())
    }
}

impl From<async_nats::jetstream::stream::ConsumerError> for NatsError {
    fn from(err: async_nats::jetstream::stream::ConsumerError) -> Self {
        NatsError::JetStream(err.to_string())
    }
}

/// NATS JetStream event store for policy events
pub struct NatsEventStore {
    jetstream: jetstream::Context,
    stream: Stream,
    stream_name: String,
}

impl NatsEventStore {
    /// Create a new NATS event store with the given JetStream context and stream name
    pub async fn new(jetstream: jetstream::Context, stream_name: String) -> Result<Self, NatsError> {
        let stream = jetstream
            .get_or_create_stream(jetstream::stream::Config {
                name: stream_name.clone(),
                subjects: vec!["events.policy.>".to_string()],
                max_age: std::time::Duration::from_secs(365 * 24 * 60 * 60), // 1 year retention
                storage: jetstream::stream::StorageType::File,
                num_replicas: 1,
                ..Default::default()
            })
            .await?;

        Ok(Self {
            jetstream,
            stream,
            stream_name,
        })
    }

    /// Append an event to the event store
    pub async fn append_event(&self, event: PolicyEvent) -> Result<(), NatsError> {
        let subject = self.event_subject(&event);
        let payload = serde_json::to_vec(&event)?;

        let mut headers = async_nats::HeaderMap::new();
        headers.insert("event-type", event.event_type());
        headers.insert("aggregate-id", event.aggregate_id().to_string().as_str());

        self.jetstream
            .publish_with_headers(subject, headers, payload.into())
            .await?;

        Ok(())
    }

    /// Load all events for a specific aggregate
    pub async fn load_events(&self, aggregate_id: Uuid) -> Result<Vec<PolicyEvent>, NatsError> {
        let subject_filter = format!("events.policy.{}.*", aggregate_id);

        let consumer = self
            .stream
            .create_consumer(jetstream::consumer::pull::Config {
                filter_subject: subject_filter,
                ..Default::default()
            })
            .await?;

        let mut messages = consumer.messages().await.map_err(|e| {
            NatsError::JetStream(format!("Failed to get messages: {}", e))
        })?;

        let mut events = Vec::new();

        while let Some(message) = messages.next().await {
            match message {
                Ok(msg) => {
                    let event: PolicyEvent = serde_json::from_slice(&msg.payload)?;
                    events.push(event);
                    let _ = msg.ack().await;
                }
                Err(e) => {
                    tracing::warn!("Error reading message: {}", e);
                    break;
                }
            }
        }

        Ok(events)
    }

    /// Generate the NATS subject for an event
    ///
    /// Subject pattern: events.policy.{aggregate_id}.{event_type}
    ///
    /// Examples:
    /// - events.policy.550e8400-e29b-41d4-a716-446655440000.created
    /// - events.policy.550e8400-e29b-41d4-a716-446655440000.approved
    /// - events.policy.550e8400-e29b-41d4-a716-446655440000.activated
    pub fn event_subject(&self, event: &PolicyEvent) -> String {
        let aggregate_id = event.aggregate_id();
        let event_type = event.event_type().to_lowercase();

        format!("events.policy.{}.{}", aggregate_id, event_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{PolicyCreated, PolicyEvent};
    use crate::value_objects::PolicyId;
    use chrono::Utc;
    use cim_domain::MessageIdentity;

    #[test]
    fn test_event_subject_generation() {
        let event_store = create_test_event_store();

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

        let subject = event_store.event_subject(&event);
        assert!(subject.starts_with("events.policy."));
        assert!(subject.ends_with(".policycreated"));
    }

    fn create_test_event_store() -> NatsEventStore {
        // Mock event store for testing (doesn't actually connect to NATS)
        NatsEventStore {
            jetstream: unsafe { std::mem::zeroed() },
            stream: unsafe { std::mem::zeroed() },
            stream_name: "POLICY_EVENTS".to_string(),
        }
    }
}
