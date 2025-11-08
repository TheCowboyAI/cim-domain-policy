//! NATS implementation of the EventPublisher port

use crate::events::PolicyEvent;
use crate::ports::event_publisher::{event_to_subject, EventPublisher, PublishError, QueryError};
use async_nats::jetstream;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use cim_domain::DomainEvent;
use futures::StreamExt;
use uuid::Uuid;

/// NATS JetStream implementation of EventPublisher
pub struct NatsEventPublisher {
    jetstream: jetstream::Context,
    stream_name: String,
}

impl NatsEventPublisher {
    /// Create a new NATS event publisher
    pub fn new(jetstream: jetstream::Context, stream_name: String) -> Self {
        Self {
            jetstream,
            stream_name,
        }
    }
}

#[async_trait]
impl EventPublisher for NatsEventPublisher {
    async fn publish(&self, event: &PolicyEvent) -> Result<(), PublishError> {
        let subject = event_to_subject(event);
        let payload = serde_json::to_vec(event)
            .map_err(|e| PublishError::Serialization(e.to_string()))?;

        let mut headers = async_nats::HeaderMap::new();
        headers.insert("event-type", event.event_type());
        headers.insert("aggregate-id", event.aggregate_id().to_string().as_str());
        headers.insert("stream", self.stream_name.as_str());

        self.jetstream
            .publish_with_headers(subject, headers, payload.into())
            .await
            .map_err(|e| PublishError::Publishing(e.to_string()))?;

        Ok(())
    }

    async fn publish_batch(&self, events: &[PolicyEvent]) -> Result<(), PublishError> {
        for event in events {
            self.publish(event).await?;
        }
        Ok(())
    }

    async fn query_by_correlation(&self, correlation_id: Uuid) -> Result<Vec<PolicyEvent>, QueryError> {
        // For correlation queries, we'd need to implement a consumer that filters by correlation ID in headers
        // This is a simplified implementation
        let _ = correlation_id;
        Ok(Vec::new())
    }

    async fn query_by_aggregate(&self, aggregate_id: Uuid) -> Result<Vec<PolicyEvent>, QueryError> {
        let subject_filter = format!("events.policy.{}.*", aggregate_id);

        let stream = self
            .jetstream
            .get_stream(&self.stream_name)
            .await
            .map_err(|e| QueryError::Query(e.to_string()))?;

        let consumer = stream
            .create_consumer(jetstream::consumer::pull::Config {
                filter_subject: subject_filter,
                ..Default::default()
            })
            .await
            .map_err(|e| QueryError::Query(e.to_string()))?;

        let mut messages = consumer
            .messages()
            .await
            .map_err(|e| QueryError::Query(e.to_string()))?;

        let mut events = Vec::new();

        while let Some(message) = messages.next().await {
            match message {
                Ok(msg) => {
                    let event: PolicyEvent = serde_json::from_slice(&msg.payload)
                        .map_err(|e| QueryError::Deserialization(e.to_string()))?;
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

    async fn query_by_time_range(
        &self,
        _start: DateTime<Utc>,
        _end: DateTime<Utc>,
    ) -> Result<Vec<PolicyEvent>, QueryError> {
        // Time range queries would require filtering messages by timestamp
        // This is a simplified implementation
        Ok(Vec::new())
    }
}

