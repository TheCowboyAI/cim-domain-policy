//! PolicyExemption repository with event sourcing support

use crate::aggregate::PolicyExemption;
use crate::events::{PolicyEvent, PolicyExemptionGranted};
use crate::infrastructure::nats_integration::{NatsError, NatsEventStore};
use crate::value_objects::ExemptionId;
use chrono::Utc;
use cim_domain::DomainEvent;
use std::sync::Arc;
use thiserror::Error;

/// Errors that can occur in the exemption repository
#[derive(Debug, Error)]
pub enum RepositoryError {
    #[error("NATS error: {0}")]
    Nats(#[from] NatsError),

    #[error("Policy error: {0}")]
    Policy(#[from] crate::PolicyError),

    #[error("Invalid event sequence: {0}")]
    InvalidSequence(String),
}

/// Repository for policy exemption aggregates using event sourcing
pub struct ExemptionRepository {
    event_store: Arc<NatsEventStore>,
    snapshot_frequency: u64,
}

impl ExemptionRepository {
    /// Create a new exemption repository
    pub fn new(event_store: Arc<NatsEventStore>) -> Self {
        Self {
            event_store,
            snapshot_frequency: 100,
        }
    }

    /// Set the snapshot frequency
    pub fn with_snapshot_frequency(mut self, frequency: u64) -> Self {
        self.snapshot_frequency = frequency;
        self
    }

    /// Load an exemption by reconstructing it from its event history
    pub async fn load(&self, exemption_id: ExemptionId) -> Result<Option<PolicyExemption>, RepositoryError> {
        let uuid_id = exemption_id.0;
        let events = self.event_store.load_events(uuid_id).await?;

        if events.is_empty() {
            return Ok(None);
        }

        let mut exemption = None;

        for event in events {
            match &exemption {
                None => {
                    if let PolicyEvent::PolicyExemptionGranted(granted) = &event {
                        exemption = Some(self.create_from_granted_event(granted)?);
                    } else {
                        return Err(RepositoryError::InvalidSequence(format!(
                            "First event must be PolicyExemptionGranted, got: {}",
                            event.event_type()
                        )));
                    }
                }
                Some(ex) => {
                    exemption = Some(ex.apply_event_pure(&event)?);
                }
            }
        }

        Ok(exemption)
    }

    /// Save a batch of events for an exemption
    pub async fn save(&self, events: Vec<PolicyEvent>) -> Result<(), RepositoryError> {
        for event in events {
            self.event_store.append_event(event).await?;
        }
        Ok(())
    }

    /// Create an exemption from a PolicyExemptionGranted event
    fn create_from_granted_event(&self, event: &PolicyExemptionGranted) -> Result<PolicyExemption, RepositoryError> {
        let exemption = PolicyExemption::new(
            event.policy_id,
            &event.reason,
            &event.reason, // Use reason as justification for now
            &event.granted_by,
            event.valid_until,
        );

        let policy_event = PolicyEvent::PolicyExemptionGranted(event.clone());
        Ok(exemption.apply_event_pure(&policy_event)?)
    }
}
