//! Policy repository with event sourcing support

use crate::aggregate::Policy;
use crate::events::{PolicyCreated, PolicyEvent};
use crate::infrastructure::nats_integration::{NatsError, NatsEventStore};
use crate::value_objects::PolicyId;
use cim_domain::DomainEvent;
use std::sync::Arc;
use thiserror::Error;

/// Errors that can occur in the policy repository
#[derive(Debug, Error)]
pub enum RepositoryError {
    #[error("NATS error: {0}")]
    Nats(#[from] NatsError),

    #[error("Policy error: {0}")]
    Policy(#[from] crate::PolicyError),

    #[error("Invalid event sequence: {0}")]
    InvalidSequence(String),
}

/// Repository for policy aggregates using event sourcing
pub struct PolicyRepository {
    event_store: Arc<NatsEventStore>,
    snapshot_frequency: u64,
}

impl PolicyRepository {
    /// Create a new policy repository
    pub fn new(event_store: Arc<NatsEventStore>) -> Self {
        Self {
            event_store,
            snapshot_frequency: 100, // Default: snapshot every 100 events
        }
    }

    /// Set the snapshot frequency (number of events between snapshots)
    pub fn with_snapshot_frequency(mut self, frequency: u64) -> Self {
        self.snapshot_frequency = frequency;
        self
    }

    /// Load a policy by reconstructing it from its event history
    ///
    /// This is the core of event sourcing - we rebuild the aggregate state
    /// by applying each event in sequence.
    pub async fn load(&self, policy_id: PolicyId) -> Result<Option<Policy>, RepositoryError> {
        let uuid_id = policy_id.0;
        let events = self.event_store.load_events(uuid_id).await?;

        if events.is_empty() {
            return Ok(None);
        }

        // First event must be PolicyCreated
        let mut policy = None;

        for event in events {
            match &policy {
                None => {
                    // First event must create the policy
                    if let PolicyEvent::PolicyCreated(created) = &event {
                        policy = Some(self.create_from_created_event(created)?);
                    } else {
                        return Err(RepositoryError::InvalidSequence(format!(
                            "First event must be PolicyCreated, got: {}",
                            event.event_type()
                        )));
                    }
                }
                Some(pol) => {
                    // Apply subsequent events
                    policy = Some(pol.apply_event_pure(&event)?);
                }
            }
        }

        Ok(policy)
    }

    /// Save a batch of events for a policy
    pub async fn save(&self, events: Vec<PolicyEvent>) -> Result<(), RepositoryError> {
        for event in events {
            self.event_store.append_event(event).await?;
        }
        Ok(())
    }

    /// Create a policy from a PolicyCreated event
    fn create_from_created_event(&self, event: &PolicyCreated) -> Result<Policy, RepositoryError> {
        let policy = Policy::new(&event.name, &event.description);

        // Apply the created event to set proper state
        let policy_event = PolicyEvent::PolicyCreated(event.clone());
        Ok(policy.apply_event_pure(&policy_event)?)
    }
}

