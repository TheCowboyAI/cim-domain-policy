//! PolicySet repository with event sourcing support

use crate::aggregate::PolicySet;
use crate::events::{PolicyEvent, PolicySetCreated};
use crate::infrastructure::nats_integration::{NatsError, NatsEventStore};
use crate::value_objects::PolicySetId;
use cim_domain::DomainEvent;
use std::sync::Arc;
use thiserror::Error;

/// Errors that can occur in the policy set repository
#[derive(Debug, Error)]
pub enum RepositoryError {
    #[error("NATS error: {0}")]
    Nats(#[from] NatsError),

    #[error("Policy error: {0}")]
    Policy(#[from] crate::PolicyError),

    #[error("Invalid event sequence: {0}")]
    InvalidSequence(String),
}

/// Repository for policy set aggregates using event sourcing
pub struct PolicySetRepository {
    event_store: Arc<NatsEventStore>,
    snapshot_frequency: u64,
}

impl PolicySetRepository {
    /// Create a new policy set repository
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

    /// Load a policy set by reconstructing it from its event history
    pub async fn load(&self, set_id: PolicySetId) -> Result<Option<PolicySet>, RepositoryError> {
        let uuid_id = set_id.0;
        let events = self.event_store.load_events(uuid_id).await?;

        if events.is_empty() {
            return Ok(None);
        }

        let mut policy_set = None;

        for event in events {
            match &policy_set {
                None => {
                    if let PolicyEvent::PolicySetCreated(created) = &event {
                        policy_set = Some(self.create_from_created_event(created)?);
                    } else {
                        return Err(RepositoryError::InvalidSequence(format!(
                            "First event must be PolicySetCreated, got: {}",
                            event.event_type()
                        )));
                    }
                }
                Some(set) => {
                    policy_set = Some(set.apply_event_pure(&event)?);
                }
            }
        }

        Ok(policy_set)
    }

    /// Save a batch of events for a policy set
    pub async fn save(&self, events: Vec<PolicyEvent>) -> Result<(), RepositoryError> {
        for event in events {
            self.event_store.append_event(event).await?;
        }
        Ok(())
    }

    /// Create a policy set from a PolicySetCreated event
    fn create_from_created_event(&self, event: &PolicySetCreated) -> Result<PolicySet, RepositoryError> {
        let policy_set = PolicySet::new(&event.name, &event.description);
        let policy_event = PolicyEvent::PolicySetCreated(event.clone());
        Ok(policy_set.apply_event_pure(&policy_event)?)
    }
}
