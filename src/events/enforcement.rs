//! Enforcement-related events

use bevy_ecs::prelude::*;
use cim_domain::DomainEvent;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use std::collections::HashMap;

use crate::value_objects::{
    ViolationType, ViolationSeverity, ActionType,
    EnforcementMode, EnforcementResult
};

/// Event emitted when a policy is enforced
#[derive(Event, Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEnforced {
    pub policy_id: Uuid,
    pub enforced_at: DateTime<Utc>,
    pub enforcement_mode: EnforcementMode,
}

/// Event emitted when a policy violation is detected
#[derive(Event, Debug, Clone, Serialize, Deserialize)]
pub struct PolicyViolationDetected {
    pub policy_id: Uuid,
    pub violation_id: Uuid,
    pub violation_type: ViolationType,
    pub severity: ViolationSeverity,
    pub violator_id: Uuid,
    pub detected_at: DateTime<Utc>,
    pub context: HashMap<String, String>,
}

/// Event emitted when an enforcement action is taken
#[derive(Event, Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementActionTaken {
    pub policy_id: Uuid,
    pub action_id: Uuid,
    pub action_type: ActionType,
    pub target_id: Uuid,
    pub violation_id: Option<Uuid>,
    pub executed_at: DateTime<Utc>,
    pub result: EnforcementResult,
}

// Implement DomainEvent for enforcement events
impl DomainEvent for PolicyEnforced {
    fn event_type(&self) -> &'static str {
        "PolicyEnforced"
    }

    fn aggregate_id(&self) -> Uuid {
        self.policy_id
    }

    fn subject(&self) -> String {
        format!("policy.{}.enforced", self.policy_id)
    }
}

impl DomainEvent for PolicyViolationDetected {
    fn event_type(&self) -> &'static str {
        "PolicyViolationDetected"
    }

    fn aggregate_id(&self) -> Uuid {
        self.policy_id
    }

    fn subject(&self) -> String {
        format!("policy.{}.violation_detected", self.policy_id)
    }
}

impl DomainEvent for EnforcementActionTaken {
    fn event_type(&self) -> &'static str {
        "EnforcementActionTaken"
    }

    fn aggregate_id(&self) -> Uuid {
        self.policy_id
    }

    fn subject(&self) -> String {
        format!("policy.{}.enforcement_action_taken", self.policy_id)
    }
} 