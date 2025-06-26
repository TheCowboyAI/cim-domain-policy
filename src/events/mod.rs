//! Policy domain events
//!
//! These events represent things that have happened in the policy domain.
//! They are the source of truth for the domain's state.

use cim_domain::DomainEvent;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use bevy_ecs::event::Event;
use bevy_ecs::prelude::*;

pub mod authentication;
pub mod enforcement;

// Re-export authentication events
pub use authentication::*;
pub use enforcement::*;

use crate::components::{PolicyType, PolicyScope};
use crate::aggregate::PolicyMetadata;

/// Event: A new policy has been enacted
#[derive(Event, Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEnacted {
    /// Policy ID
    pub policy_id: Uuid,
    /// Policy type
    pub policy_type: PolicyType,
    /// Policy scope
    pub scope: PolicyScope,
    /// Owner ID
    pub owner_id: Uuid,
    /// Policy metadata
    pub metadata: PolicyMetadata,
    /// When the policy was enacted
    pub enacted_at: DateTime<Utc>,
}

impl DomainEvent for PolicyEnacted {
    fn event_type(&self) -> &'static str {
        "PolicyEnacted"
    }

    fn aggregate_id(&self) -> Uuid {
        self.policy_id
    }

    fn subject(&self) -> String {
        format!("policy.{}.enacted", self.policy_id)
    }
}

/// Event: Policy submitted for approval
#[derive(Event, Debug, Clone, Serialize, Deserialize)]
pub struct PolicySubmittedForApproval {
    /// Policy ID
    pub policy_id: Uuid,
    /// Who submitted it
    pub submitted_by: Uuid,
    /// When it was submitted
    pub submitted_at: DateTime<Utc>,
    /// Optional comment
    pub comment: Option<String>,
}

impl DomainEvent for PolicySubmittedForApproval {
    fn event_type(&self) -> &'static str {
        "PolicySubmittedForApproval"
    }

    fn aggregate_id(&self) -> Uuid {
        self.policy_id
    }

    fn subject(&self) -> String {
        format!("policy.{}.submitted_for_approval", self.policy_id)
    }
}

/// Event: Policy approved
#[derive(Event, Debug, Clone, Serialize, Deserialize)]
pub struct PolicyApproved {
    /// Policy ID
    pub policy_id: Uuid,
    /// Who approved it
    pub approved_by: Uuid,
    /// When it was approved
    pub approved_at: DateTime<Utc>,
    /// Optional comment
    pub comment: Option<String>,
}

impl DomainEvent for PolicyApproved {
    fn event_type(&self) -> &'static str {
        "PolicyApproved"
    }

    fn aggregate_id(&self) -> Uuid {
        self.policy_id
    }

    fn subject(&self) -> String {
        format!("policy.{}.approved", self.policy_id)
    }
}

/// Event: Policy rejected
#[derive(Event, Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRejected {
    /// Policy ID
    pub policy_id: Uuid,
    /// Who rejected it
    pub rejected_by: Uuid,
    /// When it was rejected
    pub rejected_at: DateTime<Utc>,
    /// Reason for rejection
    pub reason: String,
}

impl DomainEvent for PolicyRejected {
    fn event_type(&self) -> &'static str {
        "PolicyRejected"
    }

    fn aggregate_id(&self) -> Uuid {
        self.policy_id
    }

    fn subject(&self) -> String {
        format!("policy.{}.rejected", self.policy_id)
    }
}

/// Event: Policy suspended
#[derive(Event, Debug, Clone, Serialize, Deserialize)]
pub struct PolicySuspended {
    /// Policy ID
    pub policy_id: Uuid,
    /// Who suspended it
    pub suspended_by: Uuid,
    /// When it was suspended
    pub suspended_at: DateTime<Utc>,
    /// Reason for suspension
    pub reason: String,
}

impl DomainEvent for PolicySuspended {
    fn event_type(&self) -> &'static str {
        "PolicySuspended"
    }

    fn aggregate_id(&self) -> Uuid {
        self.policy_id
    }

    fn subject(&self) -> String {
        format!("policy.{}.suspended", self.policy_id)
    }
}

/// Event: Policy reactivated
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyReactivated {
    /// Policy ID
    pub policy_id: Uuid,
    /// Who reactivated it
    pub reactivated_by: Uuid,
    /// When it was reactivated
    pub reactivated_at: DateTime<Utc>,
    /// Optional comment
    pub comment: Option<String>,
}

impl DomainEvent for PolicyReactivated {
    fn event_type(&self) -> &'static str {
        "PolicyReactivated"
    }

    fn aggregate_id(&self) -> Uuid {
        self.policy_id
    }

    fn subject(&self) -> String {
        "policies.policy.reactivated.v1".to_string()
    }
}

/// Event: Policy superseded by another
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySuperseded {
    /// Old policy ID
    pub old_policy_id: Uuid,
    /// New policy ID that supersedes it
    pub new_policy_id: Uuid,
    /// Who made the change
    pub superseded_by: Uuid,
    /// When it was superseded
    pub superseded_at: DateTime<Utc>,
    /// Reason or comment
    pub reason: Option<String>,
}

impl DomainEvent for PolicySuperseded {
    fn event_type(&self) -> &'static str {
        "PolicySuperseded"
    }

    fn aggregate_id(&self) -> Uuid {
        self.old_policy_id
    }

    fn subject(&self) -> String {
        "policies.policy.superseded.v1".to_string()
    }
}

/// Event: Policy archived
#[derive(Event, Debug, Clone, Serialize, Deserialize)]
pub struct PolicyArchived {
    /// Policy ID
    pub policy_id: Uuid,
    /// When it was archived
    pub archived_at: DateTime<Utc>,
    /// Reason for archival
    pub reason: Option<String>,
}

impl DomainEvent for PolicyArchived {
    fn event_type(&self) -> &'static str {
        "PolicyArchived"
    }

    fn aggregate_id(&self) -> Uuid {
        self.policy_id
    }

    fn subject(&self) -> String {
        format!("policy.{}.archived", self.policy_id)
    }
}

/// Event: External approval requested for a policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyExternalApprovalRequested {
    /// Policy ID
    pub policy_id: Uuid,
    /// Request ID
    pub request_id: Uuid,
    /// Type of approval needed
    pub approval_type: String,
    /// Who requested it
    pub requested_by: Uuid,
    /// When it was requested
    pub requested_at: DateTime<Utc>,
    /// Metadata for the external system
    pub metadata: HashMap<String, serde_json::Value>,
}

impl DomainEvent for PolicyExternalApprovalRequested {
    fn event_type(&self) -> &'static str {
        "PolicyExternalApprovalRequested"
    }

    fn aggregate_id(&self) -> Uuid {
        self.policy_id
    }

    fn subject(&self) -> String {
        "policies.policy.external_approval_requested.v1".to_string()
    }
}

/// Event: External approval received for a policy
#[derive(Event, Debug, Clone, Serialize, Deserialize)]
pub struct PolicyExternalApprovalReceived {
    /// Policy ID
    pub policy_id: Uuid,
    /// Request ID this fulfills
    pub request_id: Uuid,
    /// Type of approval
    pub approval_type: String,
    /// Verification ID from external system
    pub verification_id: String,
    /// When it was received
    pub received_at: DateTime<Utc>,
    /// Metadata from the external system
    pub metadata: HashMap<String, serde_json::Value>,
}

impl DomainEvent for PolicyExternalApprovalReceived {
    fn event_type(&self) -> &'static str {
        "PolicyExternalApprovalReceived"
    }

    fn aggregate_id(&self) -> Uuid {
        self.policy_id
    }

    fn subject(&self) -> String {
        format!("policy.{}.external_approval_received", self.policy_id)
    }
}

/// Enum to wrap all policy events
#[derive(Debug, Clone)]
pub enum PolicyEvent {
    PolicyEnacted(PolicyEnacted),
    PolicySubmittedForApproval(PolicySubmittedForApproval),
    PolicyApproved(PolicyApproved),
    PolicyRejected(PolicyRejected),
    PolicySuspended(PolicySuspended),
    PolicyReactivated(PolicyReactivated),
    PolicySuperseded(PolicySuperseded),
    PolicyArchived(PolicyArchived),
    PolicyExternalApprovalRequested(PolicyExternalApprovalRequested),
    PolicyExternalApprovalReceived(PolicyExternalApprovalReceived),
    // Authentication events
    AuthenticationRequested(AuthenticationRequested),
    AuthenticationPolicyApplied(AuthenticationPolicyApplied),
    AuthenticationTypeDetermined(AuthenticationTypeDetermined),
    MfaWorkflowStarted(MfaWorkflowStarted),
    AuthenticationFactorCompleted(AuthenticationFactorCompleted),
    AuthenticationDecisionMade(AuthenticationDecisionMade),
    AuthenticationSessionCreated(AuthenticationSessionCreated),
    AuthenticationSessionTerminated(AuthenticationSessionTerminated),
    AuthenticationFailed(AuthenticationFailed),
    AuthenticationRequirementsUpdated(AuthenticationRequirementsUpdated),
    FederatedAuthenticationConfigured(FederatedAuthenticationConfigured),
    ExternalAuthenticationApprovalRequested(ExternalAuthenticationApprovalRequested),
    ExternalAuthenticationApprovalReceived(ExternalAuthenticationApprovalReceived),
    AuthenticationRateLimitExceeded(AuthenticationRateLimitExceeded),
    AuthenticationAuditEventOccurred(AuthenticationAuditEventOccurred),
}
