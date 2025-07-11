//! Policy domain events

pub mod authentication;

// Re-export authentication events
pub use authentication::{
    AuthenticationRequested, AuthenticationPolicyApplied, AuthenticationType,
    AuthenticationTypeDetermined, MfaWorkflowStarted, AuthenticationFactorCompleted,
    AuthenticationDecisionMade, AuthenticationSessionCreated, AuthenticationSessionTerminated,
    AuthenticationFailed, AuthenticationRequirementsUpdated, FederatedAuthenticationConfigured,
    ExternalAuthenticationApprovalRequested, ExternalAuthenticationApprovalReceived,
    AuthenticationRateLimitExceeded, LimitedEntity, AuthenticationAuditEventOccurred,
};

use bevy_ecs::prelude::Event;
use cim_domain::DomainEvent;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use std::collections::HashMap;
use crate::components::policy::{ScopeType, PolicyType as ComponentPolicyType};

/// Policy enacted event
#[derive(Debug, Clone, Serialize, Deserialize, Event)]
pub struct PolicyEnacted {
    /// The unique identifier of the policy
    pub policy_id: Uuid,
    /// The type of policy being enacted
    pub policy_type: crate::PolicyType,
    /// What the policy applies to
    pub scope: crate::PolicyScope,
    /// The ID of the entity that owns this policy
    pub owner_id: Uuid,
    /// Additional metadata about the policy
    pub metadata: crate::PolicyMetadata,
    /// When the policy was enacted
    pub enacted_at: chrono::DateTime<chrono::Utc>,
}

impl DomainEvent for PolicyEnacted {
    fn aggregate_id(&self) -> Uuid {
        self.policy_id
    }

    fn event_type(&self) -> &'static str {
        "PolicyEnacted"
    }

    fn subject(&self) -> String {
        "policies.policy.enacted.v1".to_string()
    }
}

/// Policy created event (for ECS system)
#[derive(Debug, Clone, Serialize, Deserialize, Event)]
pub struct PolicyCreated {
    pub policy_id: Uuid,
    pub policy_type: ComponentPolicyType,
    pub scope_type: ScopeType,
    pub targets: Vec<String>,
    pub priority: u32,
    pub override_lower: bool,
}

impl DomainEvent for PolicyCreated {
    fn aggregate_id(&self) -> Uuid {
        self.policy_id
    }

    fn event_type(&self) -> &'static str {
        "PolicyCreated"
    }

    fn subject(&self) -> String {
        "policies.policy.created.v1".to_string()
    }
}

/// Policy updated event (for ECS system)
#[derive(Debug, Clone, Serialize, Deserialize, Event)]
pub struct PolicyUpdated {
    pub policy_id: Uuid,
    pub new_scope: Option<PolicyScopeUpdate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyScopeUpdate {
    pub scope_type: ScopeType,
    pub targets: Vec<String>,
}

impl DomainEvent for PolicyUpdated {
    fn aggregate_id(&self) -> Uuid {
        self.policy_id
    }

    fn event_type(&self) -> &'static str {
        "PolicyUpdated"
    }

    fn subject(&self) -> String {
        "policies.policy.updated.v1".to_string()
    }
}

/// Policy activated event (for ECS system)
#[derive(Debug, Clone, Serialize, Deserialize, Event)]
pub struct PolicyActivated {
    pub policy_id: Uuid,
}

impl DomainEvent for PolicyActivated {
    fn aggregate_id(&self) -> Uuid {
        self.policy_id
    }

    fn event_type(&self) -> &'static str {
        "PolicyActivated"
    }

    fn subject(&self) -> String {
        "policies.policy.activated.v1".to_string()
    }
}

/// Policy submitted for approval
#[derive(Debug, Clone, Serialize, Deserialize, Event)]
pub struct PolicySubmittedForApproval {
    /// Policy ID
    pub policy_id: Uuid,
    /// Who submitted it
    pub submitted_by: Uuid,
    /// Submission notes
    pub notes: Option<String>,
    /// When submitted
    pub submitted_at: chrono::DateTime<chrono::Utc>,
}

impl DomainEvent for PolicySubmittedForApproval {
    fn aggregate_id(&self) -> Uuid {
        self.policy_id
    }

    fn event_type(&self) -> &'static str {
        "PolicySubmittedForApproval"
    }

    fn subject(&self) -> String {
        "policies.policy.submitted_for_approval.v1".to_string()
    }
}

/// Policy approved
#[derive(Debug, Clone, Serialize, Deserialize, Event)]
pub struct PolicyApproved {
    /// Policy ID
    pub policy_id: Uuid,
    /// Who approved it
    pub approved_by: Uuid,
    /// Approval comments
    pub comments: Option<String>,
    /// External verification if any
    pub external_verification: Option<crate::ExternalVerification>,
    /// When approved
    pub approved_at: chrono::DateTime<chrono::Utc>,
}

impl DomainEvent for PolicyApproved {
    fn aggregate_id(&self) -> Uuid {
        self.policy_id
    }

    fn event_type(&self) -> &'static str {
        "PolicyApproved"
    }

    fn subject(&self) -> String {
        "policies.policy.approved.v1".to_string()
    }
}

/// Policy rejected
#[derive(Debug, Clone, Serialize, Deserialize, Event)]
pub struct PolicyRejected {
    /// Policy ID
    pub policy_id: Uuid,
    /// Who rejected it
    pub rejected_by: Uuid,
    /// Rejection reason
    pub reason: String,
    /// When rejected
    pub rejected_at: chrono::DateTime<chrono::Utc>,
}

impl DomainEvent for PolicyRejected {
    fn aggregate_id(&self) -> Uuid {
        self.policy_id
    }

    fn event_type(&self) -> &'static str {
        "PolicyRejected"
    }

    fn subject(&self) -> String {
        "policies.policy.rejected.v1".to_string()
    }
}

/// Policy suspended
#[derive(Debug, Clone, Serialize, Deserialize, Event)]
pub struct PolicySuspended {
    /// Policy ID
    pub policy_id: Uuid,
    /// Suspension reason
    pub reason: String,
    /// Who suspended it
    pub suspended_by: Uuid,
    /// When suspended
    pub suspended_at: chrono::DateTime<chrono::Utc>,
}

impl DomainEvent for PolicySuspended {
    fn aggregate_id(&self) -> Uuid {
        self.policy_id
    }

    fn event_type(&self) -> &'static str {
        "PolicySuspended"
    }

    fn subject(&self) -> String {
        "policies.policy.suspended.v1".to_string()
    }
}

/// Policy reactivated
#[derive(Debug, Clone, Serialize, Deserialize, Event)]
pub struct PolicyReactivated {
    /// Policy ID
    pub policy_id: Uuid,
    /// Who reactivated it
    pub reactivated_by: Uuid,
    /// When reactivated
    pub reactivated_at: chrono::DateTime<chrono::Utc>,
}

impl DomainEvent for PolicyReactivated {
    fn aggregate_id(&self) -> Uuid {
        self.policy_id
    }

    fn event_type(&self) -> &'static str {
        "PolicyReactivated"
    }

    fn subject(&self) -> String {
        "policies.policy.reactivated.v1".to_string()
    }
}

/// Policy superseded by another
#[derive(Debug, Clone, Serialize, Deserialize, Event)]
pub struct PolicySuperseded {
    /// Policy ID being superseded
    pub policy_id: Uuid,
    /// New policy that supersedes this one
    pub superseded_by: Uuid,
    /// When superseded
    pub superseded_at: chrono::DateTime<chrono::Utc>,
}

impl DomainEvent for PolicySuperseded {
    fn aggregate_id(&self) -> Uuid {
        self.policy_id
    }

    fn event_type(&self) -> &'static str {
        "PolicySuperseded"
    }

    fn subject(&self) -> String {
        "policies.policy.superseded.v1".to_string()
    }
}

/// Policy archived
#[derive(Debug, Clone, Serialize, Deserialize, Event)]
pub struct PolicyArchived {
    /// Policy ID
    pub policy_id: Uuid,
    /// Archive reason
    pub reason: Option<String>,
    /// When archived
    pub archived_at: chrono::DateTime<chrono::Utc>,
}

impl DomainEvent for PolicyArchived {
    fn aggregate_id(&self) -> Uuid {
        self.policy_id
    }

    fn event_type(&self) -> &'static str {
        "PolicyArchived"
    }

    fn subject(&self) -> String {
        "policies.policy.archived.v1".to_string()
    }
}

/// External approval requested for policy
#[derive(Debug, Clone, Serialize, Deserialize, Event)]
pub struct PolicyExternalApprovalRequested {
    /// Policy ID
    pub policy_id: Uuid,
    /// Request ID
    pub request_id: Uuid,
    /// Type of approval required
    pub approval_type: String,
    /// Request metadata
    pub metadata: HashMap<String, serde_json::Value>,
    /// When requested
    pub requested_at: chrono::DateTime<chrono::Utc>,
}

impl DomainEvent for PolicyExternalApprovalRequested {
    fn aggregate_id(&self) -> Uuid {
        self.policy_id
    }

    fn event_type(&self) -> &'static str {
        "PolicyExternalApprovalRequested"
    }

    fn subject(&self) -> String {
        "policies.policy.external_approval_requested.v1".to_string()
    }
}

/// External approval received for policy
#[derive(Debug, Clone, Serialize, Deserialize, Event)]
pub struct PolicyExternalApprovalReceived {
    /// Policy ID
    pub policy_id: Uuid,
    /// Request ID this approval is for
    pub request_id: Uuid,
    /// External verification details
    pub verification: crate::ExternalVerification,
    /// When received
    pub received_at: chrono::DateTime<chrono::Utc>,
}

impl DomainEvent for PolicyExternalApprovalReceived {
    fn aggregate_id(&self) -> Uuid {
        self.policy_id
    }

    fn event_type(&self) -> &'static str {
        "PolicyExternalApprovalReceived"
    }

    fn subject(&self) -> String {
        "policies.policy.external_approval_received.v1".to_string()
    }
}
