//! Policy domain events

use cim_core_domain::event::{DomainEvent, EventMetadata};
use cim_core_domain::identifiers::AggregateId;
use cim_core_domain::subject::Subject;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use std::collections::{HashMap, HashSet};

/// Policy enacted event
#[derive(Debug, Clone, Serialize, Deserialize)]
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
        format!("policies.policy.enacted.v1")
    }
}

/// Policy submitted for approval
#[derive(Debug, Clone, Serialize, Deserialize)]
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
        format!("policies.policy.submitted_for_approval.v1")
    }
}

/// Policy approved
#[derive(Debug, Clone, Serialize, Deserialize)]
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
        format!("policies.policy.approved.v1")
    }
}

/// Policy rejected
#[derive(Debug, Clone, Serialize, Deserialize)]
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
        format!("policies.policy.rejected.v1")
    }
}

/// Policy suspended
#[derive(Debug, Clone, Serialize, Deserialize)]
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
        format!("policies.policy.suspended.v1")
    }
}

/// Policy reactivated
#[derive(Debug, Clone, Serialize, Deserialize)]
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
        format!("policies.policy.reactivated.v1")
    }
}

/// Policy superseded by another
#[derive(Debug, Clone, Serialize, Deserialize)]
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
        format!("policies.policy.superseded.v1")
    }
}

/// Policy archived
#[derive(Debug, Clone, Serialize, Deserialize)]
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
        format!("policies.policy.archived.v1")
    }
}

/// External approval requested for policy
#[derive(Debug, Clone, Serialize, Deserialize)]
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
        format!("policies.policy.external_approval_requested.v1")
    }
}

/// External approval received for policy
#[derive(Debug, Clone, Serialize, Deserialize)]
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
        format!("policies.policy.external_approval_received.v1")
    }
}
