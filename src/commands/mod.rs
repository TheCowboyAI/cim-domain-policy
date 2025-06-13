//! Policy commands

use cim_domain::Command;
use cim_domain::EntityId;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use std::collections::HashMap;

/// Enact a new policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnactPolicy {
    /// Policy ID
    pub policy_id: Uuid,
    /// Policy type
    pub policy_type: crate::PolicyType,
    /// Policy scope
    pub scope: crate::PolicyScope,
    /// Owner ID
    pub owner_id: Uuid,
    /// Policy metadata
    pub metadata: crate::PolicyMetadata,
}

impl Command for EnactPolicy {
    type Aggregate = crate::Policy;

    fn aggregate_id(&self) -> Option<EntityId<Self::Aggregate>> {
        Some(EntityId::from_uuid(self.policy_id))
    }
}

/// Update policy rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdatePolicyRules {
    /// Policy ID
    pub policy_id: Uuid,
    /// New rules
    pub rules: serde_json::Value,
    /// Rule engine type
    pub engine: String,
    /// Rule version
    pub version: String,
}

impl Command for UpdatePolicyRules {
    type Aggregate = crate::Policy;

    fn aggregate_id(&self) -> Option<EntityId<Self::Aggregate>> {
        Some(EntityId::from_uuid(self.policy_id))
    }
}

/// Submit policy for approval
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitPolicyForApproval {
    /// Policy ID
    pub policy_id: Uuid,
    /// Submission notes
    pub notes: Option<String>,
}

impl Command for SubmitPolicyForApproval {
    type Aggregate = crate::Policy;

    fn aggregate_id(&self) -> Option<EntityId<Self::Aggregate>> {
        Some(EntityId::from_uuid(self.policy_id))
    }
}

/// Approve a policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovePolicy {
    /// Policy ID
    pub policy_id: Uuid,
    /// Approver ID
    pub approver_id: Uuid,
    /// Approval comments
    pub comments: Option<String>,
    /// External verification if required
    pub external_verification: Option<crate::ExternalVerification>,
}

impl Command for ApprovePolicy {
    type Aggregate = crate::Policy;

    fn aggregate_id(&self) -> Option<EntityId<Self::Aggregate>> {
        Some(EntityId::from_uuid(self.policy_id))
    }
}

/// Reject a policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RejectPolicy {
    /// Policy ID
    pub policy_id: Uuid,
    /// Rejector ID
    pub rejector_id: Uuid,
    /// Rejection reason
    pub reason: String,
}

impl Command for RejectPolicy {
    type Aggregate = crate::Policy;

    fn aggregate_id(&self) -> Option<EntityId<Self::Aggregate>> {
        Some(EntityId::from_uuid(self.policy_id))
    }
}

/// Suspend a policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspendPolicy {
    /// Policy ID
    pub policy_id: Uuid,
    /// Suspension reason
    pub reason: String,
}

impl Command for SuspendPolicy {
    type Aggregate = crate::Policy;

    fn aggregate_id(&self) -> Option<EntityId<Self::Aggregate>> {
        Some(EntityId::from_uuid(self.policy_id))
    }
}

/// Reactivate a suspended policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReactivatePolicy {
    /// Policy ID
    pub policy_id: Uuid,
}

impl Command for ReactivatePolicy {
    type Aggregate = crate::Policy;

    fn aggregate_id(&self) -> Option<EntityId<Self::Aggregate>> {
        Some(EntityId::from_uuid(self.policy_id))
    }
}

/// Supersede a policy with another
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupersedePolicy {
    /// Policy ID being superseded
    pub policy_id: Uuid,
    /// New policy ID that supersedes this one
    pub new_policy_id: Uuid,
}

impl Command for SupersedePolicy {
    type Aggregate = crate::Policy;

    fn aggregate_id(&self) -> Option<EntityId<Self::Aggregate>> {
        Some(EntityId::from_uuid(self.policy_id))
    }
}

/// Archive a policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchivePolicy {
    /// Policy ID
    pub policy_id: Uuid,
}

impl Command for ArchivePolicy {
    type Aggregate = crate::Policy;

    fn aggregate_id(&self) -> Option<EntityId<Self::Aggregate>> {
        Some(EntityId::from_uuid(self.policy_id))
    }
}

/// Request external approval for a policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestPolicyExternalApproval {
    /// Policy ID
    pub policy_id: Uuid,
    /// Type of approval required
    pub approval_type: String,
    /// Request metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

impl Command for RequestPolicyExternalApproval {
    type Aggregate = crate::Policy;

    fn aggregate_id(&self) -> Option<EntityId<Self::Aggregate>> {
        Some(EntityId::from_uuid(self.policy_id))
    }
}

/// Record external approval received
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordPolicyExternalApproval {
    /// Policy ID
    pub policy_id: Uuid,
    /// Request ID this approval is for
    pub request_id: Uuid,
    /// External verification details
    pub verification: crate::ExternalVerification,
}

impl Command for RecordPolicyExternalApproval {
    type Aggregate = crate::Policy;

    fn aggregate_id(&self) -> Option<EntityId<Self::Aggregate>> {
        Some(EntityId::from_uuid(self.policy_id))
    }
}
