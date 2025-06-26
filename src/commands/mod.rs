//! Policy commands

pub mod authentication;

// Re-export authentication commands
pub use authentication::{
    RequestAuthentication, ApplyAuthenticationPolicy, DetermineAuthenticationType,
    StartMfaWorkflow, CompleteAuthenticationFactor, VerificationProof,
    MakeAuthenticationDecision, RiskAssessment, CreateAuthenticationSession,
    TerminateAuthenticationSession, SessionTerminationReason,
    UpdateAuthenticationRequirements, ConfigureFederatedAuthentication,
    HandleAuthenticationFailure, RequestExternalAuthenticationApproval,
};

use bevy_ecs::prelude::Event;
use cim_domain::Command;
use cim_domain::EntityId;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use std::collections::HashMap;
use crate::value_objects::{PolicyType, PolicyScope, ExternalVerification, PolicyStatus};
use crate::aggregate::{Policy, PolicyMetadata};

/// Enact a new policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnactPolicy {
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
}

impl Command for EnactPolicy {
    type Aggregate = Policy;

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
    type Aggregate = Policy;

    fn aggregate_id(&self) -> Option<EntityId<Self::Aggregate>> {
        Some(EntityId::from_uuid(self.policy_id))
    }
}

/// Submit policy for approval
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitPolicyForApproval {
    /// Policy ID
    pub policy_id: Uuid,
    /// Who submitted it
    pub submitted_by: Uuid,
    /// Submission notes
    pub notes: Option<String>,
}

impl Command for SubmitPolicyForApproval {
    type Aggregate = Policy;

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
    pub external_verification: Option<ExternalVerification>,
}

impl Command for ApprovePolicy {
    type Aggregate = Policy;

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
    type Aggregate = Policy;

    fn aggregate_id(&self) -> Option<EntityId<Self::Aggregate>> {
        Some(EntityId::from_uuid(self.policy_id))
    }
}

/// Suspend a policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspendPolicy {
    /// Policy ID
    pub policy_id: Uuid,
    /// Who suspended it
    pub suspended_by: Uuid,
    /// Suspension reason
    pub reason: String,
}

impl Command for SuspendPolicy {
    type Aggregate = Policy;

    fn aggregate_id(&self) -> Option<EntityId<Self::Aggregate>> {
        Some(EntityId::from_uuid(self.policy_id))
    }
}

/// Reactivate a suspended policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReactivatePolicy {
    /// Policy ID
    pub policy_id: Uuid,
    /// Who reactivated it
    pub reactivated_by: Uuid,
}

impl Command for ReactivatePolicy {
    type Aggregate = Policy;

    fn aggregate_id(&self) -> Option<EntityId<Self::Aggregate>> {
        Some(EntityId::from_uuid(self.policy_id))
    }
}

/// Supersede a policy with another
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupersedePolicy {
    /// Policy ID being superseded
    pub old_policy_id: Uuid,
    /// New policy ID that supersedes this one
    pub new_policy_id: Uuid,
    /// Who made the change
    pub superseded_by: Uuid,
}

impl Command for SupersedePolicy {
    type Aggregate = Policy;

    fn aggregate_id(&self) -> Option<EntityId<Self::Aggregate>> {
        Some(EntityId::from_uuid(self.old_policy_id))
    }
}

/// Archive a policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchivePolicy {
    /// Policy ID
    pub policy_id: Uuid,
    /// Archive reason
    pub reason: Option<String>,
}

impl Command for ArchivePolicy {
    type Aggregate = Policy;

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
    /// Who requested it
    pub requested_by: Uuid,
    /// Request metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

impl Command for RequestPolicyExternalApproval {
    type Aggregate = Policy;

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
    pub verification: ExternalVerification,
}

impl Command for RecordPolicyExternalApproval {
    type Aggregate = Policy;

    fn aggregate_id(&self) -> Option<EntityId<Self::Aggregate>> {
        Some(EntityId::from_uuid(self.policy_id))
    }
}

/// Create a new policy (ECS command)
#[derive(Debug, Clone, Event)]
pub struct CreatePolicyCommand {
    pub name: String,
    pub description: String,
    pub policy_type: PolicyType,
    pub scope: PolicyScope,
}

/// Update policy status (ECS command)
#[derive(Debug, Clone, Event)]
pub struct UpdatePolicyStatusCommand {
    pub policy_id: Uuid,
    pub new_status: PolicyStatus,
}

/// Enum to wrap all policy commands
#[derive(Debug, Clone)]
pub enum PolicyCommand {
    EnactPolicy(EnactPolicy),
    UpdatePolicyRules(UpdatePolicyRules),
    SubmitPolicyForApproval(SubmitPolicyForApproval),
    ApprovePolicy(ApprovePolicy),
    RejectPolicy(RejectPolicy),
    SuspendPolicy(SuspendPolicy),
    ReactivatePolicy(ReactivatePolicy),
    SupersedePolicy(SupersedePolicy),
    ArchivePolicy(ArchivePolicy),
    RequestPolicyExternalApproval(RequestPolicyExternalApproval),
    RecordPolicyExternalApproval(RecordPolicyExternalApproval),
    // Authentication commands
    RequestAuthentication(RequestAuthentication),
    ApplyAuthenticationPolicy(ApplyAuthenticationPolicy),
    DetermineAuthenticationType(DetermineAuthenticationType),
    StartMfaWorkflow(StartMfaWorkflow),
    CompleteAuthenticationFactor(CompleteAuthenticationFactor),
    MakeAuthenticationDecision(MakeAuthenticationDecision),
    CreateAuthenticationSession(CreateAuthenticationSession),
    TerminateAuthenticationSession(TerminateAuthenticationSession),
    UpdateAuthenticationRequirements(UpdateAuthenticationRequirements),
    ConfigureFederatedAuthentication(ConfigureFederatedAuthentication),
    HandleAuthenticationFailure(HandleAuthenticationFailure),
    RequestExternalAuthenticationApproval(RequestExternalAuthenticationApproval),
}
