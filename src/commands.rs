//! Commands for the policy domain

use crate::value_objects::*;
use chrono::{DateTime, Duration, Utc};
use cim_domain::{Command, EntityId, MessageIdentity};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::aggregate::{Policy, PolicySet};

/// Base command type for all policy operations
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command_type")]
pub enum PolicyCommand {
    // Policy lifecycle commands
    CreatePolicy(CreatePolicy),
    UpdatePolicy(UpdatePolicy),
    ApprovePolicy(ApprovePolicy),
    ActivatePolicy(ActivatePolicy),
    SuspendPolicy(SuspendPolicy),
    RevokePolicy(RevokePolicy),
    ArchivePolicy(ArchivePolicy),

    // Evaluation commands
    EvaluatePolicy(EvaluatePolicy),
    EnforcePolicy(EnforcePolicy),

    // Exemption commands
    RequestExemption(RequestExemption),
    GrantExemption(GrantExemption),
    RevokeExemption(RevokeExemption),

    // PolicySet commands
    CreatePolicySet(CreatePolicySet),
    AddPolicyToSet(AddPolicyToSet),
    RemovePolicyFromSet(RemovePolicyFromSet),
    ActivatePolicySet(ActivatePolicySet),
}

impl Command for PolicyCommand {
    type Aggregate = Policy;

    fn aggregate_id(&self) -> Option<EntityId<Self::Aggregate>> {
        match self {
            PolicyCommand::CreatePolicy(_) => None, // New aggregate
            PolicyCommand::UpdatePolicy(cmd) => Some(EntityId::from_uuid(cmd.policy_id.0)),
            PolicyCommand::ApprovePolicy(cmd) => Some(EntityId::from_uuid(cmd.policy_id.0)),
            PolicyCommand::ActivatePolicy(cmd) => Some(EntityId::from_uuid(cmd.policy_id.0)),
            PolicyCommand::SuspendPolicy(cmd) => Some(EntityId::from_uuid(cmd.policy_id.0)),
            PolicyCommand::RevokePolicy(cmd) => Some(EntityId::from_uuid(cmd.policy_id.0)),
            PolicyCommand::ArchivePolicy(cmd) => Some(EntityId::from_uuid(cmd.policy_id.0)),
            PolicyCommand::EvaluatePolicy(cmd) => Some(EntityId::from_uuid(cmd.policy_id.0)),
            PolicyCommand::EnforcePolicy(cmd) => Some(EntityId::from_uuid(cmd.policy_id.0)),
            PolicyCommand::RequestExemption(cmd) => Some(EntityId::from_uuid(cmd.policy_id.0)),
            PolicyCommand::GrantExemption(cmd) => Some(EntityId::from_uuid(cmd.policy_id.0)),
            PolicyCommand::RevokeExemption(_cmd) => None, // Exemption aggregate
            PolicyCommand::CreatePolicySet(_) => None, // PolicySet aggregate
            PolicyCommand::AddPolicyToSet(_) => None, // PolicySet aggregate
            PolicyCommand::RemovePolicyFromSet(_) => None, // PolicySet aggregate
            PolicyCommand::ActivatePolicySet(_) => None, // PolicySet aggregate
        }
    }
}

// Policy Lifecycle Commands

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePolicy {
    pub identity: MessageIdentity,
    pub name: String,
    pub description: String,
    pub rules: Vec<crate::entities::PolicyRule>,
    pub target: PolicyTarget,
    pub enforcement_level: EnforcementLevel,
    pub effective_date: Option<DateTime<Utc>>,
    pub expiry_date: Option<DateTime<Utc>>,
    pub tags: Vec<String>,
    pub created_by: String,
}

impl Command for CreatePolicy {
    type Aggregate = Policy;

    fn aggregate_id(&self) -> Option<EntityId<Self::Aggregate>> {
        None // Creating new aggregate
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdatePolicy {
    pub identity: MessageIdentity,
    pub policy_id: PolicyId,
    pub name: Option<String>,
    pub description: Option<String>,
    pub rules: Option<Vec<crate::entities::PolicyRule>>,
    pub target: Option<PolicyTarget>,
    pub enforcement_level: Option<EnforcementLevel>,
    pub effective_date: Option<DateTime<Utc>>,
    pub expiry_date: Option<DateTime<Utc>>,
    pub updated_by: String,
}

impl Command for UpdatePolicy {
    type Aggregate = Policy;

    fn aggregate_id(&self) -> Option<EntityId<Self::Aggregate>> {
        Some(EntityId::from_uuid(self.policy_id.0))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovePolicy {
    pub identity: MessageIdentity,
    pub policy_id: PolicyId,
    pub approved_by: String,
    pub approval_notes: Option<String>,
}

impl Command for ApprovePolicy {
    type Aggregate = Policy;

    fn aggregate_id(&self) -> Option<EntityId<Self::Aggregate>> {
        Some(EntityId::from_uuid(self.policy_id.0))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivatePolicy {
    pub identity: MessageIdentity,
    pub policy_id: PolicyId,
    pub activated_by: String,
    pub effective_immediately: bool,
    pub schedule_activation: Option<DateTime<Utc>>,
}

impl Command for ActivatePolicy {
    type Aggregate = Policy;

    fn aggregate_id(&self) -> Option<EntityId<Self::Aggregate>> {
        Some(EntityId::from_uuid(self.policy_id.0))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspendPolicy {
    pub identity: MessageIdentity,
    pub policy_id: PolicyId,
    pub suspended_by: String,
    pub reason: String,
    pub expected_resume_date: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokePolicy {
    pub identity: MessageIdentity,
    pub policy_id: PolicyId,
    pub revoked_by: String,
    pub reason: String,
    pub immediate: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchivePolicy {
    pub identity: MessageIdentity,
    pub policy_id: PolicyId,
    pub archived_by: String,
    pub retention_period_days: Option<u32>,
}

// Evaluation Commands

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluatePolicy {
    pub identity: MessageIdentity,
    pub policy_id: PolicyId,
    pub context: EvaluationContext,
    pub requester: String,
    pub purpose: String,
}

impl Command for EvaluatePolicy {
    type Aggregate = Policy;

    fn aggregate_id(&self) -> Option<EntityId<Self::Aggregate>> {
        Some(EntityId::from_uuid(self.policy_id.0))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcePolicy {
    pub identity: MessageIdentity,
    pub policy_id: PolicyId,
    pub target: PolicyTarget,
    pub context: HashMap<String, Value>,
    pub enforced_by: String,
    pub enforcement_action: EnforcementAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EnforcementAction {
    Block,
    Allow,
    AllowWithWarning,
    Redirect,
    Quarantine,
    Custom(String),
}

// Exemption Commands

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestExemption {
    pub identity: MessageIdentity,
    pub policy_id: PolicyId,
    pub requester: String,
    pub reason: String,
    pub justification: String,
    pub duration: Duration,
    pub scope: crate::aggregate::ExemptionScope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantExemption {
    pub identity: MessageIdentity,
    pub policy_id: PolicyId,
    pub requester: String,
    pub approver: String,
    pub reason: String,
    pub justification: String,
    pub risk_acceptance: Option<String>,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub conditions: Vec<crate::aggregate::ExemptionCondition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeExemption {
    pub identity: MessageIdentity,
    pub exemption_id: ExemptionId,
    pub revoked_by: String,
    pub reason: String,
}

// PolicySet Commands

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePolicySet {
    pub identity: MessageIdentity,
    pub name: String,
    pub description: String,
    pub initial_policies: Vec<PolicyId>,
    pub composition_rule: crate::aggregate::CompositionRule,
    pub conflict_resolution: crate::aggregate::ConflictResolution,
    pub created_by: String,
}

impl Command for CreatePolicySet {
    type Aggregate = PolicySet;

    fn aggregate_id(&self) -> Option<EntityId<Self::Aggregate>> {
        None // Creating new aggregate
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddPolicyToSet {
    pub identity: MessageIdentity,
    pub policy_set_id: PolicySetId,
    pub policy_id: PolicyId,
    pub added_by: String,
}

impl Command for AddPolicyToSet {
    type Aggregate = PolicySet;

    fn aggregate_id(&self) -> Option<EntityId<Self::Aggregate>> {
        Some(EntityId::from_uuid(self.policy_set_id.0))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemovePolicyFromSet {
    pub identity: MessageIdentity,
    pub policy_set_id: PolicySetId,
    pub policy_id: PolicyId,
    pub removed_by: String,
    pub reason: Option<String>,
}

impl Command for RemovePolicyFromSet {
    type Aggregate = PolicySet;

    fn aggregate_id(&self) -> Option<EntityId<Self::Aggregate>> {
        Some(EntityId::from_uuid(self.policy_set_id.0))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivatePolicySet {
    pub identity: MessageIdentity,
    pub policy_set_id: PolicySetId,
    pub activated_by: String,
}

impl Command for ActivatePolicySet {
    type Aggregate = PolicySet;

    fn aggregate_id(&self) -> Option<EntityId<Self::Aggregate>> {
        Some(EntityId::from_uuid(self.policy_set_id.0))
    }
}

// ============= Commands from GitHub version =============

/// Command to assign a policy to an entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssignPolicyCommand {
    pub identity: MessageIdentity,
    pub policy_id: PolicyId,
    pub entity_id: Uuid,
    pub entity_type: String,
    pub assigned_by: String,
    pub reason: Option<String>,
}

impl Command for AssignPolicyCommand {
    type Aggregate = Policy;

    fn aggregate_id(&self) -> Option<EntityId<Self::Aggregate>> {
        Some(EntityId::from_uuid(self.policy_id.0))
    }
}

/// Command to evaluate access based on claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluateAccessCommand {
    pub identity: MessageIdentity,
    pub subject: String,
    pub resource: String,
    pub action: String,
    pub claims: ClaimSet,
    pub context: HashMap<String, String>,
}

/// Command to revoke a policy assignment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokePolicyAssignmentCommand {
    pub identity: MessageIdentity,
    pub policy_id: PolicyId,
    pub entity_id: Uuid,
    pub revoked_by: String,
    pub reason: Option<String>,
}

impl Command for RevokePolicyAssignmentCommand {
    type Aggregate = Policy;

    fn aggregate_id(&self) -> Option<EntityId<Self::Aggregate>> {
        Some(EntityId::from_uuid(self.policy_id.0))
    }
}