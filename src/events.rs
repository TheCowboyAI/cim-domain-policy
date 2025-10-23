//! Events in the policy domain

use crate::value_objects::*;
use chrono::{DateTime, Utc};
use cim_domain::{DomainEvent, MessageIdentity};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Base event type for all policy events
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event_type")]
pub enum PolicyEvent {
    // Lifecycle events
    PolicyCreated(PolicyCreated),
    PolicyUpdated(PolicyUpdated),
    PolicyApproved(PolicyApproved),
    PolicyActivated(PolicyActivated),
    PolicySuspended(PolicySuspended),
    PolicyRevoked(PolicyRevoked),
    PolicyArchived(PolicyArchived),

    // Evaluation events
    PolicyEvaluated(PolicyEvaluated),
    PolicyViolationDetected(PolicyViolationDetected),
    PolicyCompliancePassed(PolicyCompliancePassed),

    // Exemption events
    PolicyExemptionGranted(PolicyExemptionGranted),
    PolicyExemptionRevoked(PolicyExemptionRevoked),
    PolicyExemptionExpired(PolicyExemptionExpired),

    // PolicySet events
    PolicySetCreated(PolicySetCreated),
    PolicyAddedToSet(PolicyAddedToSet),
    PolicyRemovedFromSet(PolicyRemovedFromSet),
    PolicyConflictDetected(PolicyConflictDetected),
}

impl DomainEvent for PolicyEvent {
    fn event_type(&self) -> &'static str {
        match self {
            PolicyEvent::PolicyCreated(_) => "PolicyCreated",
            PolicyEvent::PolicyUpdated(_) => "PolicyUpdated",
            PolicyEvent::PolicyApproved(_) => "PolicyApproved",
            PolicyEvent::PolicyActivated(_) => "PolicyActivated",
            PolicyEvent::PolicySuspended(_) => "PolicySuspended",
            PolicyEvent::PolicyRevoked(_) => "PolicyRevoked",
            PolicyEvent::PolicyArchived(_) => "PolicyArchived",
            PolicyEvent::PolicyEvaluated(_) => "PolicyEvaluated",
            PolicyEvent::PolicyViolationDetected(_) => "PolicyViolationDetected",
            PolicyEvent::PolicyCompliancePassed(_) => "PolicyCompliancePassed",
            PolicyEvent::PolicyExemptionGranted(_) => "PolicyExemptionGranted",
            PolicyEvent::PolicyExemptionRevoked(_) => "PolicyExemptionRevoked",
            PolicyEvent::PolicyExemptionExpired(_) => "PolicyExemptionExpired",
            PolicyEvent::PolicySetCreated(_) => "PolicySetCreated",
            PolicyEvent::PolicyAddedToSet(_) => "PolicyAddedToSet",
            PolicyEvent::PolicyRemovedFromSet(_) => "PolicyRemovedFromSet",
            PolicyEvent::PolicyConflictDetected(_) => "PolicyConflictDetected",
        }
    }

    fn aggregate_id(&self) -> Uuid {
        match self {
            PolicyEvent::PolicyCreated(e) => e.policy_id.0,
            PolicyEvent::PolicyUpdated(e) => e.policy_id.0,
            PolicyEvent::PolicyApproved(e) => e.policy_id.0,
            PolicyEvent::PolicyActivated(e) => e.policy_id.0,
            PolicyEvent::PolicySuspended(e) => e.policy_id.0,
            PolicyEvent::PolicyRevoked(e) => e.policy_id.0,
            PolicyEvent::PolicyArchived(e) => e.policy_id.0,
            PolicyEvent::PolicyEvaluated(e) => e.policy_id.0,
            PolicyEvent::PolicyViolationDetected(e) => e.policy_id.0,
            PolicyEvent::PolicyCompliancePassed(e) => e.policy_id.0,
            PolicyEvent::PolicyExemptionGranted(e) => e.policy_id.0,
            PolicyEvent::PolicyExemptionRevoked(e) => e.exemption_id.0,
            PolicyEvent::PolicyExemptionExpired(e) => e.exemption_id.0,
            PolicyEvent::PolicySetCreated(e) => e.policy_set_id.0,
            PolicyEvent::PolicyAddedToSet(e) => e.policy_set_id.0,
            PolicyEvent::PolicyRemovedFromSet(e) => e.policy_set_id.0,
            PolicyEvent::PolicyConflictDetected(e) => e.conflict_id,
        }
    }
}

// Lifecycle Events

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCreated {
    pub event_id: Uuid,
    pub identity: MessageIdentity,
    pub policy_id: PolicyId,
    pub name: String,
    pub description: String,
    pub policy_type: String,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyUpdated {
    pub event_id: Uuid,
    pub identity: MessageIdentity,
    pub policy_id: PolicyId,
    pub version: u32,
    pub changes: Vec<PolicyChange>,
    pub updated_by: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyChange {
    pub field: String,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyApproved {
    pub event_id: Uuid,
    pub identity: MessageIdentity,
    pub policy_id: PolicyId,
    pub approved_by: String,
    pub approved_at: DateTime<Utc>,
    pub approval_notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyActivated {
    pub event_id: Uuid,
    pub identity: MessageIdentity,
    pub policy_id: PolicyId,
    pub activated_by: String,
    pub activated_at: DateTime<Utc>,
    pub effective_from: DateTime<Utc>,
    pub effective_until: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySuspended {
    pub event_id: Uuid,
    pub identity: MessageIdentity,
    pub policy_id: PolicyId,
    pub suspended_by: String,
    pub suspended_at: DateTime<Utc>,
    pub reason: String,
    pub expected_resume_date: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRevoked {
    pub event_id: Uuid,
    pub identity: MessageIdentity,
    pub policy_id: PolicyId,
    pub revoked_by: String,
    pub revoked_at: DateTime<Utc>,
    pub reason: String,
    pub immediate: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyArchived {
    pub event_id: Uuid,
    pub identity: MessageIdentity,
    pub policy_id: PolicyId,
    pub archived_by: String,
    pub archived_at: DateTime<Utc>,
    pub retention_period_days: Option<u32>,
}

// Evaluation Events

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEvaluated {
    pub event_id: Uuid,
    pub identity: MessageIdentity,
    pub policy_id: PolicyId,
    pub evaluation_id: Uuid,
    pub evaluated_at: DateTime<Utc>,
    pub context_hash: String,
    pub result: ComplianceResult,
    pub execution_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyViolationDetected {
    pub event_id: Uuid,
    pub identity: MessageIdentity,
    pub policy_id: PolicyId,
    pub violation_id: Uuid,
    pub detected_at: DateTime<Utc>,
    pub violations: Vec<Violation>,
    pub severity: Severity,
    pub enforcement_action: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCompliancePassed {
    pub event_id: Uuid,
    pub identity: MessageIdentity,
    pub policy_id: PolicyId,
    pub evaluation_id: Uuid,
    pub passed_at: DateTime<Utc>,
    pub rules_evaluated: usize,
}

// Exemption Events

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyExemptionGranted {
    pub event_id: Uuid,
    pub identity: MessageIdentity,
    pub exemption_id: ExemptionId,
    pub policy_id: PolicyId,
    pub granted_by: String,
    pub granted_at: DateTime<Utc>,
    pub reason: String,
    pub valid_until: DateTime<Utc>,
    pub risk_acceptance: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyExemptionRevoked {
    pub event_id: Uuid,
    pub identity: MessageIdentity,
    pub exemption_id: ExemptionId,
    pub policy_id: PolicyId,
    pub revoked_by: String,
    pub revoked_at: DateTime<Utc>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyExemptionExpired {
    pub event_id: Uuid,
    pub identity: MessageIdentity,
    pub exemption_id: ExemptionId,
    pub policy_id: PolicyId,
    pub expired_at: DateTime<Utc>,
}

// PolicySet Events

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySetCreated {
    pub event_id: Uuid,
    pub identity: MessageIdentity,
    pub policy_set_id: PolicySetId,
    pub name: String,
    pub description: String,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyAddedToSet {
    pub event_id: Uuid,
    pub identity: MessageIdentity,
    pub policy_set_id: PolicySetId,
    pub policy_id: PolicyId,
    pub added_at: DateTime<Utc>,
    pub added_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRemovedFromSet {
    pub event_id: Uuid,
    pub identity: MessageIdentity,
    pub policy_set_id: PolicySetId,
    pub policy_id: PolicyId,
    pub removed_at: DateTime<Utc>,
    pub removed_by: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConflictDetected {
    pub event_id: Uuid,
    pub identity: MessageIdentity,
    pub conflict_id: Uuid,
    pub policy_ids: Vec<PolicyId>,
    pub conflict_type: String,
    pub description: String,
    pub detected_at: DateTime<Utc>,
    pub severity: Severity,
}

// ============= Events from GitHub version =============

/// Event: Policy was assigned to an entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyAssigned {
    pub event_id: Uuid,
    pub identity: MessageIdentity,
    pub policy_id: PolicyId,
    pub entity_id: Uuid,
    pub entity_type: String,
    pub assigned_by: String,
    pub reason: Option<String>,
    pub assigned_at: DateTime<Utc>,
}

/// Event: Access was granted based on policy evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessGranted {
    pub event_id: Uuid,
    pub identity: MessageIdentity,
    pub subject: String,
    pub resource: String,
    pub action: String,
    pub policy_id: PolicyId,
    pub matched_claims: Vec<Claim>,
    pub granted_at: DateTime<Utc>,
}

/// Event: Access was denied based on policy evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessDenied {
    pub event_id: Uuid,
    pub identity: MessageIdentity,
    pub subject: String,
    pub resource: String,
    pub action: String,
    pub policy_id: Option<PolicyId>,
    pub reason: String,
    pub missing_claims: Vec<String>,
    pub denied_at: DateTime<Utc>,
}

/// Event: Policy assignment was revoked
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyAssignmentRevoked {
    pub event_id: Uuid,
    pub identity: MessageIdentity,
    pub policy_id: PolicyId,
    pub entity_id: Uuid,
    pub revoked_by: String,
    pub reason: Option<String>,
    pub revoked_at: DateTime<Utc>,
}

/// Event: Claims were issued to a subject
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimsIssued {
    pub event_id: Uuid,
    pub identity: MessageIdentity,
    pub subject: String,
    pub claims: ClaimSet,
    pub issued_by: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Event: Claims were revoked for a subject
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimsRevoked {
    pub event_id: Uuid,
    pub identity: MessageIdentity,
    pub subject: String,
    pub claim_types: Vec<String>,
    pub revoked_by: String,
    pub reason: String,
    pub revoked_at: DateTime<Utc>,
}