//! Policy aggregates - the core domain models

use crate::entities::PolicyRule;
use crate::value_objects::*;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// The main Policy aggregate root
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: PolicyId,
    pub name: String,
    pub description: String,
    pub version: u32,
    pub status: PolicyStatus,
    pub rules: Vec<PolicyRule>,
    pub target: PolicyTarget,
    pub enforcement_level: EnforcementLevel,
    pub effective_date: Option<DateTime<Utc>>,
    pub expiry_date: Option<DateTime<Utc>>,
    pub parent_policy_id: Option<PolicyId>,
    pub metadata: PolicyMetadata,
}

impl Policy {
    /// Create a new policy
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            id: PolicyId::new(),
            name: name.into(),
            description: description.into(),
            version: 1,
            status: PolicyStatus::Draft,
            rules: Vec::new(),
            target: PolicyTarget::Global,
            enforcement_level: EnforcementLevel::Advisory,
            effective_date: None,
            expiry_date: None,
            parent_policy_id: None,
            metadata: PolicyMetadata::default(),
        }
    }

    /// Apply an event to create a new policy state (pure function)
    ///
    /// This is the core of event sourcing - deriving aggregate state from events.
    /// Each event transforms the policy into a new state without mutation.
    pub fn apply_event_pure(&self, event: &crate::events::PolicyEvent) -> Result<Self, crate::PolicyError> {
        use crate::events::PolicyEvent;

        let mut new_policy = self.clone();

        match event {
            PolicyEvent::PolicyCreated(e) => {
                new_policy.id = e.policy_id;
                new_policy.name = e.name.clone();
                new_policy.description = e.description.clone();
                new_policy.version = 1;
                new_policy.status = PolicyStatus::Draft;
                new_policy.rules = Vec::new();
                new_policy.target = PolicyTarget::Global;
                new_policy.enforcement_level = EnforcementLevel::Advisory;
                new_policy.effective_date = None;
                new_policy.expiry_date = None;
                new_policy.parent_policy_id = None;
                new_policy.metadata.created_at = e.created_at;
                new_policy.metadata.created_by = e.created_by.clone();
            }
            PolicyEvent::PolicyUpdated(e) => {
                new_policy.version = e.version;
                new_policy.metadata.last_modified_at = Some(e.updated_at);
                new_policy.metadata.last_modified_by = Some(e.updated_by.clone());
                // Changes are stored in metadata for audit trail
            }
            PolicyEvent::PolicyApproved(_e) => {
                new_policy.status = PolicyStatus::Approved;
            }
            PolicyEvent::PolicyActivated(e) => {
                new_policy.status = PolicyStatus::Active;
                new_policy.effective_date = Some(e.effective_from);
                new_policy.expiry_date = e.effective_until;
            }
            PolicyEvent::PolicySuspended(_e) => {
                new_policy.status = PolicyStatus::Suspended;
            }
            PolicyEvent::PolicyRevoked(_e) => {
                new_policy.status = PolicyStatus::Revoked;
            }
            PolicyEvent::PolicyArchived(_e) => {
                new_policy.status = PolicyStatus::Archived;
            }
            // Evaluation events don't modify the policy aggregate itself
            PolicyEvent::PolicyEvaluated(_) |
            PolicyEvent::PolicyViolationDetected(_) |
            PolicyEvent::PolicyCompliancePassed(_) => {
                // These events are for audit/reporting, don't change policy state
            }
            // Exemption events don't modify the policy aggregate
            PolicyEvent::PolicyExemptionGranted(_) |
            PolicyEvent::PolicyExemptionRevoked(_) |
            PolicyEvent::PolicyExemptionExpired(_) => {
                // These modify PolicyExemption aggregate, not Policy
            }
            // PolicySet events don't modify policy aggregate
            PolicyEvent::PolicySetCreated(_) |
            PolicyEvent::PolicyAddedToSet(_) |
            PolicyEvent::PolicyRemovedFromSet(_) |
            PolicyEvent::PolicyConflictDetected(_) => {
                // These modify PolicySet aggregate, not Policy
            }
        }

        Ok(new_policy)
    }

    /// Add a rule to the policy
    pub fn add_rule(&mut self, rule: PolicyRule) {
        self.rules.push(rule);
    }

    /// Update policy status
    pub fn update_status(&mut self, status: PolicyStatus) -> Result<(), crate::PolicyError> {
        // Validate state transitions
        match (self.status, status) {
            (PolicyStatus::Draft, PolicyStatus::UnderReview) => {},
            (PolicyStatus::UnderReview, PolicyStatus::Approved) => {},
            (PolicyStatus::UnderReview, PolicyStatus::Draft) => {}, // Send back for revision
            (PolicyStatus::Approved, PolicyStatus::Active) => {},
            (PolicyStatus::Active, PolicyStatus::Suspended) => {},
            (PolicyStatus::Suspended, PolicyStatus::Active) => {},
            (PolicyStatus::Active, PolicyStatus::Revoked) => {},
            (PolicyStatus::Suspended, PolicyStatus::Revoked) => {},
            (PolicyStatus::Revoked, PolicyStatus::Archived) => {},
            _ => {
                return Err(crate::PolicyError::ValidationError(
                    format!("Invalid status transition from {:?} to {:?}", self.status, status)
                ));
            }
        }

        self.status = status;
        Ok(())
    }

    /// Check if policy is currently effective
    pub fn is_effective(&self) -> bool {
        if self.status != PolicyStatus::Active {
            return false;
        }

        let now = Utc::now();

        if let Some(effective_date) = self.effective_date {
            if now < effective_date {
                return false;
            }
        }

        if let Some(expiry_date) = self.expiry_date {
            if now > expiry_date {
                return false;
            }
        }

        true
    }

    /// Create a new version of this policy
    pub fn create_version(&self) -> Self {
        let mut new_version = self.clone();
        new_version.id = PolicyId::new();
        new_version.version = self.version + 1;
        new_version.status = PolicyStatus::Draft;
        new_version.parent_policy_id = Some(self.id);
        new_version.metadata.created_at = Utc::now();
        new_version
    }
}

/// PolicySet aggregate - groups multiple policies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySet {
    pub id: PolicySetId,
    pub name: String,
    pub description: String,
    pub policies: Vec<PolicyId>,
    pub composition_rule: CompositionRule,
    pub conflict_resolution: ConflictResolution,
    pub status: PolicyStatus,
    pub metadata: PolicyMetadata,
}

impl PolicySet {
    /// Create a new policy set
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            id: PolicySetId::new(),
            name: name.into(),
            description: description.into(),
            policies: Vec::new(),
            composition_rule: CompositionRule::All,
            conflict_resolution: ConflictResolution::MostRestrictive,
            status: PolicyStatus::Draft,
            metadata: PolicyMetadata::default(),
        }
    }

    /// Apply an event to create a new policy set state (pure function)
    pub fn apply_event_pure(&self, event: &crate::events::PolicyEvent) -> Result<Self, crate::PolicyError> {
        use crate::events::PolicyEvent;

        let mut new_set = self.clone();

        match event {
            PolicyEvent::PolicySetCreated(e) => {
                new_set.id = e.policy_set_id;
                new_set.name = e.name.clone();
                new_set.description = e.description.clone();
                new_set.policies = Vec::new();
                new_set.composition_rule = CompositionRule::All;
                new_set.conflict_resolution = ConflictResolution::MostRestrictive;
                new_set.status = PolicyStatus::Draft;
                new_set.metadata.created_at = e.created_at;
                new_set.metadata.created_by = e.created_by.clone();
            }
            PolicyEvent::PolicyAddedToSet(e) => {
                if !new_set.policies.contains(&e.policy_id) {
                    new_set.policies.push(e.policy_id);
                }
            }
            PolicyEvent::PolicyRemovedFromSet(e) => {
                new_set.policies.retain(|id| id != &e.policy_id);
            }
            // Other events don't modify PolicySet aggregate
            PolicyEvent::PolicyCreated(_) |
            PolicyEvent::PolicyUpdated(_) |
            PolicyEvent::PolicyApproved(_) |
            PolicyEvent::PolicyActivated(_) |
            PolicyEvent::PolicySuspended(_) |
            PolicyEvent::PolicyRevoked(_) |
            PolicyEvent::PolicyArchived(_) |
            PolicyEvent::PolicyEvaluated(_) |
            PolicyEvent::PolicyViolationDetected(_) |
            PolicyEvent::PolicyCompliancePassed(_) |
            PolicyEvent::PolicyExemptionGranted(_) |
            PolicyEvent::PolicyExemptionRevoked(_) |
            PolicyEvent::PolicyExemptionExpired(_) |
            PolicyEvent::PolicyConflictDetected(_) => {
                // These don't modify PolicySet
            }
        }

        Ok(new_set)
    }

    /// Add a policy to the set
    pub fn add_policy(&mut self, policy_id: PolicyId) {
        if !self.policies.contains(&policy_id) {
            self.policies.push(policy_id);
        }
    }

    /// Remove a policy from the set
    pub fn remove_policy(&mut self, policy_id: &PolicyId) {
        self.policies.retain(|id| id != policy_id);
    }
}

/// How policies in a set are composed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompositionRule {
    /// All policies must be satisfied
    All,
    /// At least one policy must be satisfied
    Any,
    /// Majority of policies must be satisfied
    Majority,
    /// Specific number of policies must be satisfied
    AtLeast(usize),
}

/// How to resolve conflicts between policies
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConflictResolution {
    /// Use the most restrictive policy
    MostRestrictive,
    /// Use the least restrictive policy
    LeastRestrictive,
    /// Use the first policy in order
    FirstWins,
    /// Use the last policy in order
    LastWins,
    /// Fail if there's any conflict
    FailOnConflict,
}

/// PolicyExemption aggregate - authorized exception to a policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyExemption {
    pub id: ExemptionId,
    pub policy_id: PolicyId,
    pub reason: String,
    pub justification: String,
    pub risk_acceptance: Option<String>,
    pub approved_by: String,
    pub approved_at: DateTime<Utc>,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub scope: ExemptionScope,
    pub conditions: Vec<ExemptionCondition>,
    pub status: ExemptionStatus,
}

impl PolicyExemption {
    /// Create a new exemption
    pub fn new(
        policy_id: PolicyId,
        reason: impl Into<String>,
        justification: impl Into<String>,
        approved_by: impl Into<String>,
        valid_until: DateTime<Utc>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: ExemptionId::new(),
            policy_id,
            reason: reason.into(),
            justification: justification.into(),
            risk_acceptance: None,
            approved_by: approved_by.into(),
            approved_at: now,
            valid_from: now,
            valid_until,
            scope: ExemptionScope::Global,
            conditions: Vec::new(),
            status: ExemptionStatus::Active,
        }
    }

    /// Apply an event to create a new exemption state (pure function)
    pub fn apply_event_pure(&self, event: &crate::events::PolicyEvent) -> Result<Self, crate::PolicyError> {
        use crate::events::PolicyEvent;

        let mut new_exemption = self.clone();

        match event {
            PolicyEvent::PolicyExemptionGranted(e) => {
                new_exemption.id = e.exemption_id;
                new_exemption.policy_id = e.policy_id;
                new_exemption.reason = e.reason.clone();
                new_exemption.justification = String::new(); // Set from command
                new_exemption.risk_acceptance = e.risk_acceptance.clone();
                new_exemption.approved_by = e.granted_by.clone();
                new_exemption.approved_at = e.granted_at;
                new_exemption.valid_from = e.granted_at;
                new_exemption.valid_until = e.valid_until;
                new_exemption.scope = ExemptionScope::Global;
                new_exemption.conditions = Vec::new();
                new_exemption.status = ExemptionStatus::Active;
            }
            PolicyEvent::PolicyExemptionRevoked(e) => {
                new_exemption.status = ExemptionStatus::Revoked {
                    revoked_by: e.revoked_by.clone(),
                    revoked_at: e.revoked_at,
                    reason: e.reason.clone(),
                };
            }
            PolicyEvent::PolicyExemptionExpired(_e) => {
                new_exemption.status = ExemptionStatus::Expired;
            }
            // Other events don't modify PolicyExemption aggregate
            PolicyEvent::PolicyCreated(_) |
            PolicyEvent::PolicyUpdated(_) |
            PolicyEvent::PolicyApproved(_) |
            PolicyEvent::PolicyActivated(_) |
            PolicyEvent::PolicySuspended(_) |
            PolicyEvent::PolicyRevoked(_) |
            PolicyEvent::PolicyArchived(_) |
            PolicyEvent::PolicyEvaluated(_) |
            PolicyEvent::PolicyViolationDetected(_) |
            PolicyEvent::PolicyCompliancePassed(_) |
            PolicyEvent::PolicySetCreated(_) |
            PolicyEvent::PolicyAddedToSet(_) |
            PolicyEvent::PolicyRemovedFromSet(_) |
            PolicyEvent::PolicyConflictDetected(_) => {
                // These don't modify PolicyExemption
            }
        }

        Ok(new_exemption)
    }

    /// Check if exemption is currently valid
    pub fn is_valid(&self) -> bool {
        if self.status != ExemptionStatus::Active {
            return false;
        }

        let now = Utc::now();
        now >= self.valid_from && now <= self.valid_until
    }

    /// Revoke the exemption
    pub fn revoke(&mut self, revoked_by: impl Into<String>, reason: impl Into<String>) {
        self.status = ExemptionStatus::Revoked {
            revoked_by: revoked_by.into(),
            revoked_at: Utc::now(),
            reason: reason.into(),
        };
    }
}

/// Scope of an exemption
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ExemptionScope {
    /// Exemption applies globally
    Global,
    /// Exemption applies to specific organization
    Organization(Uuid),
    /// Exemption applies to specific user
    User(String),
    /// Exemption applies to specific resource
    Resource(String),
    /// Exemption applies to specific operation
    Operation(OperationType),
}

/// Conditions that must be met for exemption to apply
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExemptionCondition {
    pub field: String,
    pub operator: ConditionOperator,
    pub value: Value,
}

/// Operators for exemption conditions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConditionOperator {
    Equals,
    NotEquals,
    GreaterThan,
    LessThan,
    Contains,
    NotContains,
}

/// Status of an exemption
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ExemptionStatus {
    /// Exemption is active
    Active,
    /// Exemption has expired
    Expired,
    /// Exemption was revoked
    Revoked {
        revoked_by: String,
        revoked_at: DateTime<Utc>,
        reason: String,
    },
}