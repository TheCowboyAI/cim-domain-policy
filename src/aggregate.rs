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