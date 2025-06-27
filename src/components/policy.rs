//! Core policy components

use bevy_ecs::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Core policy entity component
#[derive(Component, Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEntity {
    pub policy_id: Uuid,
    pub policy_type: PolicyType,
    pub status: PolicyStatus,
    pub version: u32,
}

/// Type of policy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyType {
    /// Access control policy
    AccessControl,
    /// Data governance policy
    DataGovernance,
    /// Security policy
    Security,
    /// Compliance policy
    Compliance,
    /// Business rule policy
    BusinessRule,
    /// Custom policy type
    Custom(u32),
}

/// Current status of a policy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyStatus {
    /// Policy is in draft state
    Draft,
    /// Policy is pending approval
    PendingApproval,
    /// Policy is approved and active
    Active,
    /// Policy is suspended
    Suspended,
    /// Policy is archived
    Archived,
}

/// Scope of policy application
#[derive(Component, Debug, Clone, Serialize, Deserialize)]
pub struct PolicyScope {
    pub policy_id: Uuid,
    pub scope_type: ScopeType,
    pub targets: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScopeType {
    Global,
    Organization,
    Department,
    Team,
    Individual,
    Resource,
}

/// Priority level for policy evaluation
#[derive(Component, Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PolicyPriority {
    pub policy_id: Uuid,
    pub priority: u32,
    pub override_lower: bool,
}

/// Target entities or resources for the policy
#[derive(Component, Debug, Clone, Serialize, Deserialize)]
pub struct PolicyTarget {
    pub policy_id: Uuid,
    pub target_type: TargetType,
    pub target_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TargetType {
    User,
    Role,
    Resource,
    Service,
    Data,
    All,
}

/// Conditions that must be met for policy to apply
#[derive(Component, Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCondition {
    pub policy_id: Uuid,
    pub condition_type: ConditionType,
    pub expression: String,
    pub parameters: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConditionType {
    TimeWindow,
    LocationBased,
    AttributeBased,
    RiskLevel,
    Custom,
}

/// Actions to take when policy is triggered
#[derive(Component, Debug, Clone, Serialize, Deserialize)]
pub struct PolicyAction {
    pub policy_id: Uuid,
    pub action_type: ActionType,
    pub parameters: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionType {
    Allow,
    Deny,
    RequireApproval,
    Log,
    Alert,
    Remediate,
    Custom,
} 