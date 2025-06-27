//! Policy approval components

use bevy_ecs::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Policy approval tracking component
#[derive(Component, Debug, Clone, Serialize, Deserialize)]
pub struct PolicyApproval {
    pub policy_id: Uuid,
    pub approval_id: Uuid,
    pub status: ApprovalStatus,
    pub submitted_at: DateTime<Utc>,
    pub submitted_by: String,
}

/// Current status of an approval request
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalStatus {
    Pending,
    InProgress,
    Approved,
    Rejected,
    Escalated,
    Expired,
}

/// Approval workflow configuration
#[derive(Component, Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalWorkflow {
    pub policy_id: Uuid,
    pub workflow_type: WorkflowType,
    pub required_approvers: Vec<String>,
    pub escalation_path: Vec<String>,
    pub timeout_hours: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkflowType {
    SingleApprover,
    AllApprovers,
    MajorityVote,
    Hierarchical,
    Custom,
}

/// Individual approval step in the workflow
#[derive(Component, Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalStep {
    pub approval_id: Uuid,
    pub step_id: Uuid,
    pub approver: String,
    pub decision: Option<ApprovalDecision>,
    pub decided_at: Option<DateTime<Utc>>,
    pub comments: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalDecision {
    Approve,
    Reject,
    RequestChanges,
    Escalate,
}

/// Requirements for policy approval
#[derive(Component, Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequirement {
    pub policy_id: Uuid,
    pub min_approvers: u32,
    pub required_roles: Vec<String>,
    pub required_certifications: Vec<String>,
    pub conflict_of_interest_rules: Vec<String>,
}

/// Historical record of approval actions
#[derive(Component, Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalHistory {
    pub policy_id: Uuid,
    pub approval_id: Uuid,
    pub action: ApprovalAction,
    pub actor: String,
    pub timestamp: DateTime<Utc>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalAction {
    Submitted,
    Reviewed,
    Approved,
    Rejected,
    Escalated,
    Withdrawn,
    Expired,
} 