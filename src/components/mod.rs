//! ECS Components for the Policy domain
//!
//! This module contains all ECS components used in the policy domain.
//! Components represent the data/state of entities in the system.

pub mod policy;
pub mod approval;
pub mod enforcement;
pub mod authentication;
pub mod metadata;

// Re-export commonly used types
pub use policy::{
    PolicyEntity, PolicyType, PolicyStatus, PolicyScope,
    PolicyPriority, PolicyTarget, PolicyCondition, PolicyAction,
};

pub use approval::{
    PolicyApproval, ApprovalStatus, ApprovalWorkflow,
    ApprovalStep, ApprovalRequirement, ApprovalHistory,
};

pub use enforcement::{
    PolicyEnforcement, EnforcementMode, EnforcementResult,
    EnforcementContext, EnforcementMetrics, ViolationRecord,
};

pub use authentication::{
    AuthenticationPolicy, AuthMethod, AuthRequirement,
    AuthContext, AuthDecision, AuthChallenge,
};

pub use metadata::{
    PolicyMetadata, PolicyVersion, PolicyAuthor,
    PolicyTag, PolicyReference, PolicyAudit,
};

// Type aliases for common types
pub type PolicyId = uuid::Uuid;
pub type ApprovalId = uuid::Uuid;
pub type EnforcementId = uuid::Uuid;
pub type ViolationId = uuid::Uuid; 