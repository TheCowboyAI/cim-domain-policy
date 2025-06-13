//! Policy domain module
//!
//! This module contains all policy-related domain logic including:
//! - Policy aggregate and components
//! - Policy commands and events
//! - Policy command and query handlers

pub mod aggregate;
pub mod commands;
pub mod events;
pub mod handlers;
pub mod projections;
pub mod queries;
pub mod value_objects;

// Re-export main types
pub use aggregate::{
    Policy, PolicyMarker, PolicyMetadata, PolicyStatus, PolicyType,
    PolicyScope, PolicyException, ViolationSeverity, EnforcementMode,
    RulesComponent, ApprovalRequirementsComponent, ApprovalStateComponent,
    EnforcementComponent, ExternalApprovalRequirement, Approval, Rejection,
    PendingExternalApproval, ExternalVerification, ViolationAction,
};

pub use commands::{
    EnactPolicy, UpdatePolicyRules, SubmitPolicyForApproval,
    ApprovePolicy, RejectPolicy, SuspendPolicy, ReactivatePolicy,
    SupersedePolicy, ArchivePolicy, RequestPolicyExternalApproval,
    RecordPolicyExternalApproval,
};

pub use events::{
    PolicyEnacted, PolicySubmittedForApproval, PolicyApproved,
    PolicyRejected, PolicySuspended, PolicyReactivated,
    PolicySuperseded, PolicyArchived, PolicyExternalApprovalRequested,
    PolicyExternalApprovalReceived,
};

pub use handlers::{PolicyCommandHandler, PolicyEventHandler};
pub use projections::PolicyView;
pub use queries::{PolicyQuery, PolicyQueryHandler, FindActivePolicies};
