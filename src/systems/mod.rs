//! ECS Systems for the Policy domain
//!
//! This module contains all systems that operate on policy components.
//! Systems implement the behavior and business logic of the domain.

pub mod lifecycle;
pub mod approval;
pub mod enforcement;
pub mod authentication;
pub mod evaluation;

// Re-export key systems
pub use lifecycle::{
    create_policy_system,
    update_policy_system,
    activate_policy_system,
    suspend_policy_system,
    archive_policy_system,
};

pub use approval::{
    submit_for_approval_system,
    process_approval_system,
    escalate_approval_system,
    complete_approval_system,
};

pub use enforcement::{
    enforce_policy_system,
    record_violation_system,
    remediate_violation_system,
    generate_compliance_report_system,
};

pub use authentication::{
    evaluate_auth_policy_system,
    challenge_authentication_system,
    validate_credentials_system,
    refresh_auth_context_system,
};

pub use evaluation::{
    evaluate_policy_system,
    resolve_conflicts_system,
    cache_decisions_system,
    audit_decisions_system,
}; 