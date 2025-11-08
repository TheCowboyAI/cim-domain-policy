//! # CIM Domain Policy
//!
//! This domain provides comprehensive policy management for the CIM ecosystem.
//! It defines rules, constraints, and requirements that govern behavior across
//! all CIM components, with special focus on PKI, compliance, and access control.
//!
//! ## Core Concepts
//!
//! - **Policy**: A set of rules that must be followed
//! - **Rule**: A single constraint or requirement
//! - **Evaluation**: Checking if something complies with a policy
//! - **Enforcement**: Ensuring policies are applied
//! - **Exemption**: Authorized exception to a policy
//!
//! ## Usage
//!
//! ```rust
//! use cim_domain_policy::{Policy, PolicySet, PolicyExemption};
//!
//! // Create a policy using pure functional approach
//! let policy = Policy::new("Security Policy", "All users must use MFA");
//! assert_eq!(policy.name, "Security Policy");
//!
//! // Create a policy set
//! let policy_set = PolicySet::new("Security Policies", "Organization security policies");
//! assert_eq!(policy_set.policies.len(), 0);
//!
//! // Create a policy exemption
//! use chrono::{Utc, Duration};
//! use cim_domain_policy::value_objects::PolicyId;
//! let exemption = PolicyExemption::new(
//!     PolicyId::new(),
//!     "Service account",
//!     "No MFA for API keys",
//!     "security-admin",
//!     Utc::now() + Duration::days(90),
//! );
//! ```

pub mod adapters;
pub mod aggregate;
pub mod commands;
pub mod entities;
pub mod events;
pub mod infrastructure;
pub mod ports;
pub mod sagas;
pub mod services;
pub mod value_objects;

// Re-export main types
pub use aggregate::{Policy, PolicySet, PolicyExemption, ConflictResolution, CompositionRule};
pub use commands::{PolicyCommand, CreatePolicy, UpdatePolicy, EvaluatePolicy, EnforcementAction};
pub use entities::{PolicyRule, PolicyEvaluation};
pub use events::{PolicyEvent, PolicyCreated, PolicyEvaluated, PolicyViolationDetected};
pub use value_objects::{
    PolicyId, PolicyStatus, PolicyTarget, EnforcementLevel,
    ComplianceResult, RuleExpression, Severity, EvaluationContext, Value, Violation,
};
pub use services::{PolicyEvaluator, PolicyConflictResolver};

// Domain-specific error types
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("Policy not found: {0}")]
    PolicyNotFound(uuid::Uuid),

    #[error("Policy validation failed: {0}")]
    ValidationError(String),

    #[error("Policy conflict detected: {0}")]
    ConflictError(String),

    #[error("Policy evaluation failed: {0}")]
    EvaluationError(String),

    #[error("Policy enforcement failed: {0}")]
    EnforcementError(String),

    #[error("Invalid rule expression: {0}")]
    InvalidRuleExpression(String),

    #[error("Unauthorized policy operation: {0}")]
    UnauthorizedOperation(String),
}

pub type PolicyResult<T> = Result<T, PolicyError>;