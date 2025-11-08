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
//! use cim_domain_policy::{Policy, PolicyEvaluator, EvaluationContext};
//!
//! // Define a policy
//! let policy = Policy::new("key_generation_policy")
//!     .with_rule(Rule::min_key_size(2048))
//!     .with_rule(Rule::allowed_algorithms(vec!["RSA", "ECDSA"]));
//!
//! // Evaluate against the policy
//! let context = EvaluationContext::new()
//!     .with_field("key_size", 4096)
//!     .with_field("algorithm", "RSA");
//!
//! let result = PolicyEvaluator::evaluate(&policy, &context)?;
//! assert!(result.is_compliant());
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