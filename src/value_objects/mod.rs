//! Value objects for the Policy domain
//!
//! Value objects are immutable objects that represent domain concepts
//! with no identity. They are compared by their values, not by reference.

use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

// Re-export all value objects
pub use self::authentication::*;
pub use self::policy_types::*;

mod authentication;
mod policy_types;

/// Policy ID value object
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PolicyId(pub Uuid);

impl PolicyId {
    /// Create a new policy ID
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for PolicyId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for PolicyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Approval level
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ApprovalLevel {
    None,
    Team,
    Manager,
    Director,
    Executive,
    Board,
}

/// Approver role
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ApproverRole {
    PolicyOwner,
    DomainExpert,
    ComplianceOfficer,
    SecurityOfficer,
    Manager,
    Executive,
    External,
}

/// Violation type
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ViolationType {
    Unauthorized,
    DataBreach,
    ComplianceViolation,
    SecurityViolation,
    ProcessViolation,
    Other(String),
}

/// Violation severity
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ViolationSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Action type
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ActionType {
    Log,
    Alert,
    Warn,
    Block,
    Quarantine,
    Remediate,
    Custom(String),
}

/// Enforcement mode
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EnforcementMode {
    Disabled,
    Monitoring,
    Active,
    Strict,
}

/// Enforcement result
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EnforcementResult {
    Success,
    Failure(String),
    PartialSuccess(String),
    Skipped(String),
}

/// External verification data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalVerification {
    pub provider: String,
    pub reference_id: String,
    pub verification_data: serde_json::Value,
    pub verified_at: chrono::DateTime<chrono::Utc>,
}

impl fmt::Display for ExternalVerification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.provider, self.reference_id)
    }
}

/// Enforcement metrics
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnforcementMetrics {
    pub total_evaluations: u64,
    pub successful_enforcements: u64,
    pub failed_enforcements: u64,
    pub average_enforcement_time_ms: f64,
}

// Re-export authentication types
pub use authentication::{
    AuthenticationFactor, BiometricType, TokenType,
    TrustLevel, AuthenticationDecision, DenialReason,
    LocationConstraint, IpNetwork, GeoRegion,
    TimeConstraint, TimeRange, DateRange,
    AuthenticationContext, IdentityRef, LocationContext,
    GeoCoordinates, InternalCriteria, ExternalHandling,
    ExternalProvider, ProviderType, IdentityVerificationLevel,
    RiskConfiguration, RiskFactor, RiskLevel, RiskAction,
};
