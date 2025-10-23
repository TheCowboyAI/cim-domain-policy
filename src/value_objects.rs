//! Value objects for the policy domain
//!
//! These are immutable objects that represent concepts in the policy domain.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

/// Unique identifier for a policy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PolicyId(pub Uuid);

impl PolicyId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl From<Uuid> for PolicyId {
    fn from(id: Uuid) -> Self {
        Self(id)
    }
}

impl std::fmt::Display for PolicyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unique identifier for a policy set
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PolicySetId(pub Uuid);

impl PolicySetId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

/// Unique identifier for an exemption
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExemptionId(pub Uuid);

impl ExemptionId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

/// Status of a policy in its lifecycle
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyStatus {
    /// Policy is being drafted
    Draft,
    /// Policy is under review
    UnderReview,
    /// Policy has been approved
    Approved,
    /// Policy is active and being enforced
    Active,
    /// Policy is temporarily disabled
    Suspended,
    /// Policy is permanently disabled
    Revoked,
    /// Policy has been moved to archive
    Archived,
}

/// What/who a policy applies to
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PolicyTarget {
    /// Applies globally to everything
    Global,
    /// Applies to a specific organization
    Organization(Uuid),
    /// Applies to an organizational unit (department/team)
    OrganizationUnit(Uuid),
    /// Applies to a specific role
    Role(String),
    /// Applies to a type of resource
    Resource(ResourceType),
    /// Applies to a specific operation
    Operation(OperationType),
    /// Applies to multiple targets
    Composite(Vec<PolicyTarget>),
}

/// Types of resources policies can apply to
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ResourceType {
    Certificate,
    Key,
    Secret,
    Document,
    Service,
    Network,
    Custom(String),
}

/// Types of operations policies can govern
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum OperationType {
    // PKI operations
    CertificateIssuance,
    CertificateRenewal,
    CertificateRevocation,
    KeyGeneration,
    KeyRotation,
    KeyExport,

    // Access operations
    Read,
    Write,
    Delete,
    Execute,

    // Administrative operations
    CreatePolicy,
    ModifyPolicy,
    DeletePolicy,
    GrantExemption,

    Custom(String),
}

/// How strictly a policy should be enforced
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EnforcementLevel {
    /// Just a recommendation, no enforcement
    Advisory,
    /// Log violations but allow the action
    Soft,
    /// Block the action if policy is violated
    Hard,
    /// Block and alert security team
    Critical,
}

/// Severity of a policy rule
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Result of policy evaluation
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ComplianceResult {
    /// Fully compliant with all rules
    Compliant,
    /// Not compliant, with list of violations
    NonCompliant { violations: Vec<Violation> },
    /// Compliant due to an exemption
    CompliantWithExemption { exemption_id: ExemptionId },
    /// Partially compliant
    PartiallyCompliant { passed: usize, failed: usize },
}

impl ComplianceResult {
    pub fn is_compliant(&self) -> bool {
        matches!(
            self,
            ComplianceResult::Compliant | ComplianceResult::CompliantWithExemption { .. }
        )
    }
}

/// A policy violation
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Violation {
    pub rule_id: Uuid,
    pub rule_description: String,
    pub severity: Severity,
    pub details: String,
    pub suggested_remediation: Option<String>,
}

/// Expression that defines a policy rule
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RuleExpression {
    // Comparison operations
    Equal {
        field: String,
        value: Value
    },
    NotEqual {
        field: String,
        value: Value
    },
    GreaterThan {
        field: String,
        value: Value
    },
    GreaterThanOrEqual {
        field: String,
        value: Value
    },
    LessThan {
        field: String,
        value: Value
    },
    LessThanOrEqual {
        field: String,
        value: Value
    },

    // Logical operations
    And(Vec<RuleExpression>),
    Or(Vec<RuleExpression>),
    Not(Box<RuleExpression>),

    // Set operations
    In {
        field: String,
        values: Vec<Value>
    },
    NotIn {
        field: String,
        values: Vec<Value>
    },
    Contains {
        field: String,
        value: Value
    },

    // String operations
    Matches {
        field: String,
        pattern: String
    },
    StartsWith {
        field: String,
        prefix: String
    },
    EndsWith {
        field: String,
        suffix: String
    },

    // Existence checks
    Exists {
        field: String
    },
    NotExists {
        field: String
    },

    // Custom predicates for complex logic
    Custom {
        predicate: String,
        args: HashMap<String, Value>
    },
}

/// Value types that can be used in rule expressions
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Value {
    Null,
    Bool(bool),
    Integer(i64),
    Float(f64),
    String(String),
    DateTime(DateTime<Utc>),
    List(Vec<Value>),
    Map(HashMap<String, Value>),
}

// Manual implementations for Eq and Hash since f64 doesn't implement them
impl Eq for Value {}

impl std::hash::Hash for Value {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            Value::Null => 0.hash(state),
            Value::Bool(b) => {
                1.hash(state);
                b.hash(state);
            }
            Value::Integer(i) => {
                2.hash(state);
                i.hash(state);
            }
            Value::Float(f) => {
                3.hash(state);
                // Hash the bits of the float
                f.to_bits().hash(state);
            }
            Value::String(s) => {
                4.hash(state);
                s.hash(state);
            }
            Value::DateTime(dt) => {
                5.hash(state);
                dt.timestamp().hash(state);
                dt.timestamp_subsec_nanos().hash(state);
            }
            Value::List(list) => {
                6.hash(state);
                for item in list {
                    item.hash(state);
                }
            }
            Value::Map(map) => {
                7.hash(state);
                // Hash in sorted order for consistency
                let mut pairs: Vec<_> = map.iter().collect();
                pairs.sort_by_key(|(k, _)| k.as_str());
                for (k, v) in pairs {
                    k.hash(state);
                    v.hash(state);
                }
            }
        }
    }
}

/// Policy metadata
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyMetadata {
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub last_modified_by: Option<String>,
    pub last_modified_at: Option<DateTime<Utc>>,
    pub tags: Vec<String>,
    pub compliance_standards: Vec<String>,
    pub documentation_url: Option<String>,
}

impl Default for PolicyMetadata {
    fn default() -> Self {
        Self {
            created_by: String::new(),
            created_at: Utc::now(),
            last_modified_by: None,
            last_modified_at: None,
            tags: Vec::new(),
            compliance_standards: Vec::new(),
            documentation_url: None,
        }
    }
}

/// Context for policy evaluation
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvaluationContext {
    pub fields: HashMap<String, Value>,
    pub requester: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub environment: HashMap<String, String>,
}

impl EvaluationContext {
    pub fn new() -> Self {
        Self {
            fields: HashMap::new(),
            requester: None,
            timestamp: Utc::now(),
            environment: HashMap::new(),
        }
    }

    pub fn with_field(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.fields.insert(key.into(), value.into());
        self
    }

    pub fn get_field(&self, key: &str) -> Option<&Value> {
        self.fields.get(key)
    }
}

// Implement Into<Value> for common types
impl From<bool> for Value {
    fn from(v: bool) -> Self {
        Value::Bool(v)
    }
}

impl From<i32> for Value {
    fn from(v: i32) -> Self {
        Value::Integer(v as i64)
    }
}

impl From<i64> for Value {
    fn from(v: i64) -> Self {
        Value::Integer(v)
    }
}

impl From<f64> for Value {
    fn from(v: f64) -> Self {
        Value::Float(v)
    }
}

impl From<String> for Value {
    fn from(v: String) -> Self {
        Value::String(v)
    }
}

impl From<&str> for Value {
    fn from(v: &str) -> Self {
        Value::String(v.to_string())
    }
}

impl From<DateTime<Utc>> for Value {
    fn from(v: DateTime<Utc>) -> Self {
        Value::DateTime(v)
    }
}

// ============= Claims-Based Authorization (from GitHub version) =============

/// Policy effect - explicit Allow or Deny
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyEffect {
    Allow,
    Deny,
}

/// Resource pattern for matching resources
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ResourcePattern {
    pub pattern: String,
    pub pattern_type: PatternType,
}

impl ResourcePattern {
    pub fn new(pattern: String, pattern_type: PatternType) -> Self {
        Self { pattern, pattern_type }
    }

    pub fn matches(&self, resource: &str) -> bool {
        match self.pattern_type {
            PatternType::Exact => self.pattern == resource,
            PatternType::Prefix => resource.starts_with(&self.pattern),
            PatternType::Suffix => resource.ends_with(&self.pattern),
            PatternType::Glob => self.glob_matches(resource),
            PatternType::Regex => self.regex_matches(resource),
        }
    }

    fn glob_matches(&self, resource: &str) -> bool {
        // Simple glob matching: * matches any characters
        let pattern_parts: Vec<&str> = self.pattern.split('*').collect();
        if pattern_parts.is_empty() {
            return false;
        }

        let mut pos = 0;
        for (i, part) in pattern_parts.iter().enumerate() {
            if i == 0 && !self.pattern.starts_with('*') {
                if !resource.starts_with(part) {
                    return false;
                }
                pos = part.len();
            } else if i == pattern_parts.len() - 1 && !self.pattern.ends_with('*') {
                if !resource.ends_with(part) {
                    return false;
                }
            } else if let Some(index) = resource[pos..].find(part) {
                pos += index + part.len();
            } else {
                return false;
            }
        }
        true
    }

    fn regex_matches(&self, _resource: &str) -> bool {
        // TODO: Implement regex matching with regex crate
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PatternType {
    Exact,
    Prefix,
    Suffix,
    Glob,
    Regex,
}

/// Claim for attribute-based access control
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Claim {
    pub claim_type: String,
    pub claim_value: String,
}

impl Claim {
    pub fn new(claim_type: String, claim_value: String) -> Self {
        Self { claim_type, claim_value }
    }
}

/// Set of claims for a subject
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimSet {
    pub subject: String,
    pub claims: HashSet<Claim>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl ClaimSet {
    pub fn new(subject: String) -> Self {
        Self {
            subject,
            claims: HashSet::new(),
            issued_at: Utc::now(),
            expires_at: None,
        }
    }

    pub fn add_claim(&mut self, claim: Claim) {
        self.claims.insert(claim);
    }

    pub fn has_claim(&self, claim_type: &str, claim_value: &str) -> bool {
        self.claims.contains(&Claim::new(claim_type.to_string(), claim_value.to_string()))
    }

    pub fn is_valid(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            Utc::now() < expires_at
        } else {
            true
        }
    }
}

/// Policy condition for claims-based evaluation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyCondition {
    HasClaim { claim_type: String, claim_value: String },
    HasAnyClaim { claim_type: String },
    HasAllClaims { claims: Vec<Claim> },
    HasAnyClaims { claims: Vec<Claim> },
    And(Vec<PolicyCondition>),
    Or(Vec<PolicyCondition>),
    Not(Box<PolicyCondition>),
}

impl PolicyCondition {
    pub fn evaluate(&self, claims: &ClaimSet) -> bool {
        match self {
            PolicyCondition::HasClaim { claim_type, claim_value } => {
                claims.has_claim(claim_type, claim_value)
            }
            PolicyCondition::HasAnyClaim { claim_type } => {
                claims.claims.iter().any(|c| c.claim_type == *claim_type)
            }
            PolicyCondition::HasAllClaims { claims: required } => {
                required.iter().all(|c| claims.claims.contains(c))
            }
            PolicyCondition::HasAnyClaims { claims: required } => {
                required.iter().any(|c| claims.claims.contains(c))
            }
            PolicyCondition::And(conditions) => {
                conditions.iter().all(|c| c.evaluate(claims))
            }
            PolicyCondition::Or(conditions) => {
                conditions.iter().any(|c| c.evaluate(claims))
            }
            PolicyCondition::Not(condition) => {
                !condition.evaluate(claims)
            }
        }
    }
}