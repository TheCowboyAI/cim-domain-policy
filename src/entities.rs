//! Entities in the policy domain

use crate::value_objects::*;
use crate::aggregate::ConflictResolution;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// A single rule within a policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub rule_type: RuleType,
    pub expression: RuleExpression,
    pub parameters: HashMap<String, Value>,
    pub severity: Severity,
    pub error_message: Option<String>,
    pub remediation_hint: Option<String>,
}

impl PolicyRule {
    /// Create a new rule
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        expression: RuleExpression,
        severity: Severity,
    ) -> Self {
        Self {
            id: Uuid::now_v7(),
            name: name.into(),
            description: description.into(),
            rule_type: RuleType::Constraint,
            expression,
            parameters: HashMap::new(),
            severity,
            error_message: None,
            remediation_hint: None,
        }
    }

    /// Helper to create a minimum key size rule
    pub fn min_key_size(bits: i64) -> Self {
        Self::new(
            "Minimum Key Size",
            format!("Key size must be at least {} bits", bits),
            RuleExpression::GreaterThanOrEqual {
                field: "key_size".to_string(),
                value: Value::Integer(bits),
            },
            Severity::Critical,
        )
    }

    /// Helper to create an allowed algorithms rule
    pub fn allowed_algorithms(algorithms: Vec<&str>) -> Self {
        Self::new(
            "Allowed Algorithms",
            format!("Algorithm must be one of: {:?}", algorithms),
            RuleExpression::In {
                field: "algorithm".to_string(),
                values: algorithms.into_iter().map(|s| Value::String(s.to_string())).collect(),
            },
            Severity::Critical,
        )
    }

    /// Helper to create a maximum validity period rule
    pub fn max_validity_days(days: i64) -> Self {
        Self::new(
            "Maximum Validity Period",
            format!("Certificate validity must not exceed {} days", days),
            RuleExpression::LessThanOrEqual {
                field: "validity_days".to_string(),
                value: Value::Integer(days),
            },
            Severity::High,
        )
    }
}

/// Type of policy rule
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleType {
    /// A constraint that must be satisfied
    Constraint,
    /// A requirement that must be present
    Requirement,
    /// A validation that checks format/structure
    Validation,
    /// An authorization check
    Authorization,
}

/// Result of evaluating a policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEvaluation {
    pub id: Uuid,
    pub policy_id: PolicyId,
    pub evaluated_at: DateTime<Utc>,
    pub context: EvaluationContext,
    pub rule_results: Vec<RuleResult>,
    pub overall_result: ComplianceResult,
    pub execution_time_ms: u64,
}

impl PolicyEvaluation {
    /// Create a new evaluation
    pub fn new(policy_id: PolicyId, context: EvaluationContext) -> Self {
        Self {
            id: Uuid::now_v7(),
            policy_id,
            evaluated_at: Utc::now(),
            context,
            rule_results: Vec::new(),
            overall_result: ComplianceResult::Compliant,
            execution_time_ms: 0,
        }
    }

    /// Add a rule result
    pub fn add_rule_result(&mut self, result: RuleResult) {
        if !result.passed {
            // Update overall result if any rule fails
            let violations = self.rule_results
                .iter()
                .filter(|r| !r.passed)
                .map(|r| r.to_violation())
                .collect();

            self.overall_result = ComplianceResult::NonCompliant { violations };
        }
        self.rule_results.push(result);
    }

    /// Check if evaluation passed
    pub fn is_compliant(&self) -> bool {
        self.overall_result.is_compliant()
    }

    /// Get all violations
    pub fn violations(&self) -> Vec<Violation> {
        self.rule_results
            .iter()
            .filter(|r| !r.passed)
            .map(|r| r.to_violation())
            .collect()
    }
}

/// Result of evaluating a single rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleResult {
    pub rule_id: Uuid,
    pub rule_name: String,
    pub passed: bool,
    pub message: String,
    pub severity: Severity,
    pub actual_value: Option<Value>,
    pub expected_value: Option<Value>,
}

impl RuleResult {
    /// Convert to a violation
    pub fn to_violation(&self) -> Violation {
        Violation {
            rule_id: self.rule_id,
            rule_description: self.rule_name.clone(),
            severity: self.severity,
            details: self.message.clone(),
            suggested_remediation: None,
        }
    }
}

/// Template for creating policies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyTemplate {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub category: String,
    pub parameters: Vec<TemplateParameter>,
    pub base_rules: Vec<PolicyRule>,
    pub default_enforcement: EnforcementLevel,
    pub tags: Vec<String>,
}

impl PolicyTemplate {
    /// Create a new template
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            id: Uuid::now_v7(),
            name: name.into(),
            description: description.into(),
            category: "General".to_string(),
            parameters: Vec::new(),
            base_rules: Vec::new(),
            default_enforcement: EnforcementLevel::Soft,
            tags: Vec::new(),
        }
    }

    /// Add a parameter to the template
    pub fn add_parameter(&mut self, parameter: TemplateParameter) {
        self.parameters.push(parameter);
    }
}

/// Parameter in a policy template
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateParameter {
    pub name: String,
    pub description: String,
    pub parameter_type: ParameterType,
    pub default_value: Option<Value>,
    pub required: bool,
    pub validation: Option<RuleExpression>,
}

/// Type of template parameter
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParameterType {
    String,
    Integer,
    Float,
    Boolean,
    StringList,
    IntegerList,
    Duration,
    DateTime,
}

/// Policy conflict between multiple policies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConflict {
    pub id: Uuid,
    pub policy_ids: Vec<PolicyId>,
    pub conflict_type: ConflictType,
    pub description: String,
    pub detected_at: DateTime<Utc>,
    pub resolution: Option<ConflictResolution>,
}

/// Type of policy conflict
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConflictType {
    /// Rules directly contradict each other
    Contradiction,
    /// Rules overlap but with different requirements
    Overlap,
    /// Rules create an impossible condition
    Impossible,
    /// Rules create ambiguity
    Ambiguous,
}