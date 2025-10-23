//! Tests for human and automated authorization policies

use cim_domain_policy::*;
use cim_domain_policy::aggregate::*;
use cim_domain_policy::entities::*;
use cim_domain_policy::value_objects::*;
use cim_domain::DomainEvent;
use chrono::{Utc, Duration};
use uuid::Uuid;

#[test]
fn test_human_approval_required_policy() {
    // Policy requiring human approval for sensitive operations
    let mut policy = Policy::new(
        "Sensitive Operation Approval",
        "Requires human approval for sensitive operations"
    );

    policy.add_rule(PolicyRule::new(
        "Manager Approval Required",
        "Operations over $10,000 require manager approval",
        RuleExpression::And(vec![
            RuleExpression::GreaterThan {
                field: "amount".to_string(),
                value: Value::Float(10000.0),
            },
            RuleExpression::Exists {
                field: "manager_approval".to_string(),
            },
        ]),
        Severity::Critical,
    ));

    policy.add_rule(PolicyRule::new(
        "Director Approval for Large Amounts",
        "Operations over $50,000 require director approval",
        RuleExpression::And(vec![
            RuleExpression::GreaterThan {
                field: "amount".to_string(),
                value: Value::Float(50000.0),
            },
            RuleExpression::Exists {
                field: "director_approval".to_string(),
            },
        ]),
        Severity::Critical,
    ));

    policy.target = PolicyTarget::Operation(OperationType::Custom("financial_transaction".to_string()));
    policy.enforcement_level = EnforcementLevel::Hard;
    policy.status = PolicyStatus::Active;

    // Test transaction requiring manager approval
    let context_needs_manager = EvaluationContext::new()
        .with_field("amount", 15000.0)
        .with_field("requester", "john.doe@example.com");

    let evaluator = cim_domain_policy::services::PolicyEvaluator::new();
    let result = evaluator.evaluate(&policy, &context_needs_manager).unwrap();
    assert!(!result.is_compliant());
    assert_eq!(result.violations().len(), 1);

    // Test with manager approval
    let context_with_approval = EvaluationContext::new()
        .with_field("amount", 15000.0)
        .with_field("requester", "john.doe@example.com")
        .with_field("manager_approval", "manager@example.com");

    let result = evaluator.evaluate(&policy, &context_with_approval).unwrap();
    assert!(result.is_compliant());

    // Test large amount without director approval
    let context_needs_director = EvaluationContext::new()
        .with_field("amount", 75000.0)
        .with_field("manager_approval", "manager@example.com");

    let result = evaluator.evaluate(&policy, &context_needs_director).unwrap();
    assert!(!result.is_compliant());

    // Test with both approvals
    let context_fully_approved = EvaluationContext::new()
        .with_field("amount", 75000.0)
        .with_field("manager_approval", "manager@example.com")
        .with_field("director_approval", "director@example.com");

    let result = evaluator.evaluate(&policy, &context_fully_approved).unwrap();
    assert!(result.is_compliant());
}

#[test]
fn test_delegation_authorization_policy() {
    // Policy for delegation of authority
    let mut policy = Policy::new(
        "Delegation Authorization",
        "Controls who can delegate authority"
    );

    policy.add_rule(PolicyRule::new(
        "Delegation Chain Limit",
        "Authority cannot be delegated more than 2 levels",
        RuleExpression::LessThanOrEqual {
            field: "delegation_depth".to_string(),
            value: Value::Integer(2),
        },
        Severity::High,
    ));

    policy.add_rule(PolicyRule::new(
        "Delegation Expiry Required",
        "All delegations must have an expiry date",
        RuleExpression::And(vec![
            RuleExpression::Exists {
                field: "delegation_expires".to_string(),
            },
            RuleExpression::LessThanOrEqual {
                field: "delegation_duration_days".to_string(),
                value: Value::Integer(30),
            },
        ]),
        Severity::High,
    ));

    policy.add_rule(PolicyRule::new(
        "Delegation Scope Limited",
        "Delegated authority must be scoped to specific operations",
        RuleExpression::Exists {
            field: "delegation_scope".to_string(),
        },
        Severity::Critical,
    ));

    policy.status = PolicyStatus::Active;

    // Test valid delegation
    let valid_delegation = EvaluationContext::new()
        .with_field("delegation_depth", 1i64)
        .with_field("delegation_expires", "2025-02-01")
        .with_field("delegation_duration_days", 15i64)
        .with_field("delegation_scope", "approve_purchases");

    let evaluator = cim_domain_policy::services::PolicyEvaluator::new();
    let result = evaluator.evaluate(&policy, &valid_delegation).unwrap();
    assert!(result.is_compliant());

    // Test invalid delegation (too deep)
    let invalid_delegation = EvaluationContext::new()
        .with_field("delegation_depth", 3i64)
        .with_field("delegation_expires", "2025-02-01")
        .with_field("delegation_duration_days", 15i64)
        .with_field("delegation_scope", "approve_purchases");

    let result = evaluator.evaluate(&policy, &invalid_delegation).unwrap();
    assert!(!result.is_compliant());
}

#[test]
fn test_automated_event_driven_authorization() {
    // Policy that automatically authorizes based on events
    let mut policy = Policy::new(
        "Automated Authorization Policy",
        "Automatically approves requests based on event patterns"
    );

    // Auto-approve small transactions from verified users
    policy.add_rule(PolicyRule::new(
        "Auto-Approve Small Transactions",
        "Automatically approve transactions under $1000 from verified users",
        RuleExpression::And(vec![
            RuleExpression::LessThan {
                field: "amount".to_string(),
                value: Value::Float(1000.0),
            },
            RuleExpression::Equal {
                field: "user_verified".to_string(),
                value: Value::Bool(true),
            },
            RuleExpression::Equal {
                field: "risk_score".to_string(),
                value: Value::String("low".to_string()),
            },
        ]),
        Severity::Info,
    ));

    // Auto-deny high-risk transactions
    policy.add_rule(PolicyRule::new(
        "Auto-Deny High Risk",
        "Automatically deny high-risk transactions",
        RuleExpression::Or(vec![
            RuleExpression::Equal {
                field: "risk_score".to_string(),
                value: Value::String("high".to_string()),
            },
            RuleExpression::Equal {
                field: "fraud_detected".to_string(),
                value: Value::Bool(true),
            },
        ]),
        Severity::Critical,
    ));

    policy.enforcement_level = EnforcementLevel::Hard;
    policy.status = PolicyStatus::Active;

    // Test auto-approval scenario
    let auto_approve_context = EvaluationContext::new()
        .with_field("amount", 500.0)
        .with_field("user_verified", true)
        .with_field("risk_score", "low")
        .with_field("fraud_detected", false);

    let evaluator = cim_domain_policy::services::PolicyEvaluator::new();
    let result = evaluator.evaluate(&policy, &auto_approve_context).unwrap();
    // First rule passes (info level), second rule doesn't trigger
    assert!(result.is_compliant());

    // Test auto-deny scenario
    let auto_deny_context = EvaluationContext::new()
        .with_field("amount", 500.0)
        .with_field("user_verified", true)
        .with_field("risk_score", "high")
        .with_field("fraud_detected", false);

    let result = evaluator.evaluate(&policy, &auto_deny_context).unwrap();
    assert!(!result.is_compliant());
}

#[test]
fn test_time_based_authorization_policy() {
    // Policy with time-based constraints
    let mut policy = Policy::new(
        "Time-Based Access Policy",
        "Restricts operations to business hours"
    );

    policy.add_rule(PolicyRule::new(
        "Business Hours Only",
        "Sensitive operations only during business hours",
        RuleExpression::And(vec![
            RuleExpression::GreaterThanOrEqual {
                field: "hour_of_day".to_string(),
                value: Value::Integer(9),
            },
            RuleExpression::LessThan {
                field: "hour_of_day".to_string(),
                value: Value::Integer(17),
            },
            RuleExpression::In {
                field: "day_of_week".to_string(),
                values: vec![
                    Value::String("Monday".to_string()),
                    Value::String("Tuesday".to_string()),
                    Value::String("Wednesday".to_string()),
                    Value::String("Thursday".to_string()),
                    Value::String("Friday".to_string()),
                ],
            },
        ]),
        Severity::High,
    ));

    policy.add_rule(PolicyRule::new(
        "Emergency Override",
        "Allow emergency access with proper authorization",
        RuleExpression::Or(vec![
            RuleExpression::Equal {
                field: "emergency_override".to_string(),
                value: Value::Bool(true),
            },
            RuleExpression::Exists {
                field: "ciso_approval".to_string(),
            },
        ]),
        Severity::Critical,
    ));

    policy.status = PolicyStatus::Active;

    // Test during business hours
    let business_hours = EvaluationContext::new()
        .with_field("hour_of_day", 14i64)
        .with_field("day_of_week", "Wednesday")
        .with_field("operation", "modify_user_permissions");

    let evaluator = cim_domain_policy::services::PolicyEvaluator::new();
    let result = evaluator.evaluate(&policy, &business_hours).unwrap();
    assert!(result.is_compliant());

    // Test outside business hours without override
    let after_hours = EvaluationContext::new()
        .with_field("hour_of_day", 22i64)
        .with_field("day_of_week", "Wednesday")
        .with_field("operation", "modify_user_permissions");

    let result = evaluator.evaluate(&policy, &after_hours).unwrap();
    assert!(!result.is_compliant());

    // Test weekend with emergency override
    let emergency_weekend = EvaluationContext::new()
        .with_field("hour_of_day", 10i64)
        .with_field("day_of_week", "Saturday")
        .with_field("emergency_override", true)
        .with_field("operation", "restore_service");

    let result = evaluator.evaluate(&policy, &emergency_weekend).unwrap();
    // Emergency override should allow access
    assert!(result.is_compliant());
}

#[test]
fn test_role_based_authorization_policy() {
    // Policy for role-based access control
    let mut policy = Policy::new(
        "Role-Based Access Control",
        "Enforces role-based authorization"
    );

    policy.add_rule(PolicyRule::new(
        "Admin Role Required",
        "Administrative operations require admin role",
        RuleExpression::And(vec![
            RuleExpression::Equal {
                field: "operation_type".to_string(),
                value: Value::String("administrative".to_string()),
            },
            RuleExpression::In {
                field: "user_role".to_string(),
                values: vec![
                    Value::String("admin".to_string()),
                    Value::String("super_admin".to_string()),
                ],
            },
        ]),
        Severity::Critical,
    ));

    policy.add_rule(PolicyRule::new(
        "Separation of Duties",
        "Users cannot approve their own requests",
        RuleExpression::NotEqual {
            field: "requester".to_string(),
            value: Value::String("${approver}".to_string()), // Template variable
        },
        Severity::Critical,
    ));

    policy.add_rule(PolicyRule::new(
        "Minimum Role Level",
        "Operations require minimum role level",
        RuleExpression::GreaterThanOrEqual {
            field: "role_level".to_string(),
            value: Value::Integer(3),
        },
        Severity::High,
    ));

    policy.target = PolicyTarget::Role("*".to_string()); // All roles
    policy.status = PolicyStatus::Active;

    // Test admin accessing administrative function
    let admin_context = EvaluationContext::new()
        .with_field("operation_type", "administrative")
        .with_field("user_role", "admin")
        .with_field("role_level", 5i64)
        .with_field("requester", "admin@example.com")
        .with_field("approver", "other@example.com");

    let evaluator = cim_domain_policy::services::PolicyEvaluator::new();
    let result = evaluator.evaluate(&policy, &admin_context).unwrap();
    assert!(result.is_compliant());

    // Test non-admin trying administrative operation
    let user_context = EvaluationContext::new()
        .with_field("operation_type", "administrative")
        .with_field("user_role", "user")
        .with_field("role_level", 1i64);

    let result = evaluator.evaluate(&policy, &user_context).unwrap();
    assert!(!result.is_compliant());
}