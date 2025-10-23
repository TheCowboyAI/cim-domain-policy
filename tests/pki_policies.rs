//! Tests for PKI-specific policies

use cim_domain_policy::*;
use cim_domain_policy::aggregate::*;
use cim_domain_policy::entities::*;
use cim_domain_policy::value_objects::*;
use chrono::Utc;
use uuid::Uuid;

#[test]
fn test_certificate_issuance_policy() {
    // Create a PKI certificate issuance policy
    let mut policy = Policy::new(
        "Certificate Issuance Policy",
        "Controls certificate generation requirements"
    );

    // Add key size requirements
    policy.add_rule(PolicyRule::min_key_size(2048));

    // Add algorithm restrictions
    policy.add_rule(PolicyRule::allowed_algorithms(vec!["RSA", "ECDSA"]));

    // Add validity period restrictions
    policy.add_rule(PolicyRule::max_validity_days(365));

    // Set enforcement to critical for PKI
    policy.enforcement_level = EnforcementLevel::Critical;
    policy.target = PolicyTarget::Operation(OperationType::CertificateIssuance);

    // Activate the policy
    policy.update_status(PolicyStatus::Approved).unwrap();
    policy.update_status(PolicyStatus::Active).unwrap();

    assert!(policy.is_effective());
    assert_eq!(policy.rules.len(), 3);
}

#[test]
fn test_evaluate_certificate_request() {
    // Create certificate issuance policy
    let mut policy = Policy::new(
        "Strict Certificate Policy",
        "Enforces strict certificate requirements"
    );

    policy.add_rule(PolicyRule::new(
        "Minimum RSA Key Size",
        "RSA keys must be at least 2048 bits",
        RuleExpression::And(vec![
            RuleExpression::Equal {
                field: "algorithm".to_string(),
                value: Value::String("RSA".to_string()),
            },
            RuleExpression::GreaterThanOrEqual {
                field: "key_size".to_string(),
                value: Value::Integer(2048),
            },
        ]),
        Severity::Critical,
    ));

    policy.add_rule(PolicyRule::new(
        "Maximum Validity",
        "Certificates cannot be valid for more than 90 days",
        RuleExpression::LessThanOrEqual {
            field: "validity_days".to_string(),
            value: Value::Integer(90),
        },
        Severity::High,
    ));

    policy.status = PolicyStatus::Active;

    // Test valid certificate request
    let valid_context = EvaluationContext::new()
        .with_field("algorithm", "RSA")
        .with_field("key_size", 2048i64)
        .with_field("validity_days", 30i64)
        .with_field("requester", "alice@example.com");

    let evaluator = cim_domain_policy::services::PolicyEvaluator::new();
    let result = evaluator.evaluate(&policy, &valid_context).unwrap();
    assert!(result.is_compliant());

    // Test invalid certificate request (key too small)
    let invalid_context = EvaluationContext::new()
        .with_field("algorithm", "RSA")
        .with_field("key_size", 1024i64)
        .with_field("validity_days", 30i64);

    let result = evaluator.evaluate(&policy, &invalid_context).unwrap();
    assert!(!result.is_compliant());
    assert_eq!(result.violations().len(), 1);
}

#[test]
fn test_key_rotation_policy() {
    // Policy for automatic key rotation
    let mut policy = Policy::new(
        "Key Rotation Policy",
        "Enforces periodic key rotation"
    );

    policy.add_rule(PolicyRule::new(
        "Maximum Key Age",
        "Keys must be rotated after 180 days",
        RuleExpression::LessThanOrEqual {
            field: "key_age_days".to_string(),
            value: Value::Integer(180),
        },
        Severity::High,
    ));

    policy.add_rule(PolicyRule::new(
        "Rotation Warning",
        "Warn when key age exceeds 150 days",
        RuleExpression::GreaterThan {
            field: "key_age_days".to_string(),
            value: Value::Integer(150),
        },
        Severity::Medium,
    ));

    policy.target = PolicyTarget::Operation(OperationType::KeyRotation);
    policy.enforcement_level = EnforcementLevel::Hard;
    policy.status = PolicyStatus::Active;

    // Test key that needs rotation
    let context = EvaluationContext::new()
        .with_field("key_id", "key-123")
        .with_field("key_age_days", 200i64);

    let evaluator = cim_domain_policy::services::PolicyEvaluator::new();
    let result = evaluator.evaluate(&policy, &context).unwrap();
    assert!(!result.is_compliant());

    // Verify both rules triggered
    let violations = result.violations();
    assert_eq!(violations.len(), 2);
    assert!(violations.iter().any(|v| v.severity == Severity::High));
    assert!(violations.iter().any(|v| v.severity == Severity::Medium));
}

#[test]
fn test_certificate_chain_validation_policy() {
    // Policy for validating certificate chains
    let mut policy = Policy::new(
        "Certificate Chain Policy",
        "Validates certificate trust chains"
    );

    policy.add_rule(PolicyRule::new(
        "Root CA Required",
        "Certificate chain must include trusted root CA",
        RuleExpression::Exists {
            field: "root_ca".to_string(),
        },
        Severity::Critical,
    ));

    policy.add_rule(PolicyRule::new(
        "Chain Depth Limit",
        "Certificate chain depth cannot exceed 3",
        RuleExpression::LessThanOrEqual {
            field: "chain_depth".to_string(),
            value: Value::Integer(3),
        },
        Severity::High,
    ));

    policy.add_rule(PolicyRule::new(
        "Intermediate CA Authorization",
        "Intermediate CAs must be explicitly authorized",
        RuleExpression::Equal {
            field: "intermediate_authorized".to_string(),
            value: Value::Bool(true),
        },
        Severity::Critical,
    ));

    policy.target = PolicyTarget::Operation(OperationType::CertificateIssuance);
    policy.status = PolicyStatus::Active;

    // Test valid chain
    let valid_chain = EvaluationContext::new()
        .with_field("root_ca", "trusted-root-ca")
        .with_field("chain_depth", 2i64)
        .with_field("intermediate_authorized", true);

    let evaluator = cim_domain_policy::services::PolicyEvaluator::new();
    let result = evaluator.evaluate(&policy, &valid_chain).unwrap();
    assert!(result.is_compliant());

    // Test invalid chain (too deep)
    let invalid_chain = EvaluationContext::new()
        .with_field("root_ca", "trusted-root-ca")
        .with_field("chain_depth", 5i64)
        .with_field("intermediate_authorized", true);

    let result = evaluator.evaluate(&policy, &invalid_chain).unwrap();
    assert!(!result.is_compliant());
}

#[test]
fn test_yubikey_provisioning_policy() {
    // Policy for YubiKey provisioning
    let mut policy = Policy::new(
        "YubiKey Provisioning Policy",
        "Controls YubiKey configuration requirements"
    );

    policy.add_rule(PolicyRule::new(
        "PIN Required",
        "YubiKey must have PIN configured",
        RuleExpression::Equal {
            field: "pin_configured".to_string(),
            value: Value::Bool(true),
        },
        Severity::Critical,
    ));

    policy.add_rule(PolicyRule::new(
        "Touch Policy",
        "Touch confirmation required for signing operations",
        RuleExpression::In {
            field: "touch_policy".to_string(),
            values: vec![
                Value::String("always".to_string()),
                Value::String("cached".to_string()),
            ],
        },
        Severity::High,
    ));

    policy.add_rule(PolicyRule::new(
        "Management Key Changed",
        "Default management key must be changed",
        RuleExpression::NotEqual {
            field: "management_key".to_string(),
            value: Value::String("default".to_string()),
        },
        Severity::Critical,
    ));

    policy.target = PolicyTarget::Resource(ResourceType::Key);
    policy.enforcement_level = EnforcementLevel::Critical;
    policy.status = PolicyStatus::Active;

    // Test compliant YubiKey configuration
    let compliant_config = EvaluationContext::new()
        .with_field("pin_configured", true)
        .with_field("touch_policy", "always")
        .with_field("management_key", "custom-key-hash");

    let evaluator = cim_domain_policy::services::PolicyEvaluator::new();
    let result = evaluator.evaluate(&policy, &compliant_config).unwrap();
    assert!(result.is_compliant());

    // Test non-compliant configuration
    let non_compliant = EvaluationContext::new()
        .with_field("pin_configured", false)
        .with_field("touch_policy", "never")
        .with_field("management_key", "default");

    let result = evaluator.evaluate(&policy, &non_compliant).unwrap();
    assert!(!result.is_compliant());
    assert_eq!(result.violations().len(), 3);
}

#[test]
fn test_nats_operator_key_policy() {
    // Policy for NATS operator key generation
    let mut policy = Policy::new(
        "NATS Operator Key Policy",
        "Requirements for NATS operator keys"
    );

    policy.add_rule(PolicyRule::new(
        "Ed25519 Required",
        "NATS keys must use Ed25519",
        RuleExpression::Equal {
            field: "algorithm".to_string(),
            value: Value::String("Ed25519".to_string()),
        },
        Severity::Critical,
    ));

    policy.add_rule(PolicyRule::new(
        "Offline Storage",
        "Operator keys must be stored offline",
        RuleExpression::Equal {
            field: "storage_location".to_string(),
            value: Value::String("offline".to_string()),
        },
        Severity::Critical,
    ));

    policy.add_rule(PolicyRule::new(
        "Multi-signature Required",
        "Operator modifications require multiple signatures",
        RuleExpression::GreaterThanOrEqual {
            field: "required_signatures".to_string(),
            value: Value::Integer(2),
        },
        Severity::High,
    ));

    policy.target = PolicyTarget::Composite(vec![
        PolicyTarget::Resource(ResourceType::Key),
        PolicyTarget::Role("nats-operator".to_string()),
    ]);
    policy.status = PolicyStatus::Active;

    // Test valid NATS operator configuration
    let valid_config = EvaluationContext::new()
        .with_field("algorithm", "Ed25519")
        .with_field("storage_location", "offline")
        .with_field("required_signatures", 3i64);

    let evaluator = cim_domain_policy::services::PolicyEvaluator::new();
    let result = evaluator.evaluate(&policy, &valid_config).unwrap();
    assert!(result.is_compliant());
}