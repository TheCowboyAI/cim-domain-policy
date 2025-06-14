//! Integration tests for authentication flow across domains
//!
//! Tests the complete authentication flow from Policy domain through
//! Identity, Location, and Workflow domains.

use cim_domain_policy::{
    aggregate::Policy,
    aggregate::authentication::*,
    commands::authentication::*,
    handlers::AuthenticationCommandHandler,
    value_objects::authentication::*,
};
use cim_domain::{
    AggregateRepository, InMemoryRepository,
    EntityId,
};
use uuid::Uuid;
use std::collections::HashMap;
use chrono::Duration;

/// Test the complete authentication request flow
#[test]
fn test_authentication_request_flow() {
    // Setup
    let policy_repo = InMemoryRepository::<Policy>::new();
    let handler = AuthenticationCommandHandler::new(policy_repo);

    // Create authentication request command
    let request_id = Uuid::new_v4();
    let cmd = RequestAuthentication {
        request_id,
        identity_ref: Some(IdentityRef::Person(Uuid::new_v4())),
        location: LocationContext {
            ip_address: Some("10.0.0.1".to_string()),
            coordinates: None,
            country: Some("US".to_string()),
            network_type: Some("corporate".to_string()),
            device_id: Some("device-123".to_string()),
        },
        available_factors: vec![
            AuthenticationFactor::Password,
            AuthenticationFactor::Otp,
        ],
        client_metadata: HashMap::new(),
    };

    // Execute command
    let events = handler.handle_request_authentication(cmd).unwrap();

    // Verify event was created
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type(), "AuthenticationRequested");
}

/// Test authentication type determination
#[test]
fn test_authentication_type_determination() {
    // Setup
    let policy_repo = InMemoryRepository::<Policy>::new();
    let handler = AuthenticationCommandHandler::new(policy_repo);

    // Test internal authentication (corporate email + corporate network)
    let cmd = DetermineAuthenticationType {
        request_id: Uuid::new_v4(),
        identity_ref: Some(IdentityRef::Person(Uuid::new_v4())),
        location: LocationContext {
            ip_address: Some("10.0.0.1".to_string()),
            coordinates: None,
            country: Some("US".to_string()),
            network_type: Some("corporate".to_string()),
            device_id: None,
        },
        email: Some("user@company.com".to_string()),
    };

    let events = handler.handle_determine_authentication_type(cmd).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type(), "AuthenticationTypeDetermined");

    // Test external authentication
    let cmd = DetermineAuthenticationType {
        request_id: Uuid::new_v4(),
        identity_ref: Some(IdentityRef::Person(Uuid::new_v4())),
        location: LocationContext {
            ip_address: Some("192.168.1.1".to_string()),
            coordinates: None,
            country: Some("US".to_string()),
            network_type: Some("home".to_string()),
            device_id: None,
        },
        email: Some("user@gmail.com".to_string()),
    };

    let events = handler.handle_determine_authentication_type(cmd).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type(), "AuthenticationTypeDetermined");
}

/// Test MFA workflow initiation
#[test]
fn test_mfa_workflow_start() {
    // Setup
    let mut policy_repo = InMemoryRepository::<Policy>::new();

    // Create a policy with authentication requirements
    let policy_id = Uuid::new_v4();
    let mut policy = Policy::new_with_defaults(policy_id);

    // Add authentication requirements
    let requirements = AuthenticationRequirementsComponent {
        min_factors: 2,
        required_factors: vec![AuthenticationFactor::Password],
        optional_factors: vec![
            AuthenticationFactor::Otp,
            AuthenticationFactor::Sms,
            AuthenticationFactor::Email,
        ],
        min_trust_level: TrustLevel::Medium,
        location_requirements: None,
        time_requirements: None,
        risk_adjustments: RiskAdjustments {
            risk_thresholds: HashMap::new(),
            risk_factors: vec![],
            default_action: RiskAction::Allow,
        },
    };
    policy.add_component(requirements).unwrap();
    policy_repo.save(&policy).unwrap();

    let handler = AuthenticationCommandHandler::new(policy_repo);

    // Start MFA workflow
    let cmd = StartMfaWorkflow {
        policy_id,
        request_id: Uuid::new_v4(),
        identity_ref: IdentityRef::Person(Uuid::new_v4()),
        required_factors: vec![
            AuthenticationFactor::Password,
            AuthenticationFactor::Otp,
        ],
        timeout: Duration::minutes(10),
    };

    let events = handler.handle_start_mfa_workflow(cmd).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type(), "MfaWorkflowStarted");
}

/// Test authentication decision making
#[test]
fn test_authentication_decision() {
    // Setup
    let mut policy_repo = InMemoryRepository::<Policy>::new();

    // Create a policy with authentication requirements
    let policy_id = Uuid::new_v4();
    let mut policy = Policy::new_with_defaults(policy_id);

    // Add authentication requirements
    let requirements = AuthenticationRequirementsComponent {
        min_factors: 2,
        required_factors: vec![AuthenticationFactor::Password],
        optional_factors: vec![AuthenticationFactor::Otp],
        min_trust_level: TrustLevel::Medium,
        location_requirements: None,
        time_requirements: None,
        risk_adjustments: RiskAdjustments {
            risk_thresholds: HashMap::new(),
            risk_factors: vec![],
            default_action: RiskAction::Allow,
        },
    };
    policy.add_component(requirements).unwrap();
    policy_repo.save(&policy).unwrap();

    let handler = AuthenticationCommandHandler::new(policy_repo);

    // Test successful authentication
    let cmd = MakeAuthenticationDecision {
        policy_id,
        request_id: Uuid::new_v4(),
        completed_factors: vec![
            CompletedFactor {
                factor: AuthenticationFactor::Password,
                completed_at: chrono::Utc::now(),
                verification_method: "password-hash".to_string(),
                metadata: HashMap::new(),
            },
            CompletedFactor {
                factor: AuthenticationFactor::Otp,
                completed_at: chrono::Utc::now(),
                verification_method: "totp".to_string(),
                metadata: HashMap::new(),
            },
        ],
        risk_assessment: RiskAssessment {
            risk_score: 0.2,
            risk_level: RiskLevel::Low,
            risk_factors: vec![],
            recommended_actions: vec![],
        },
    };

    let events = handler.handle_make_authentication_decision(cmd).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type(), "AuthenticationDecisionMade");

    // Test failed authentication (insufficient factors)
    let cmd = MakeAuthenticationDecision {
        policy_id,
        request_id: Uuid::new_v4(),
        completed_factors: vec![
            CompletedFactor {
                factor: AuthenticationFactor::Password,
                completed_at: chrono::Utc::now(),
                verification_method: "password-hash".to_string(),
                metadata: HashMap::new(),
            },
        ],
        risk_assessment: RiskAssessment {
            risk_score: 0.2,
            risk_level: RiskLevel::Low,
            risk_factors: vec![],
            recommended_actions: vec![],
        },
    };

    let events = handler.handle_make_authentication_decision(cmd).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type(), "AuthenticationDecisionMade");
}

/// Test session creation
#[test]
fn test_session_creation() {
    // Setup
    let mut policy_repo = InMemoryRepository::<Policy>::new();

    // Create a policy
    let policy_id = Uuid::new_v4();
    let policy = Policy::new_with_defaults(policy_id);
    policy_repo.save(&policy).unwrap();

    let handler = AuthenticationCommandHandler::new(policy_repo);

    // Create session
    let cmd = CreateAuthenticationSession {
        policy_id,
        identity_ref: IdentityRef::Person(Uuid::new_v4()),
        factors_used: vec![
            AuthenticationFactor::Password,
            AuthenticationFactor::Otp,
        ],
        trust_level: TrustLevel::High,
        session_duration: Duration::hours(8),
        location: LocationContext {
            ip_address: Some("10.0.0.1".to_string()),
            coordinates: None,
            country: Some("US".to_string()),
            network_type: Some("corporate".to_string()),
            device_id: Some("device-123".to_string()),
        },
    };

    let events = handler.handle_create_authentication_session(cmd).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type(), "AuthenticationSessionCreated");
}
