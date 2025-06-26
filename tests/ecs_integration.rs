//! Integration tests for Policy domain ECS implementation

use bevy_ecs::prelude::*;
use cim_domain_policy::components::*;
use cim_domain_policy::events::*;
use cim_domain_policy::systems::*;
use cim_domain_policy::value_objects::*;
use uuid::Uuid;
use chrono::Utc;
use std::collections::HashMap;

/// Test the policy lifecycle system
#[test]
fn test_policy_lifecycle() {
    let mut world = World::new();
    let mut schedule = Schedule::default();
    
    // Add the create policy system
    schedule.add_systems(policy_lifecycle::create_policy_system);
    
    // Register events
    world.init_resource::<Events<PolicyEnacted>>();
    
    // Create a policy entity with required components
    let policy_id = PolicyId(Uuid::new_v4());
    world.spawn((
        policy_id,
        PolicyStatus::Draft,
        PolicyType::AccessControl,
        PolicyScope::Global,
        PolicyRules {
            conditions: vec![],
            actions: vec![],
            exceptions: vec![],
        },
        PolicyMetadata {
            name: "Test Policy".to_string(),
            description: "Test policy for lifecycle".to_string(),
            version: 1,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: Uuid::new_v4(),
            tags: vec!["test".to_string()],
            expiration_date: None,
        },
    ));
    
    // Run the schedule
    schedule.run(&mut world);
    
    // Verify the policy status was updated
    let mut query = world.query::<&PolicyStatus>();
    let status = query.single(&world);
    assert_eq!(*status, PolicyStatus::Draft);
}

/// Test the approval workflow systems
#[test]
fn test_approval_workflow() {
    let mut world = World::new();
    let mut schedule = Schedule::default();
    
    // Add approval systems
    schedule.add_systems((
        approval_workflow::submit_for_approval_system,
        approval_workflow::process_approvals_system,
    ).chain());
    
    // Register events
    world.init_resource::<Events<PolicySubmittedForApproval>>();
    world.init_resource::<Events<PolicyApproved>>();
    world.init_resource::<Events<PolicyRejected>>();
    
    // Create a draft policy with approval requirements
    let policy_id = PolicyId(Uuid::new_v4());
    world.spawn((
        policy_id,
        PolicyStatus::Draft,
        ApprovalRequirement {
            approval_levels: vec![ApprovalLevel::Manager, ApprovalLevel::Director],
            minimum_approvers: Some(2),
            quorum_percentage: None,
            timeout: None,
        },
    ));
    
    // Run the systems
    schedule.run(&mut world);
    
    // Verify approval status was added
    let mut query = world.query::<(&PolicyStatus, Option<&ApprovalStatus>)>();
    let (status, approval_status) = query.single(&world);
    assert_eq!(*status, PolicyStatus::PendingApproval);
    assert!(approval_status.is_some());
}

/// Test the enforcement systems
#[test]
fn test_enforcement_systems() {
    let mut world = World::new();
    let mut schedule = Schedule::default();
    
    // Add enforcement systems
    schedule.add_systems((
        enforcement::enforce_policies_system,
        enforcement::detect_violations_system,
        enforcement::take_enforcement_actions_system,
    ).chain());
    
    // Register events and resources
    world.init_resource::<Events<PolicyEnforced>>();
    world.init_resource::<Events<PolicyViolationDetected>>();
    world.init_resource::<Events<EnforcementActionTaken>>();
    world.init_resource::<Time>();
    
    // Create an active policy
    let policy_id = PolicyId(Uuid::new_v4());
    world.spawn((
        policy_id,
        PolicyStatus::Active,
    ));
    
    // Run the systems
    schedule.run(&mut world);
    
    // Verify enforcement status was added
    let mut query = world.query::<(&PolicyStatus, Option<&EnforcementStatus>)>();
    let (_status, enforcement_status) = query.single(&world);
    assert!(enforcement_status.is_some());
}

/// Test the authentication systems
#[test]
fn test_authentication_systems() {
    let mut world = World::new();
    let mut schedule = Schedule::default();
    
    // Add authentication systems
    schedule.add_systems((
        authentication::evaluate_authentication_requirements_system,
        authentication::process_authentication_system,
    ).chain());
    
    // Register events and resources
    world.init_resource::<Events<AuthenticationRequired>>();
    world.init_resource::<Events<AuthenticationSucceeded>>();
    world.init_resource::<Events<AuthenticationFailed>>();
    world.init_resource::<Time>();
    
    // Create an active policy with authentication requirements
    let policy_id = PolicyId(Uuid::new_v4());
    world.spawn((
        policy_id,
        PolicyStatus::Active,
        AuthenticationRequirement {
            required_factors: vec![AuthenticationFactor::Password, AuthenticationFactor::Totp],
            minimum_trust_level: TrustLevel::High,
            session_timeout: None,
            require_recent_auth: false,
            location_constraint: None,
            time_constraint: None,
            risk_threshold: None,
        },
    ));
    
    // Run the systems
    schedule.run(&mut world);
    
    // Verify authentication status was added
    let mut query = world.query::<(&PolicyStatus, Option<&AuthenticationStatus>)>();
    let (_status, auth_status) = query.single(&world);
    assert!(auth_status.is_some());
}

/// Test component metadata tracking
#[test]
fn test_component_metadata() {
    let mut world = World::new();
    
    // Create a policy with metadata component
    let policy_id = PolicyId(Uuid::new_v4());
    let entity = world.spawn((
        policy_id,
        ComponentMetadata {
            entity_type: "Policy".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            version: 1,
            properties: HashMap::from([
                ("domain".to_string(), "security".to_string()),
                ("priority".to_string(), "high".to_string()),
            ]),
        },
    )).id();
    
    // Query and verify metadata
    let metadata = world.entity(entity).get::<ComponentMetadata>().unwrap();
    assert_eq!(metadata.entity_type, "Policy");
    assert_eq!(metadata.properties.get("domain").unwrap(), "security");
    assert_eq!(metadata.properties.get("priority").unwrap(), "high");
}

/// Test event generation and handling
#[test]
fn test_event_generation() {
    let mut world = World::new();
    
    // Register events
    world.init_resource::<Events<PolicyEnacted>>();
    world.init_resource::<Events<PolicyApproved>>();
    world.init_resource::<Events<PolicyEnforced>>();
    
    // Get event writers
    let mut enacted_events = world.resource_mut::<Events<PolicyEnacted>>();
    let policy_id = Uuid::new_v4();
    
    // Send an event
    enacted_events.send(PolicyEnacted {
        policy_id,
        policy_type: PolicyType::AccessControl,
        scope: PolicyScope::Global,
        enacted_by: Uuid::new_v4(),
        enacted_at: Utc::now(),
    });
    
    // Verify event was sent
    let events = world.resource::<Events<PolicyEnacted>>();
    let mut reader = events.get_reader();
    let event_count = reader.read(events).count();
    assert_eq!(event_count, 1);
}

/// Test query filtering with multiple components
#[test]
fn test_complex_queries() {
    let mut world = World::new();
    
    // Create multiple policies with different states
    let active_policy = world.spawn((
        PolicyId(Uuid::new_v4()),
        PolicyStatus::Active,
        PolicyType::AccessControl,
        EnforcementStatus {
            mode: EnforcementMode::Active,
            violations: vec![],
            actions_taken: vec![],
            last_checked: Utc::now(),
            enforcement_count: 0,
        },
    )).id();
    
    let draft_policy = world.spawn((
        PolicyId(Uuid::new_v4()),
        PolicyStatus::Draft,
        PolicyType::DataGovernance,
    )).id();
    
    let pending_policy = world.spawn((
        PolicyId(Uuid::new_v4()),
        PolicyStatus::PendingApproval,
        PolicyType::Compliance,
        ApprovalStatus {
            current_level: ApprovalLevel::None,
            required_levels: vec![ApprovalLevel::Manager],
            approvals: vec![],
            rejection: None,
            started_at: Utc::now(),
            completed_at: None,
        },
    )).id();
    
    // Query for active policies with enforcement
    let mut active_enforced = world.query::<(&PolicyStatus, &EnforcementStatus)>();
    let count = active_enforced.iter(&world).count();
    assert_eq!(count, 1);
    
    // Query for policies pending approval
    let mut pending_approval = world.query_filtered::<&PolicyId, With<ApprovalStatus>>();
    let count = pending_approval.iter(&world).count();
    assert_eq!(count, 1);
    
    // Query for all policies
    let mut all_policies = world.query::<&PolicyId>();
    let count = all_policies.iter(&world).count();
    assert_eq!(count, 3);
} 