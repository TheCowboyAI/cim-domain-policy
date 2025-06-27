//! ECS integration tests for the policy domain
//!
//! ## Test Coverage
//!
//! ```mermaid
//! graph TD
//!     A[Policy ECS Tests] --> B[Component Tests]
//!     A --> C[System Tests]
//!     A --> D[Event Flow Tests]
//!     
//!     B --> B1[PolicyEntity Creation]
//!     B --> B2[Approval Components]
//!     B --> B3[Enforcement Components]
//!     
//!     C --> C1[Lifecycle Systems]
//!     C --> C2[Approval Systems]
//!     C --> C3[Enforcement Systems]
//!     
//!     D --> D1[Command to Event]
//!     D --> D2[Event to Component]
//!     D --> D3[Component to Query]
//! ```

use bevy_ecs::prelude::*;
use cim_domain_policy::components::*;
use cim_domain_policy::components::policy::{ScopeType, PolicyType, PolicyStatus};
use cim_domain_policy::components::approval::{ApprovalDecision, WorkflowType};
use cim_domain_policy::components::enforcement::{Decision, ViolationSeverity};
use cim_domain_policy::systems::*;
use cim_domain_policy::systems::approval::ApprovalStepEvent;
use cim_domain_policy::systems::enforcement::{EnforcementRequest, ViolationDetected};
use cim_domain_policy::events::*;
use uuid::Uuid;
use chrono::Utc;

/// Helper to create a test ECS world
fn create_test_world() -> World {
    let mut world = World::new();
    
    // Register events
    world.insert_resource(Events::<PolicyCreated>::default());
    world.insert_resource(Events::<PolicyUpdated>::default());
    world.insert_resource(Events::<PolicyActivated>::default());
    world.insert_resource(Events::<PolicySubmittedForApproval>::default());
    world.insert_resource(Events::<PolicyApproved>::default());
    world.insert_resource(Events::<PolicyRejected>::default());
    world.insert_resource(Events::<ApprovalStepEvent>::default());
    world.insert_resource(Events::<EnforcementRequest>::default());
    world.insert_resource(Events::<ViolationDetected>::default());
    
    world
}

#[test]
fn test_policy_entity_creation() {
    let mut world = create_test_world();
    
    // Create a policy entity
    let policy_id = Uuid::new_v4();
    let _entity = world.spawn((
        PolicyEntity {
            policy_id,
            policy_type: PolicyType::AccessControl,
            status: PolicyStatus::Draft,
            version: 1,
        },
        PolicyScope {
            policy_id,
            scope_type: ScopeType::Organization,
            targets: vec!["org-123".to_string()],
        },
    )).id();
    
    // Query the entity
    let mut query = world.query::<(&PolicyEntity, &PolicyScope)>();
    let (policy, scope) = query.single(&world).unwrap();
    
    assert_eq!(policy.policy_id, policy_id);
    assert_eq!(policy.policy_type, PolicyType::AccessControl);
    assert_eq!(policy.status, PolicyStatus::Draft);
    assert_eq!(scope.scope_type, ScopeType::Organization);
}

#[test]
fn test_create_policy_system() {
    let mut world = create_test_world();
    
    // Create a test schedule
    let mut schedule = Schedule::default();
    schedule.add_systems(create_policy_system);
    
    // Send a PolicyCreated event
    let policy_id = Uuid::new_v4();
    world.resource_mut::<Events<PolicyCreated>>().send(PolicyCreated {
        policy_id,
        policy_type: PolicyType::Security,
        scope_type: ScopeType::Global,
        targets: vec![],
        priority: 100,
        override_lower: true,
    });
    
    // Run the system
    schedule.run(&mut world);
    
    // Verify the entity was created
    let mut query = world.query::<&PolicyEntity>();
    let policy = query.single(&world).unwrap();
    
    assert_eq!(policy.policy_id, policy_id);
    assert_eq!(policy.policy_type, PolicyType::Security);
    assert_eq!(policy.status, PolicyStatus::Draft);
}

#[test]
fn test_approval_workflow() {
    let mut world = create_test_world();
    
    // Create schedules for approval systems
    let mut submit_schedule = Schedule::default();
    submit_schedule.add_systems(submit_for_approval_system);
    
    let mut process_schedule = Schedule::default();
    process_schedule.add_systems(process_approval_system);
    
    // Create a policy
    let policy_id = Uuid::new_v4();
    world.spawn(PolicyEntity {
        policy_id,
        policy_type: PolicyType::Compliance,
        status: PolicyStatus::Draft,
        version: 1,
    });
    
    // Submit for approval
    world.resource_mut::<Events<PolicySubmittedForApproval>>().send(
        PolicySubmittedForApproval {
            policy_id,
            submitted_by: Uuid::new_v4(),
            notes: Some("Please review".to_string()),
            submitted_at: Utc::now(),
        }
    );
    
    submit_schedule.run(&mut world);
    
    // Verify approval was created
    let approval_id = {
        let mut approval_query = world.query::<&PolicyApproval>();
        let approval = approval_query.single(&world).unwrap();
        assert_eq!(approval.policy_id, policy_id);
        assert_eq!(approval.status, ApprovalStatus::Pending);
        approval.approval_id
    };
    
    // Process approval decision
    world.resource_mut::<Events<ApprovalStepEvent>>().send(
        ApprovalStepEvent {
            approval_id,
            step_id: Uuid::new_v4(),
            approver: "admin".to_string(),
            decision: Some(ApprovalDecision::Approve),
            decided_at: Some(Utc::now()),
            comments: Some("Looks good".to_string()),
        }
    );
    
    process_schedule.run(&mut world);
    
    // Verify policy was approved
    let mut policy_query = world.query::<&PolicyEntity>();
    let policy = policy_query.single(&world).unwrap();
    assert_eq!(policy.status, PolicyStatus::Active);
    
    // Check that approved event was sent
    let approved_events = world.resource::<Events<PolicyApproved>>();
    assert_eq!(approved_events.len(), 1);
}

#[test]
fn test_enforcement_system() {
    let mut world = create_test_world();
    
    // Create enforcement schedule
    let mut schedule = Schedule::default();
    schedule.add_systems(enforce_policy_system);
    
    // Create an active policy with enforcement
    let policy_id = Uuid::new_v4();
    world.spawn((
        PolicyEntity {
            policy_id,
            policy_type: PolicyType::AccessControl,
            status: PolicyStatus::Active,
            version: 1,
        },
        PolicyEnforcement {
            policy_id,
            mode: EnforcementMode::Strict,
            enabled: true,
        },
        EnforcementMetrics {
            policy_id,
            total_evaluations: 0,
            allowed: 0,
            denied: 0,
            errors: 0,
        },
    ));
    
    // Send enforcement request
    world.resource_mut::<Events<EnforcementRequest>>().send(
        EnforcementRequest {
            policy_id,
            subject: "user-123".to_string(),
            resource: "document-456".to_string(),
            action: "read".to_string(),
            context: serde_json::json!({}),
        }
    );
    
    schedule.run(&mut world);
    
    // Verify enforcement result was created
    let mut result_query = world.query::<&EnforcementResult>();
    let result = result_query.single(&world).unwrap();
    assert_eq!(result.policy_id, policy_id);
    assert_eq!(result.decision, Decision::Deny); // Strict mode defaults to deny
    
    // Verify metrics were updated
    let mut metrics_query = world.query::<&EnforcementMetrics>();
    let metrics = metrics_query.single(&world).unwrap();
    assert_eq!(metrics.total_evaluations, 1);
    assert_eq!(metrics.denied, 1);
}

#[test]
fn test_violation_recording() {
    let mut world = create_test_world();
    
    // Create violation recording schedule
    let mut schedule = Schedule::default();
    schedule.add_systems(record_violation_system);
    
    // Create policy with metrics
    let policy_id = Uuid::new_v4();
    world.spawn(EnforcementMetrics {
        policy_id,
        total_evaluations: 0,
        allowed: 0,
        denied: 0,
        errors: 0,
    });
    
    // Send violation event
    world.resource_mut::<Events<ViolationDetected>>().send(
        ViolationDetected {
            policy_id,
            violator: "user-123".to_string(),
            violation_type: "unauthorized_access".to_string(),
            severity: ViolationSeverity::High,
        }
    );
    
    schedule.run(&mut world);
    
    // Verify violation record was created
    let mut violation_query = world.query::<&ViolationRecord>();
    let violation = violation_query.single(&world).unwrap();
    assert_eq!(violation.policy_id, policy_id);
    assert_eq!(violation.violator, "user-123");
    assert_eq!(violation.severity, ViolationSeverity::High);
    
    // Verify metrics were updated
    let mut metrics_query = world.query::<&EnforcementMetrics>();
    let metrics = metrics_query.single(&world).unwrap();
    assert_eq!(metrics.errors, 1);
}

#[test]
fn test_policy_lifecycle_flow() {
    let mut world = create_test_world();
    
    // Create all necessary schedules
    let mut create_schedule = Schedule::default();
    create_schedule.add_systems(create_policy_system);
    
    let mut update_schedule = Schedule::default();
    update_schedule.add_systems(update_policy_system);
    
    let mut activate_schedule = Schedule::default();
    activate_schedule.add_systems(activate_policy_system);
    
    // Create policy
    let policy_id = Uuid::new_v4();
    world.resource_mut::<Events<PolicyCreated>>().send(PolicyCreated {
        policy_id,
        policy_type: PolicyType::BusinessRule,
        scope_type: ScopeType::Department,
        targets: vec!["dept-hr".to_string()],
        priority: 50,
        override_lower: false,
    });
    
    create_schedule.run(&mut world);
    
    // Update policy
    world.resource_mut::<Events<PolicyUpdated>>().send(PolicyUpdated {
        policy_id,
        new_scope: Some(PolicyScopeUpdate {
            scope_type: ScopeType::Team,
            targets: vec!["team-security".to_string()],
        }),
    });
    
    update_schedule.run(&mut world);
    
    // Activate policy
    world.resource_mut::<Events<PolicyActivated>>().send(PolicyActivated {
        policy_id,
    });
    
    activate_schedule.run(&mut world);
    
    // Verify final state
    let mut query = world.query::<(&PolicyEntity, &PolicyScope)>();
    let (policy, scope) = query.single(&world).unwrap();
    
    assert_eq!(policy.status, PolicyStatus::Active);
    assert_eq!(scope.scope_type, ScopeType::Team);
}

#[test]
fn test_approval_escalation() {
    let mut world = create_test_world();
    
    // Create escalation schedule
    let mut schedule = Schedule::default();
    schedule.add_systems(escalate_approval_system);
    
    // Create an approval that's been pending for a while
    let policy_id = Uuid::new_v4();
    let approval_id = Uuid::new_v4();
    let old_submission_time = Utc::now() - chrono::Duration::hours(49); // Past timeout
    
    world.spawn((
        PolicyApproval {
            policy_id,
            approval_id,
            status: ApprovalStatus::Pending,
            submitted_at: old_submission_time,
            submitted_by: "user-123".to_string(),
        },
        ApprovalWorkflow {
            policy_id,
            workflow_type: WorkflowType::SingleApprover,
            required_approvers: vec!["admin".to_string()],
            escalation_path: vec!["senior_admin".to_string()],
            timeout_hours: 48,
        },
    ));
    
    // Run escalation
    schedule.run(&mut world);
    
    // Verify approval was escalated
    let mut query = world.query::<&PolicyApproval>();
    let approval = query.single(&world).unwrap();
    assert_eq!(approval.status, ApprovalStatus::Escalated);
} 