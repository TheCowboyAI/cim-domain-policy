//! Policy approval systems

use bevy_ecs::prelude::*;
use crate::components::{
    PolicyEntity, PolicyStatus, PolicyApproval, ApprovalStatus, ApprovalWorkflow,
    ApprovalHistory,
};
use crate::components::approval::{
    ApprovalDecision, ApprovalAction, WorkflowType,
};
use crate::events::{
    PolicySubmittedForApproval, PolicyApproved, PolicyRejected,
};
use uuid::Uuid;
use chrono::Utc;

/// Event for approval step decisions
#[derive(Event)]
pub struct ApprovalStepEvent {
    pub approval_id: Uuid,
    pub step_id: Uuid,
    pub approver: String,
    pub decision: Option<ApprovalDecision>,
    pub decided_at: Option<chrono::DateTime<chrono::Utc>>,
    pub comments: Option<String>,
}

/// System to submit policies for approval
pub fn submit_for_approval_system(
    mut commands: Commands,
    mut policy_query: Query<&mut PolicyEntity, With<PolicyEntity>>,
    mut events: EventReader<PolicySubmittedForApproval>,
) {
    for event in events.read() {
        // Find the policy entity
        for mut policy in policy_query.iter_mut() {
            if policy.policy_id == event.policy_id {
                // Update policy status
                policy.status = PolicyStatus::PendingApproval;
                
                // Create approval workflow
                let approval_id = Uuid::new_v4();
                commands.spawn((
                    PolicyApproval {
                        policy_id: event.policy_id,
                        approval_id,
                        status: ApprovalStatus::Pending,
                        submitted_at: event.submitted_at,
                        submitted_by: event.submitted_by.to_string(),
                    },
                    ApprovalWorkflow {
                        policy_id: event.policy_id,
                        workflow_type: WorkflowType::SingleApprover, // Default, could be configurable
                        required_approvers: vec!["admin".to_string()], // Example
                        escalation_path: vec!["senior_admin".to_string()],
                        timeout_hours: 48,
                    },
                ));
                
                // Record in history
                commands.spawn(ApprovalHistory {
                    policy_id: event.policy_id,
                    approval_id,
                    action: ApprovalAction::Submitted,
                    actor: event.submitted_by.to_string(),
                    timestamp: event.submitted_at,
                    reason: event.notes.clone(),
                });
            }
        }
    }
}

/// System to process approval decisions
pub fn process_approval_system(
    mut commands: Commands,
    mut approval_query: Query<(&mut PolicyApproval, &ApprovalWorkflow)>,
    mut policy_query: Query<&mut PolicyEntity>,
    mut step_events: EventReader<ApprovalStepEvent>,
    mut approved_events: EventWriter<PolicyApproved>,
    mut rejected_events: EventWriter<PolicyRejected>,
) {
    for step in step_events.read() {
        // Find the approval
        for (mut approval, _workflow) in approval_query.iter_mut() {
            if approval.approval_id == step.approval_id {
                match step.decision.as_ref() {
                    Some(ApprovalDecision::Approve) => {
                        approval.status = ApprovalStatus::Approved;
                        
                        // Update policy status
                        for mut policy in policy_query.iter_mut() {
                            if policy.policy_id == approval.policy_id {
                                policy.status = PolicyStatus::Active;
                            }
                        }
                        
                        // Send approved event
                        approved_events.write(PolicyApproved {
                            policy_id: approval.policy_id,
                            approved_by: step.approver.parse().unwrap_or_default(),
                            comments: step.comments.clone(),
                            external_verification: None,
                            approved_at: step.decided_at.unwrap_or_else(Utc::now),
                        });
                    }
                    Some(ApprovalDecision::Reject) => {
                        approval.status = ApprovalStatus::Rejected;
                        
                        // Update policy status
                        for mut policy in policy_query.iter_mut() {
                            if policy.policy_id == approval.policy_id {
                                policy.status = PolicyStatus::Draft;
                            }
                        }
                        
                        // Send rejected event
                        rejected_events.write(PolicyRejected {
                            policy_id: approval.policy_id,
                            rejected_by: step.approver.parse().unwrap_or_default(),
                            reason: step.comments.clone().unwrap_or_else(|| "No reason provided".to_string()),
                            rejected_at: step.decided_at.unwrap_or_else(Utc::now),
                        });
                    }
                    Some(ApprovalDecision::Escalate) => {
                        approval.status = ApprovalStatus::Escalated;
                        // Escalation logic would go here
                    }
                    _ => {}
                }
                
                // Record in history
                commands.spawn(ApprovalHistory {
                    policy_id: approval.policy_id,
                    approval_id: approval.approval_id,
                    action: match step.decision.as_ref() {
                        Some(ApprovalDecision::Approve) => ApprovalAction::Approved,
                        Some(ApprovalDecision::Reject) => ApprovalAction::Rejected,
                        Some(ApprovalDecision::Escalate) => ApprovalAction::Escalated,
                        _ => ApprovalAction::Reviewed,
                    },
                    actor: step.approver.clone(),
                    timestamp: step.decided_at.unwrap_or_else(Utc::now),
                    reason: step.comments.clone(),
                });
            }
        }
    }
}

/// System to escalate approvals
pub fn escalate_approval_system(
    mut approval_query: Query<(&mut PolicyApproval, &ApprovalWorkflow), With<PolicyApproval>>,
) {
    let current_time = Utc::now();
    
    for (mut approval, workflow) in approval_query.iter_mut() {
        if approval.status == ApprovalStatus::Pending || approval.status == ApprovalStatus::InProgress {
            // Check if timeout has been exceeded
            let elapsed = current_time.signed_duration_since(approval.submitted_at);
            let timeout_duration = chrono::Duration::hours(workflow.timeout_hours as i64);
            
            if elapsed > timeout_duration {
                approval.status = ApprovalStatus::Escalated;
                // In a real system, this would trigger notifications to escalation path
            }
        }
    }
}

/// System to complete approval workflows
pub fn complete_approval_system(
    mut commands: Commands,
    approval_query: Query<(Entity, &PolicyApproval), With<PolicyApproval>>,
    mut policy_query: Query<&mut PolicyEntity>,
) {
    for (entity, approval) in approval_query.iter() {
        // Check if workflow is in a terminal state
        match approval.status {
            ApprovalStatus::Approved | ApprovalStatus::Rejected => {
                // Archive the approval workflow
                commands.entity(entity).despawn();
                
                // Ensure policy status is consistent
                for mut policy in policy_query.iter_mut() {
                    if policy.policy_id == approval.policy_id {
                        match approval.status {
                            ApprovalStatus::Approved => policy.status = PolicyStatus::Active,
                            ApprovalStatus::Rejected => policy.status = PolicyStatus::Draft,
                            _ => {}
                        }
                    }
                }
            }
            ApprovalStatus::Expired => {
                // Handle expired approvals
                commands.entity(entity).despawn();
                
                // Reset policy to draft
                for mut policy in policy_query.iter_mut() {
                    if policy.policy_id == approval.policy_id {
                        policy.status = PolicyStatus::Draft;
                    }
                }
            }
            _ => {}
        }
    }
} 