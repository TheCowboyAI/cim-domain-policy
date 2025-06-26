//! Approval workflow systems
//!
//! Systems that handle policy approval processes

use bevy_ecs::prelude::*;
use uuid::Uuid;
use chrono::Utc;
use std::collections::HashMap;

use crate::components::{
    PolicyId, PolicyEntity, ApprovalStatus, ApprovalRequirement,
    Approval, ExternalApproval, ComponentMetadata
};
use crate::value_objects::PolicyStatus;
use crate::events::{
    PolicySubmittedForApproval, PolicyApproved, PolicyRejected,
    PolicyExternalApprovalReceived
};
use crate::value_objects::{ApprovalLevel, ApproverRole};

/// System for submitting policies for approval
pub fn submit_for_approval_system(
    mut commands: Commands,
    mut query: Query<(Entity, &PolicyId, &PolicyEntity, &ApprovalRequirement), Without<ApprovalStatus>>,
    mut events: EventWriter<PolicySubmittedForApproval>,
) {
    for (entity, policy_id, policy_entity, requirement) in query.iter() {
        // Only submit if policy is in Draft status
        if policy_entity.status == PolicyStatus::Draft {
            // Create approval status component
            let approval_status = ApprovalStatus {
                current_level: 0,
                required_levels: requirement.approval_levels.len() as u32,
                approvals: Vec::new(),
                rejection_reason: None,
                is_complete: false,
            };
            
            // Add approval status to entity
            commands.entity(entity).insert(approval_status);
            
            // Update policy status
            commands.entity(entity).insert(PolicyStatus::PendingApproval);
            
            // Emit event
            events.write(PolicySubmittedForApproval {
                policy_id: policy_id.clone(),
                submitted_by: Uuid::new_v4(), // Would come from context
                comment: None,
            });
        }
    }
}

/// System for processing approvals
pub fn process_approvals_system(
    mut query: Query<(&PolicyId, &PolicyEntity, &mut ApprovalStatus, &ApprovalRequirement)>,
    mut approved_events: EventWriter<PolicyApproved>,
    mut rejected_events: EventWriter<PolicyRejected>,
) {
    for (policy_id, policy_entity, mut status, requirement) in query.iter_mut() {
        // Skip if already complete
        if status.is_complete || policy_entity.status != PolicyStatus::PendingApproval {
            continue;
        }
        
        // Check if we have all required approvals
        if status.current_level >= status.required_levels {
            status.is_complete = true;
            
            // Check if any approval was rejected
            if status.approvals.iter().any(|a| !a.approved) {
                rejected_events.write(PolicyRejected {
                    policy_id: policy_id.clone(),
                    rejected_by: status.approvals.iter()
                        .find(|a| !a.approved)
                        .map(|a| a.approver_id)
                        .unwrap_or_default(),
                    reason: status.rejection_reason.clone()
                        .unwrap_or_else(|| "Policy rejected during approval".to_string()),
                    rejected_at: Utc::now(),
                });
            } else {
                // All approvals successful
                approved_events.write(PolicyApproved {
                    policy_id: policy_id.clone(),
                    approved_by: status.approvals.last()
                        .map(|a| a.approver_id)
                        .unwrap_or_default(),
                    approved_at: Utc::now(),
                    comment: None,
                });
            }
        }
    }
}

/// System for checking approval requirements
pub fn check_approval_requirements_system(
    query: Query<(&PolicyId, &ApprovalStatus, &ApprovalRequirement)>,
    mut metadata_query: Query<&mut ComponentMetadata>,
) {
    for (policy_id, status, requirement) in query.iter() {
        // Check if we need to notify approvers
        if status.current_level < requirement.approval_levels.len() as u32 {
            let current_level = &requirement.approval_levels[status.current_level as usize];
            
            // In a real system, this would send notifications
            tracing::info!(
                "Policy {} requires approval from level: {:?}",
                policy_id.0,
                current_level
            );
        }
        
        // Update metadata with approval progress
        // Note: This is a simplified approach - in reality we'd need to map PolicyId to Entity
        // For now, we'll skip this update
    }
}

/// System for handling external approvals
pub fn handle_external_approvals_system(
    mut commands: Commands,
    mut query: Query<(Entity, &PolicyId, &mut ApprovalStatus)>,
    mut events: EventReader<PolicyExternalApprovalReceived>,
    external_query: Query<&ExternalApproval>,
) {
    for event in events.read() {
        // Find the policy with matching ID
        for (entity, policy_id, mut status) in query.iter_mut() {
            if policy_id.0 == event.policy_id {
                // Create approval record
                let approval = Approval {
                    approver_id: event.approver_id,
                    approved_at: event.approved_at,
                    approved: event.approved,
                    comment: event.comment.clone(),
                    level: status.current_level,
                };
                
                // Add approval to status
                status.approvals.push(approval);
                
                if event.approved {
                    status.current_level += 1;
                } else {
                    status.rejection_reason = event.comment.clone();
                    status.is_complete = true;
                }
                
                // If this is an external approval, add the component
                if event.external_system.is_some() {
                    commands.entity(entity).insert(ExternalApproval {
                        system_name: event.external_system.clone().unwrap_or_default(),
                        reference_id: event.external_reference.clone().unwrap_or_default(),
                        approved: event.approved,
                        timestamp: event.approved_at,
                    });
                }
                
                break;
            }
        }
    }
}

// Helper function to check if approval requirements are met
fn check_approval_requirements(
    approval_status: &ApprovalStatus,
    requirement: &ApprovalRequirement,
) -> bool {
    // Check if we have approvals for all required levels
    for required_level in &requirement.approval_levels {
        let has_approval = approval_status.approvals.iter()
            .any(|approval| &approval.approval_level == required_level);
        
        if !has_approval {
            return false;
        }
    }
    
    // Check minimum approvers if specified
    if let Some(min_approvers) = requirement.minimum_approvers {
        if approval_status.approvals.len() < min_approvers {
            return false;
        }
    }
    
    // Check quorum if specified
    if let Some(quorum) = requirement.quorum_percentage {
        // This would need access to total eligible approvers
        // For now, we'll assume quorum is met if we have enough approvals
        let approval_percentage = (approval_status.approvals.len() as f32 / 10.0) * 100.0;
        if approval_percentage < quorum {
            return false;
        }
    }
    
    true
}

// Helper function to calculate approval progress
fn calculate_approval_progress(
    approval_status: &ApprovalStatus,
    requirement: &ApprovalRequirement,
) -> u32 {
    let required_count = requirement.approval_levels.len();
    if required_count == 0 {
        return 100;
    }
    
    let approved_count = approval_status.approvals.len();
    ((approved_count as f32 / required_count as f32) * 100.0) as u32
} 