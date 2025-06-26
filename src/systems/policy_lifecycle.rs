//! Systems for managing policy lifecycle transitions

use bevy_ecs::prelude::*;
use chrono::Utc;
use uuid::Uuid;

use crate::commands::{CreatePolicyCommand, UpdatePolicyStatusCommand};
use crate::components::{
    PolicyId, PolicyEntity, PolicyMetadata,
    PolicyRule, ComponentMetadata,
};
use crate::value_objects::{PolicyStatus, PolicyType, PolicyScope};
use crate::events::{PolicyEnacted, PolicyArchived};

/// Marker component for newly created policies that need initialization
#[derive(Component)]
pub struct NewPolicyMarker;

/// System for creating new policies
pub fn create_policy_system(
    mut commands: Commands,
    mut events: EventReader<CreatePolicyCommand>,
    mut policy_events: EventWriter<PolicyEnacted>,
) {
    for event in events.read() {
        let policy_id = PolicyId(Uuid::new_v4());
        
        // Create the policy entity
        let entity = commands.spawn((
            PolicyEntity {
                policy_id: policy_id.clone(),
                name: event.name.clone(),
                description: event.description.clone(),
                status: PolicyStatus::Draft,
            },
            PolicyRule {
                rule_id: Uuid::new_v4(),
                name: event.name.clone(),
                description: event.description.clone(),
                policy_type: event.policy_type,
                scope: event.scope.clone(),
                conditions: Vec::new(),
                actions: Vec::new(),
                priority: 100,
                enabled: false,
            },
            ComponentMetadata::new(Uuid::new_v4()),
        )).id();

        // Emit policy enacted event
        policy_events.write(PolicyEnacted {
            policy_id,
            name: event.name.clone(),
            policy_type: event.policy_type,
            scope: event.scope.clone(),
            enacted_by: Uuid::new_v4(),
            enacted_at: Utc::now(),
        });
    }
}

/// System for updating policy status
pub fn update_policy_status_system(
    mut query: Query<&mut PolicyEntity>,
    mut events: EventReader<UpdatePolicyStatusCommand>,
) {
    for event in events.read() {
        for mut policy in query.iter_mut() {
            if policy.policy_id == event.policy_id {
                let old_status = policy.status.clone();
                
                // Validate status transition
                if is_valid_status_transition(old_status.clone(), event.new_status) {
                    policy.status = event.new_status;
                    
                    // Log the status change
                    tracing::info!(
                        "Policy {} status changed from {:?} to {:?}",
                        policy.policy_id.0,
                        old_status,
                        event.new_status
                    );
                } else {
                    tracing::warn!(
                        "Invalid status transition for policy {} from {:?} to {:?}",
                        policy.policy_id.0,
                        old_status,
                        event.new_status
                    );
                }
            }
        }
    }
}

/// System for archiving policies
pub fn archive_policy_system(
    mut query: Query<(&PolicyEntity, &mut PolicyEntity, &PolicyMetadata)>,
    mut events: EventWriter<PolicyArchived>,
) {
    let now = Utc::now();
    
    for (policy, mut policy_mut, metadata) in query.iter_mut() {
        // Check if policy should be archived
        let should_archive = match policy.status {
            PolicyStatus::Active => {
                // Check if policy has expired
                metadata.expiration_date.map_or(false, |exp| exp < now)
            }
            PolicyStatus::Suspended => {
                // Archive suspended policies after 90 days
                metadata.last_updated.map_or(false, |updated| {
                    now.signed_duration_since(updated).num_days() > 90
                })
            }
            _ => false,
        };
        
        if should_archive {
            policy_mut.status = PolicyStatus::Archived;
            
            events.write(PolicyArchived {
                policy_id: policy.policy_id.clone(),
                reason: if metadata.expiration_date.map_or(false, |exp| exp < now) {
                    Some("Policy expired".to_string())
                } else {
                    Some("Policy auto-archived".to_string())
                },
                archived_at: now,
            });
        }
    }
}

/// Check if a status transition is valid
fn is_valid_status_transition(from: PolicyStatus, to: PolicyStatus) -> bool {
    use PolicyStatus::*;
    
    match (from, to) {
        // Draft can go to PendingApproval or Archived
        (Draft, PendingApproval) => true,
        (Draft, Archived) => true,
        
        // PendingApproval can go to Active, Draft, or Archived
        (PendingApproval, Active) => true,
        (PendingApproval, Draft) => true,
        (PendingApproval, Archived) => true,
        
        // Active can go to Suspended, Superseded, or Archived
        (Active, Suspended) => true,
        (Active, Superseded) => true,
        (Active, Archived) => true,
        
        // Suspended can go back to Active, Superseded, or Archived
        (Suspended, Active) => true,
        (Suspended, Superseded) => true,
        (Suspended, Archived) => true,
        
        // Superseded can only go to Archived
        (Superseded, Archived) => true,
        
        // Archived is terminal
        (Archived, _) => false,
        
        // All other transitions are invalid
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bevy_ecs::world::World;
    use bevy_app::{App, Update};
    
    #[test]
    fn test_create_policy_system() {
        let mut app = App::new();
        app.add_event::<CreatePolicyCommand>();
        app.add_event::<PolicyEnacted>();
        app.add_systems(Update, create_policy_system);
        
        // Send create command
        app.world_mut().send_event(CreatePolicyCommand {
            name: "Test Policy".to_string(),
            description: "A test policy".to_string(),
            policy_type: PolicyType::Security,
            scope: PolicyScope::Global,
        });
        
        // Run the system
        app.update();
        
        // Check that entity was created
        let mut query = app.world_mut().query::<&PolicyEntity>();
        let policies: Vec<_> = query.iter(&app.world()).collect();
        
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].name, "Test Policy");
        assert_eq!(policies[0].status, PolicyStatus::Draft);
    }
    
    #[test]
    fn test_status_transitions() {
        assert!(is_valid_status_transition(PolicyStatus::Draft, PolicyStatus::PendingApproval));
        assert!(is_valid_status_transition(PolicyStatus::PendingApproval, PolicyStatus::Active));
        assert!(is_valid_status_transition(PolicyStatus::Active, PolicyStatus::Suspended));
        assert!(is_valid_status_transition(PolicyStatus::Suspended, PolicyStatus::Active));
        
        assert!(!is_valid_status_transition(PolicyStatus::Draft, PolicyStatus::Active));
        assert!(!is_valid_status_transition(PolicyStatus::Archived, PolicyStatus::Active));
    }
} 