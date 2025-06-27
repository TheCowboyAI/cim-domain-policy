//! Policy lifecycle management systems

use bevy_ecs::prelude::*;
use crate::components::{PolicyEntity, PolicyStatus, PolicyScope, PolicyPriority};
use crate::events::{PolicyCreated, PolicyUpdated, PolicyActivated, PolicySuspended, PolicyArchived};

/// System to create new policies
pub fn create_policy_system(
    mut commands: Commands,
    mut events: EventReader<PolicyCreated>,
) {
    for event in events.read() {
        // Spawn new policy entity with components
        commands.spawn((
            PolicyEntity {
                policy_id: event.policy_id,
                policy_type: event.policy_type,
                status: PolicyStatus::Draft,
                version: 1,
            },
            PolicyScope {
                policy_id: event.policy_id,
                scope_type: event.scope_type,
                targets: event.targets.clone(),
            },
            PolicyPriority {
                policy_id: event.policy_id,
                priority: event.priority,
                override_lower: event.override_lower,
            },
        ));
    }
}

/// System to update existing policies
pub fn update_policy_system(
    mut query: Query<(&mut PolicyEntity, &mut PolicyScope), With<PolicyEntity>>,
    mut events: EventReader<PolicyUpdated>,
) {
    for event in events.read() {
        for (mut entity, mut scope) in query.iter_mut() {
            if entity.policy_id == event.policy_id {
                // Update version
                entity.version += 1;
                
                // Update scope if provided
                if let Some(new_scope) = &event.new_scope {
                    scope.scope_type = new_scope.scope_type.clone();
                    scope.targets = new_scope.targets.clone();
                }
            }
        }
    }
}

/// System to activate policies
pub fn activate_policy_system(
    mut query: Query<&mut PolicyEntity>,
    mut events: EventReader<PolicyActivated>,
) {
    for event in events.read() {
        for mut entity in query.iter_mut() {
            if entity.policy_id == event.policy_id {
                entity.status = PolicyStatus::Active;
            }
        }
    }
}

/// System to suspend policies
pub fn suspend_policy_system(
    mut query: Query<&mut PolicyEntity>,
    mut events: EventReader<PolicySuspended>,
) {
    for event in events.read() {
        for mut entity in query.iter_mut() {
            if entity.policy_id == event.policy_id {
                entity.status = PolicyStatus::Suspended;
            }
        }
    }
}

/// System to archive policies
pub fn archive_policy_system(
    mut commands: Commands,
    query: Query<(Entity, &PolicyEntity)>,
    mut events: EventReader<PolicyArchived>,
) {
    for event in events.read() {
        for (entity, policy) in query.iter() {
            if policy.policy_id == event.policy_id {
                // Remove entity from active world
                commands.entity(entity).despawn();
                // In a real system, we'd persist to archive storage here
            }
        }
    }
} 