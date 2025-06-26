//! Enforcement systems for policy compliance

use bevy_ecs::prelude::*;
use bevy_time::Time;
use chrono::{Duration, Utc};
use uuid::Uuid;
use std::collections::HashMap;

use crate::components::{
    PolicyId, PolicyEntity, EnforcementStatus, EnforcementAction,
    ViolationRecord, ComponentMetadata
};
use crate::value_objects::{
    PolicyStatus, EnforcementMode, ViolationType, ViolationSeverity, 
    ActionType, EnforcementResult, EnforcementMetrics
};
use crate::events::{
    PolicyEnforced, PolicyViolationDetected, EnforcementActionTaken
};

/// System for enforcing policies
pub fn enforce_policies_system(
    mut commands: Commands,
    mut query: Query<(Entity, &PolicyId, &PolicyEntity), Without<EnforcementStatus>>,
    mut events: EventWriter<PolicyEnforced>,
) {
    for (entity, policy_id, policy_entity) in query.iter() {
        // Only enforce active policies
        if policy_entity.status == PolicyStatus::Active {
            // Create enforcement status
            let enforcement_status = EnforcementStatus {
                enforcement_mode: EnforcementMode::Monitoring,
                violations_detected: 0,
                actions_taken: 0,
                mode: EnforcementMode::Monitoring, // Alias
                violations: Vec::new(),
                actions_taken_list: Vec::new(),
                last_checked: Utc::now(),
                enforcement_count: 0,
                metrics: EnforcementMetrics {
                    total_evaluations: 0,
                    successful_enforcements: 0,
                    failed_enforcements: 0,
                    average_enforcement_time_ms: 0.0,
                },
            };
            
            commands.entity(entity).insert(enforcement_status);
            
            // Emit enforcement started event
            events.write(PolicyEnforced {
                policy_id: policy_id.clone(),
                enforcement_mode: EnforcementMode::Monitoring,
                enforced_at: Utc::now(),
            });
        }
    }
}

/// System to detect policy violations
pub fn detect_violations_system(
    mut query: Query<(&PolicyId, &mut EnforcementStatus)>,
    mut events: EventWriter<PolicyViolationDetected>,
    // In a real system, this would check against actual conditions
    time: Res<Time>,
) {
    for (policy_id, mut enforcement_status) in query.iter_mut() {
        // Skip if not actively enforcing
        if enforcement_status.mode != EnforcementMode::Active {
            continue;
        }

        // Update last checked time
        enforcement_status.last_checked = Utc::now();

        // Simulate violation detection (in real system, this would check actual conditions)
        // For demo purposes, we'll create a violation every 30 seconds
        if time.elapsed_secs() as u64 % 30 == 0 && enforcement_status.violations.is_empty() {
            let violation = ViolationRecord {
                violation_id: Uuid::new_v4(),
                violation_type: ViolationType::Unauthorized,
                severity: ViolationSeverity::Medium,
                violator_id: Uuid::new_v4(),
                context: HashMap::from([
                    ("action".to_string(), "access_restricted_resource".to_string()),
                    ("resource".to_string(), "confidential_data".to_string()),
                ]),
                detected_at: Utc::now(),
                resolved_at: None,
            };

            enforcement_status.violations.push(violation.clone());

            // Emit event
            events.write(PolicyViolationDetected {
                policy_id: policy_id.0,
                violation_id: violation.violation_id,
                violation_type: violation.violation_type,
                severity: violation.severity,
                violator_id: violation.violator_id,
                detected_at: violation.detected_at,
                context: violation.context,
            });
        }
    }
}

/// System to take enforcement actions
pub fn take_enforcement_actions_system(
    mut query: Query<(&PolicyId, &mut EnforcementStatus)>,
    mut events: EventWriter<EnforcementActionTaken>,
) {
    for (policy_id, mut enforcement_status) in query.iter_mut() {
        // Clone violations to avoid borrowing issues
        let violations_to_process: Vec<_> = enforcement_status.violations.iter()
            .filter(|v| v.resolved_at.is_none())
            .cloned()
            .collect();

        for violation in violations_to_process {
            // Determine action based on violation severity
            let action_type = match violation.severity {
                ViolationSeverity::Critical => ActionType::Block,
                ViolationSeverity::High => ActionType::Alert,
                ViolationSeverity::Medium => ActionType::Warn,
                ViolationSeverity::Low => ActionType::Log,
            };

            // Check if we've already taken action for this violation
            let action_exists = enforcement_status.actions_taken_list.iter()
                .any(|action| action.violation_id == Some(violation.violation_id));

            if !action_exists {
                let action = EnforcementAction {
                    action_id: Uuid::new_v4(),
                    action_type: action_type.clone(),
                    target_id: violation.violator_id,
                    parameters: HashMap::from([
                        ("violation_type".to_string(), format!("{:?}", violation.violation_type)),
                        ("severity".to_string(), format!("{:?}", violation.severity)),
                    ]),
                    executed_at: Utc::now(),
                    result: EnforcementResult::Success,
                    violation_id: Some(violation.violation_id),
                };

                let action_clone = action.clone();
                enforcement_status.actions_taken_list.push(action);
                enforcement_status.enforcement_count += 1;

                // Emit event
                events.write(EnforcementActionTaken {
                    policy_id: policy_id.0,
                    action_id: action_clone.action_id,
                    action_type: action_clone.action_type,
                    target_id: action_clone.target_id,
                    violation_id: action_clone.violation_id,
                    executed_at: action_clone.executed_at,
                    result: action_clone.result,
                });
            }
        }
    }
}

/// System to update enforcement metrics
pub fn update_enforcement_metrics_system(
    query: Query<(&PolicyId, &EnforcementStatus)>,
    mut metadata_query: Query<&mut ComponentMetadata>,
) {
    for (policy_id, enforcement_status) in query.iter() {
        if let Ok(mut metadata) = metadata_query.get_mut(policy_id.0.into()) {
            // Update enforcement metrics
            metadata.properties.insert(
                "total_violations".to_string(),
                enforcement_status.violations.len().to_string()
            );
            metadata.properties.insert(
                "active_violations".to_string(),
                enforcement_status.violations.iter()
                    .filter(|v| v.resolved_at.is_none())
                    .count()
                    .to_string()
            );
            metadata.properties.insert(
                "enforcement_actions".to_string(),
                enforcement_status.enforcement_count.to_string()
            );
            metadata.properties.insert(
                "last_checked".to_string(),
                enforcement_status.last_checked.to_rfc3339()
            );

            // Calculate violation severity distribution
            let mut severity_counts = HashMap::new();
            for violation in &enforcement_status.violations {
                *severity_counts.entry(format!("{:?}", violation.severity))
                    .or_insert(0) += 1;
            }
            
            for (severity, count) in severity_counts {
                metadata.properties.insert(
                    format!("violations_{}", severity.to_lowercase()),
                    count.to_string()
                );
            }
        }
    }
}

/// System for handling enforcement mode changes
pub fn handle_enforcement_mode_changes_system(
    mut query: Query<(&PolicyId, &PolicyEntity, &mut EnforcementStatus), Changed<PolicyEntity>>,
) {
    for (_policy_id, policy_entity, mut enforcement_status) in query.iter_mut() {
        // Adjust enforcement based on policy status
        match policy_entity.status {
            PolicyStatus::Active => {
                enforcement_status.enforcement_mode = EnforcementMode::Active;
            }
            PolicyStatus::Suspended => {
                enforcement_status.enforcement_mode = EnforcementMode::Disabled;
            }
            _ => {
                // Other statuses keep current enforcement mode
            }
        }
    }
}

/// System to resolve violations
pub fn resolve_violations_system(
    mut query: Query<(&PolicyId, &mut EnforcementStatus)>,
    _time: Res<Time>,
) {
    for (_policy_id, mut enforcement_status) in query.iter_mut() {
        // Auto-resolve old violations (for demo purposes)
        // In a real system, this would be triggered by actual resolution events
        for violation in &mut enforcement_status.violations {
            if violation.resolved_at.is_none() {
                let age = Utc::now().signed_duration_since(violation.detected_at);
                
                // Auto-resolve violations older than 5 minutes
                if age.num_minutes() > 5 {
                    violation.resolved_at = Some(Utc::now());
                }
            }
        }
    }
}

/// System to handle violations (stub for compatibility)
pub fn handle_violations_system() {
    // This is a stub for compatibility with the lib.rs exports
    // The actual functionality is in detect_violations_system and take_enforcement_actions_system
}

/// System to cleanup expired exceptions (stub for compatibility)
pub fn cleanup_expired_exceptions_system() {
    // This is a stub for compatibility with the lib.rs exports
    // The actual functionality could be added here to clean up expired enforcement exceptions
} 