//! Policy enforcement systems

use bevy_ecs::prelude::*;
use crate::components::{
    PolicyEntity, PolicyStatus, PolicyEnforcement, EnforcementMode, EnforcementResult,
    EnforcementContext, EnforcementMetrics, ViolationRecord,
};
use crate::components::enforcement::{ViolationSeverity, Decision};
use uuid::Uuid;
use chrono::Utc;

/// Event for enforcement requests
#[derive(Event)]
pub struct EnforcementRequest {
    pub policy_id: Uuid,
    pub subject: String,
    pub resource: String,
    pub action: String,
    pub context: serde_json::Value,
}

/// Event for violations
#[derive(Event)]
pub struct ViolationDetected {
    pub policy_id: Uuid,
    pub violator: String,
    pub violation_type: String,
    pub severity: ViolationSeverity,
}

/// System to enforce policies
pub fn enforce_policy_system(
    mut commands: Commands,
    policy_query: Query<(&PolicyEntity, &PolicyEnforcement), With<PolicyEntity>>,
    mut enforcement_requests: EventReader<EnforcementRequest>,
    mut metrics_query: Query<&mut EnforcementMetrics>,
) {
    for request in enforcement_requests.read() {
        // Find the policy
        for (policy, enforcement) in policy_query.iter() {
            if policy.policy_id == request.policy_id && policy.status == PolicyStatus::Active {
                // Check if enforcement is enabled
                if !enforcement.enabled {
                    continue;
                }
                
                // Create enforcement context
                let context = EnforcementContext {
                    policy_id: request.policy_id,
                    subject: request.subject.clone(),
                    resource: request.resource.clone(),
                    action: request.action.clone(),
                    environment: request.context.clone(),
                };
                
                // Make enforcement decision based on mode
                let decision = match enforcement.mode {
                    EnforcementMode::Strict => {
                        // In strict mode, default to deny unless explicitly allowed
                        // This is a simplified example - real logic would evaluate rules
                        Decision::Deny
                    }
                    EnforcementMode::Permissive => {
                        // In permissive mode, default to allow unless explicitly denied
                        Decision::Allow
                    }
                    EnforcementMode::Monitor => {
                        // In monitor mode, always allow but log
                        Decision::Allow
                    }
                    EnforcementMode::Test => {
                        // In test mode, evaluate but always allow
                        Decision::Allow
                    }
                };
                
                // Record the result
                commands.spawn(EnforcementResult {
                    policy_id: request.policy_id,
                    decision,
                    timestamp: Utc::now(),
                });
                
                // Update metrics
                for mut metrics in metrics_query.iter_mut() {
                    if metrics.policy_id == request.policy_id {
                        metrics.total_evaluations += 1;
                        match decision {
                            Decision::Allow => metrics.allowed += 1,
                            Decision::Deny => metrics.denied += 1,
                            Decision::RequireApproval => {} // Not counted in simple metrics
                        }
                    }
                }
                
                // Spawn context for potential violation detection
                commands.spawn(context);
            }
        }
    }
}

/// System to record policy violations
pub fn record_violation_system(
    mut commands: Commands,
    mut violations: EventReader<ViolationDetected>,
    mut metrics_query: Query<&mut EnforcementMetrics>,
) {
    for violation in violations.read() {
        // Create violation record
        commands.spawn(ViolationRecord {
            violation_id: Uuid::new_v4(),
            policy_id: violation.policy_id,
            violator: violation.violator.clone(),
            violation_type: violation.violation_type.clone(),
            severity: violation.severity,
            timestamp: Utc::now(),
        });
        
        // Update metrics
        for mut metrics in metrics_query.iter_mut() {
            if metrics.policy_id == violation.policy_id {
                metrics.errors += 1;
            }
        }
    }
}

/// System to remediate violations
pub fn remediate_violation_system(
    mut commands: Commands,
    violations: Query<(Entity, &ViolationRecord), With<ViolationRecord>>,
) {
    let current_time = Utc::now();
    
    for (entity, violation) in violations.iter() {
        // Check severity and age of violation
        let age = current_time.signed_duration_since(violation.timestamp);
        
        match violation.severity {
            ViolationSeverity::Critical => {
                // Critical violations need immediate action
                // In a real system, this would trigger immediate remediation
                // For now, we'll just log it
                println!("Critical violation detected: {:?}", violation.violation_id);
            }
            ViolationSeverity::High => {
                // High severity violations get remediated after 5 minutes
                if age > chrono::Duration::minutes(5) {
                    // Trigger remediation
                    println!("Remediating high severity violation: {:?}", violation.violation_id);
                    // Mark as remediated (in real system, would update status)
                    commands.entity(entity).despawn();
                }
            }
            ViolationSeverity::Medium => {
                // Medium severity violations get remediated after 1 hour
                if age > chrono::Duration::hours(1) {
                    println!("Remediating medium severity violation: {:?}", violation.violation_id);
                    commands.entity(entity).despawn();
                }
            }
            ViolationSeverity::Low => {
                // Low severity violations are just logged, remediated after 24 hours
                if age > chrono::Duration::hours(24) {
                    commands.entity(entity).despawn();
                }
            }
        }
    }
}

/// System to generate compliance reports
pub fn generate_compliance_report_system(
    policy_query: Query<(&PolicyEntity, &PolicyEnforcement)>,
    metrics_query: Query<&EnforcementMetrics>,
    violations_query: Query<&ViolationRecord>,

    mut last_report_time: Local<Option<chrono::DateTime<chrono::Utc>>>,
) {
    // Generate reports every 60 seconds
    let current_time = Utc::now();
    
    if let Some(last_time) = *last_report_time {
        if current_time.signed_duration_since(last_time) < chrono::Duration::seconds(60) {
            return;
        }
    }
    
    // Update last report time
    *last_report_time = Some(current_time);
        
        println!("=== Policy Compliance Report ===");
        println!("Generated at: {}", Utc::now());
        
        // Report on each active policy
        for (policy, enforcement) in policy_query.iter() {
            if policy.status != PolicyStatus::Active {
                continue;
            }
            
            println!("\nPolicy ID: {}", policy.policy_id);
            println!("Status: {:?}", policy.status);
            println!("Enforcement Mode: {:?}", enforcement.mode);
            println!("Enabled: {}", enforcement.enabled);
            
            // Get metrics for this policy
            for metrics in metrics_query.iter() {
                if metrics.policy_id == policy.policy_id {
                    println!("Total Evaluations: {}", metrics.total_evaluations);
                    println!("Allowed: {}", metrics.allowed);
                    println!("Denied: {}", metrics.denied);
                    println!("Errors: {}", metrics.errors);
                    
                    if metrics.total_evaluations > 0 {
                        let allow_rate = (metrics.allowed as f64 / metrics.total_evaluations as f64) * 100.0;
                        let deny_rate = (metrics.denied as f64 / metrics.total_evaluations as f64) * 100.0;
                        println!("Allow Rate: {allow_rate:.2}%");
                        println!("Deny Rate: {deny_rate:.2}%");
                    }
                }
            }
            
            // Count violations for this policy
            let violation_count = violations_query
                .iter()
                .filter(|v| v.policy_id == policy.policy_id)
                .count();
            
            println!("Active Violations: {violation_count}");
        }
        
        println!("\n=== End of Report ===\n");
} 