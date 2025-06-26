//! Enforcement components for policy domain
//!
//! Defines how policies are enforced and what happens on violations

use bevy_ecs::component::Component;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use std::collections::HashMap;

use crate::value_objects::{
    ViolationType, ViolationSeverity, ActionType,
    EnforcementMode, EnforcementResult
};

/// Enforcement component - how the policy is enforced
#[derive(Component, Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementComponent {
    /// Enforcement mode
    pub mode: EnforcementMode,
    
    /// Actions to take on violation
    pub violation_actions: Vec<ViolationAction>,
    
    /// Exceptions to the policy
    pub exceptions: Vec<PolicyException>,
    
    /// Metadata
    pub metadata: super::ComponentMetadata,
}

/// Action to take when policy is violated
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViolationAction {
    /// Type of action to take (e.g., "log", "alert", "block")
    pub action_type: String,
    
    /// Severity level of the violation
    pub severity: ViolationSeverity,
    
    /// IDs of entities to notify about the violation
    pub notification_targets: Vec<Uuid>,
}

/// Exception to a policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyException {
    /// Entity this exception applies to (if specific)
    pub entity_id: Option<Uuid>,
    
    /// Context where this exception applies
    pub context: Option<String>,
    
    /// Reason for the exception
    pub reason: String,
    
    /// When the exception expires
    pub expires_at: Option<DateTime<Utc>>,
}

/// Enforcement status component
#[derive(Component, Debug, Clone)]
pub struct EnforcementStatus {
    pub enforcement_mode: EnforcementMode,
    pub violations_detected: u32,
    pub actions_taken: u32,
    pub mode: EnforcementMode, // Alias for enforcement_mode for compatibility
    pub violations: Vec<ViolationRecord>,
    pub actions_taken_list: Vec<EnforcementAction>,
    pub last_checked: DateTime<Utc>,
    pub enforcement_count: u32,
    pub metrics: crate::value_objects::EnforcementMetrics,
}

/// Violation record
#[derive(Debug, Clone)]
pub struct ViolationRecord {
    pub violation_id: Uuid,
    pub violation_type: ViolationType,
    pub severity: ViolationSeverity,
    pub violator_id: Uuid,
    pub context: HashMap<String, String>,
    pub detected_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
}

/// Enforcement action
#[derive(Debug, Clone)]
pub struct EnforcementAction {
    pub action_id: Uuid,
    pub action_type: ActionType,
    pub target_id: Uuid,
    pub parameters: HashMap<String, String>,
    pub executed_at: DateTime<Utc>,
    pub result: EnforcementResult,
    pub violation_id: Option<Uuid>,
}

/// Enforcement configuration component
#[derive(Component, Debug, Clone)]
pub struct EnforcementConfigComponent {
    pub config_id: Uuid,
    pub enforcement_mode: EnforcementMode,
    pub actions: Vec<EnforcementActionConfig>,
    pub exceptions: Vec<EnforcementException>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Enforcement action configuration
#[derive(Debug, Clone)]
pub struct EnforcementActionConfig {
    pub action_type: String,
    pub severity_threshold: ViolationSeverity,
    pub parameters: HashMap<String, String>,
    pub enabled: bool,
}

/// Enforcement exception
#[derive(Debug, Clone)]
pub struct EnforcementException {
    pub exception_id: Uuid,
    pub target_id: Option<Uuid>,
    pub reason: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_by: Uuid,
}

/// Enforcement metrics component
#[derive(Component, Debug, Clone, Default)]
pub struct EnforcementMetricsComponent {
    pub total_violations: u64,
    pub violations_by_type: HashMap<String, u64>,
    pub violations_by_severity: HashMap<String, u64>,
    pub actions_taken: u64,
    pub last_updated: Option<DateTime<Utc>>,
}

impl EnforcementComponent {
    /// Create a new enforcement component
    pub fn new(mode: EnforcementMode) -> Self {
        Self {
            mode,
            violation_actions: Vec::new(),
            exceptions: Vec::new(),
            metadata: super::ComponentMetadata::default(),
        }
    }
    
    /// Create a strict enforcement component
    pub fn strict() -> Self {
        Self::new(EnforcementMode::Strict)
    }
    
    /// Create a permissive enforcement component
    pub fn permissive() -> Self {
        Self::new(EnforcementMode::Monitoring)
    }
    
    /// Add a violation action
    pub fn add_violation_action(&mut self, action: ViolationAction) {
        self.violation_actions.push(action);
        self.metadata.updated_at = Utc::now();
        self.metadata.version += 1;
    }
    
    /// Add an exception
    pub fn add_exception(&mut self, exception: PolicyException) {
        self.exceptions.push(exception);
        self.metadata.updated_at = Utc::now();
        self.metadata.version += 1;
    }
    
    /// Set enforcement mode
    pub fn set_mode(&mut self, mode: EnforcementMode) {
        self.mode = mode;
        self.metadata.updated_at = Utc::now();
        self.metadata.version += 1;
    }
    
    /// Check if an entity has an exception
    pub fn has_exception(&self, entity_id: Uuid) -> bool {
        let now = Utc::now();
        self.exceptions.iter().any(|e| {
            match (&e.entity_id, &e.expires_at) {
                (Some(id), Some(expires)) => *id == entity_id && *expires > now,
                (Some(id), None) => *id == entity_id,
                _ => false,
            }
        })
    }
    
    /// Remove expired exceptions
    pub fn cleanup_expired_exceptions(&mut self) {
        let now = Utc::now();
        let before_count = self.exceptions.len();
        
        self.exceptions.retain(|e| {
            e.expires_at.map_or(true, |expires| expires > now)
        });
        
        if self.exceptions.len() != before_count {
            self.metadata.updated_at = now;
            self.metadata.version += 1;
        }
    }
}

impl Default for EnforcementComponent {
    fn default() -> Self {
        Self::new(EnforcementMode::Monitoring)
    }
}

impl ViolationAction {
    /// Create a log action
    pub fn log(severity: ViolationSeverity) -> Self {
        Self {
            action_type: "log".to_string(),
            severity,
            notification_targets: Vec::new(),
        }
    }
    
    /// Create an alert action
    pub fn alert(severity: ViolationSeverity, targets: Vec<Uuid>) -> Self {
        Self {
            action_type: "alert".to_string(),
            severity,
            notification_targets: targets,
        }
    }
    
    /// Create a block action
    pub fn block() -> Self {
        Self {
            action_type: "block".to_string(),
            severity: ViolationSeverity::High,
            notification_targets: Vec::new(),
        }
    }
}

impl PolicyException {
    /// Create a permanent exception for an entity
    pub fn permanent(entity_id: Uuid, reason: String) -> Self {
        Self {
            entity_id: Some(entity_id),
            context: None,
            reason,
            expires_at: None,
        }
    }
    
    /// Create a temporary exception for an entity
    pub fn temporary(entity_id: Uuid, reason: String, expires_at: DateTime<Utc>) -> Self {
        Self {
            entity_id: Some(entity_id),
            context: None,
            reason,
            expires_at: Some(expires_at),
        }
    }
    
    /// Create a context-based exception
    pub fn for_context(context: String, reason: String) -> Self {
        Self {
            entity_id: None,
            context: Some(context),
            reason,
            expires_at: None,
        }
    }
}

impl Default for EnforcementMode {
    fn default() -> Self {
        EnforcementMode::Monitoring
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    
    #[test]
    fn test_enforcement_component() {
        let mut enforcement = EnforcementComponent::strict();
        
        // Add violation actions
        enforcement.add_violation_action(ViolationAction::log(ViolationSeverity::Medium));
        enforcement.add_violation_action(ViolationAction::block());
        
        assert_eq!(enforcement.mode, EnforcementMode::Strict);
        assert_eq!(enforcement.violation_actions.len(), 2);
    }
    
    #[test]
    fn test_policy_exceptions() {
        let mut enforcement = EnforcementComponent::new(EnforcementMode::Strict);
        let entity_id = Uuid::new_v4();
        
        // Add permanent exception
        enforcement.add_exception(PolicyException::permanent(
            entity_id,
            "Test entity exempt".to_string()
        ));
        
        assert!(enforcement.has_exception(entity_id));
        assert!(!enforcement.has_exception(Uuid::new_v4()));
    }
    
    #[test]
    fn test_expired_exceptions() {
        let mut enforcement = EnforcementComponent::new(EnforcementMode::Strict);
        let entity_id = Uuid::new_v4();
        
        // Add expired exception
        let past = Utc::now() - Duration::hours(1);
        enforcement.add_exception(PolicyException::temporary(
            entity_id,
            "Temporary exemption".to_string(),
            past
        ));
        
        // Add valid exception
        let future = Utc::now() + Duration::hours(1);
        enforcement.add_exception(PolicyException::temporary(
            Uuid::new_v4(),
            "Valid exemption".to_string(),
            future
        ));
        
        assert_eq!(enforcement.exceptions.len(), 2);
        
        // Cleanup expired
        enforcement.cleanup_expired_exceptions();
        
        assert_eq!(enforcement.exceptions.len(), 1);
        assert!(!enforcement.has_exception(entity_id));
    }
    
    #[test]
    fn test_violation_actions() {
        let targets = vec![Uuid::new_v4(), Uuid::new_v4()];
        let alert = ViolationAction::alert(ViolationSeverity::Critical, targets.clone());
        
        assert_eq!(alert.action_type, "alert");
        assert_eq!(alert.severity, ViolationSeverity::Critical);
        assert_eq!(alert.notification_targets, targets);
    }
} 