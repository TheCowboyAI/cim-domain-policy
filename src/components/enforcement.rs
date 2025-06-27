//! Policy enforcement components

use bevy_ecs::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Policy enforcement configuration
#[derive(Component, Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEnforcement {
    pub policy_id: Uuid,
    pub mode: EnforcementMode,
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnforcementMode {
    Strict,
    Permissive,
    Monitor,
    Test,
}

/// Result of policy enforcement
#[derive(Component, Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementResult {
    pub policy_id: Uuid,
    pub decision: Decision,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    Allow,
    Deny,
    RequireApproval,
}

/// Context for policy enforcement
#[derive(Component, Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementContext {
    pub policy_id: Uuid,
    pub subject: String,
    pub resource: String,
    pub action: String,
    pub environment: serde_json::Value,
}

/// Metrics for policy enforcement
#[derive(Component, Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementMetrics {
    pub policy_id: Uuid,
    pub total_evaluations: u64,
    pub allowed: u64,
    pub denied: u64,
    pub errors: u64,
}

/// Record of policy violations
#[derive(Component, Debug, Clone, Serialize, Deserialize)]
pub struct ViolationRecord {
    pub violation_id: Uuid,
    pub policy_id: Uuid,
    pub violator: String,
    pub violation_type: String,
    pub severity: ViolationSeverity,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ViolationSeverity {
    Low,
    Medium,
    High,
    Critical,
} 