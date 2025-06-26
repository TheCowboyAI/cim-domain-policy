//! Policy type value objects

use bevy_ecs::component::Component;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Policy type
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PolicyType {
    AccessControl,
    DataGovernance,
    Compliance,
    Security,
    Privacy,
    Operational,
    Custom(String),
}

/// Policy scope
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PolicyScope {
    Global,
    Organization,
    Department,
    Team,
    User,
    Resource,
    Custom(String),
}

/// Policy status enumeration
#[derive(Component, Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PolicyStatus {
    /// Policy is in draft state
    Draft,
    /// Policy is pending approval
    PendingApproval,
    /// Policy is active and enforced
    Active,
    /// Policy is temporarily suspended
    Suspended,
    /// Policy has been superseded by another
    Superseded,
    /// Policy has been archived
    Archived,
} 