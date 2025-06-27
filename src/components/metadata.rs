//! Policy metadata components

use bevy_ecs::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Policy metadata
#[derive(Component, Debug, Clone, Serialize, Deserialize)]
pub struct PolicyMetadata {
    pub policy_id: Uuid,
    pub name: String,
    pub description: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Policy version information
#[derive(Component, Debug, Clone, Serialize, Deserialize)]
pub struct PolicyVersion {
    pub policy_id: Uuid,
    pub version: u32,
    pub published_at: DateTime<Utc>,
    pub changelog: String,
}

/// Policy author information
#[derive(Component, Debug, Clone, Serialize, Deserialize)]
pub struct PolicyAuthor {
    pub policy_id: Uuid,
    pub author_id: String,
    pub author_name: String,
    pub author_role: String,
}

/// Policy tags for categorization
#[derive(Component, Debug, Clone, Serialize, Deserialize)]
pub struct PolicyTag {
    pub policy_id: Uuid,
    pub tags: Vec<String>,
}

/// Policy references to other policies or documents
#[derive(Component, Debug, Clone, Serialize, Deserialize)]
pub struct PolicyReference {
    pub policy_id: Uuid,
    pub reference_type: ReferenceType,
    pub reference_id: String,
    pub reference_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReferenceType {
    Supersedes,
    RelatedTo,
    BasedOn,
    Conflicts,
    Complements,
}

/// Policy audit trail
#[derive(Component, Debug, Clone, Serialize, Deserialize)]
pub struct PolicyAudit {
    pub policy_id: Uuid,
    pub audit_id: Uuid,
    pub action: AuditAction,
    pub actor: String,
    pub timestamp: DateTime<Utc>,
    pub details: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditAction {
    Created,
    Updated,
    Approved,
    Rejected,
    Activated,
    Suspended,
    Archived,
    Accessed,
} 