//! Policy domain components
//!
//! This module contains all ECS components used in the policy domain.
//! Components represent the data/state of entities in the system.

pub mod rules;
pub mod approval;
pub mod enforcement;
pub mod authentication;
pub mod metadata;

// Re-export all components
pub use rules::*;
pub use approval::*;
pub use enforcement::*;
pub use authentication::*;
pub use metadata::*;

// Legacy component exports (for backward compatibility)
pub use metadata::ComponentMetadata as PolicyMetadataComponent;

// Main policy entity component
use bevy_ecs::prelude::*;
use uuid::Uuid;
use serde::{Deserialize, Serialize};

// Re-export value object types that are commonly used with components
pub use crate::value_objects::{PolicyStatus, PolicyType, PolicyScope};

/// Policy entity component - marks an entity as a policy
#[derive(Component, Debug, Clone)]
pub struct PolicyEntity {
    pub policy_id: PolicyId,
    pub name: String,
    pub description: String,
    pub status: PolicyStatus,
}

/// Policy ID wrapper type
#[derive(Component, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PolicyId(pub Uuid); 