//! Policy projections and read models

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use std::collections::HashSet;

/// Policy view for queries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyView {
    /// Policy ID
    pub policy_id: Uuid,
    /// Policy name
    pub name: String,
    /// Policy type
    pub policy_type: String,
    /// Current status
    pub status: String,
    /// Policy scope description
    pub scope: String,
    /// Owner name
    pub owner_name: Option<String>,
    /// Tags for categorization
    pub tags: HashSet<String>,
    /// When the policy becomes effective
    pub effective_date: Option<chrono::DateTime<chrono::Utc>>,
    /// When the policy expires
    pub expiration_date: Option<chrono::DateTime<chrono::Utc>>,
}
