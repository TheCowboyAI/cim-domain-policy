//! Query types for the Policy domain

use crate::value_objects::PolicyId;
use serde::{Deserialize, Serialize};

/// Query to find a policy by ID
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindPolicyById {
    /// The ID of the policy to find
    pub policy_id: PolicyId,
}

/// Query to list all policies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListPolicies {
    /// Optional filter by policy type
    pub policy_type: Option<String>,
    /// Maximum number of results to return
    pub limit: Option<usize>,
    /// Offset for pagination
    pub offset: Option<usize>,
}
