//! Approval components for policy domain
//!
//! Handles approval requirements and state tracking for policies

use bevy_ecs::component::Component;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;
use chrono::{DateTime, Duration, Utc};

use crate::value_objects::{ApprovalLevel, ApproverRole};

/// Approval requirements component
#[derive(Component, Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequirementsComponent {
    /// Minimum number of approvals needed
    pub min_approvals: u32,
    
    /// Specific approvers required (by ID)
    pub required_approvers: HashSet<Uuid>,
    
    /// Approval roles (any person with these roles can approve)
    pub approval_roles: HashSet<String>,
    
    /// Approval timeout
    pub timeout: Option<Duration>,
    
    /// External approval requirements
    pub external_approvals: Vec<ExternalApprovalRequirement>,
    
    /// Metadata
    pub metadata: super::ComponentMetadata,
}

/// External approval requirement for policies that need additional verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalApprovalRequirement {
    /// Type of external approval (e.g., "yubikey", "biometric", "2fa")
    pub approval_type: String,
    
    /// Description of the requirement
    pub description: String,
    
    /// Metadata for the external system
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Approval state component - tracks ongoing approvals
#[derive(Component, Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalStateComponent {
    /// Current approvals received
    pub approvals: Vec<Approval>,
    
    /// Pending external approvals
    pub pending_external: Vec<PendingExternalApproval>,
    
    /// Rejection reasons if any
    pub rejections: Vec<Rejection>,
    
    /// When approval process started
    pub started_at: DateTime<Utc>,
    
    /// Metadata
    pub metadata: super::ComponentMetadata,
}

/// Approval record for a policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    /// ID of the person who approved
    pub approver_id: Uuid,
    
    /// When the approval was given
    pub approved_at: DateTime<Utc>,
    
    /// Optional comments from the approver
    pub comments: Option<String>,
    
    /// External verification if required
    pub external_verification: Option<ExternalVerification>,
}

/// Pending external approval request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingExternalApproval {
    /// Type of approval required (e.g., "yubikey", "biometric")
    pub approval_type: String,
    
    /// Unique request identifier
    pub request_id: Uuid,
    
    /// When the approval was requested
    pub requested_at: DateTime<Utc>,
    
    /// When the approval request expires
    pub expires_at: Option<DateTime<Utc>>,
}

/// External verification details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalVerification {
    /// Type of verification used (e.g., "yubikey", "biometric", "2fa")
    pub verification_type: String,
    
    /// Unique identifier from the verification system
    pub verification_id: String,
    
    /// When the verification was completed
    pub verified_at: DateTime<Utc>,
    
    /// Additional verification metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Rejection record for a policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rejection {
    /// ID of the person who rejected
    pub rejector_id: Uuid,
    
    /// When the rejection occurred
    pub rejected_at: DateTime<Utc>,
    
    /// Reason for rejection
    pub reason: String,
}

/// Approval requirement component
#[derive(Component, Debug, Clone)]
pub struct ApprovalRequirement {
    pub approval_levels: Vec<ApprovalLevel>,
    pub minimum_approvers: Option<usize>,
    pub quorum_percentage: Option<f32>,
    pub timeout: Option<Duration>,
}

/// Approval status component
#[derive(Component, Debug, Clone)]
pub struct ApprovalStatus {
    pub current_level: ApprovalLevel,
    pub required_levels: Vec<ApprovalLevel>,
    pub approvals: Vec<ApprovalRecord>,
    pub rejection: Option<RejectionRecord>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Approval record
#[derive(Debug, Clone)]
pub struct ApprovalRecord {
    pub approver_id: Uuid,
    pub approver_role: ApproverRole,
    pub approval_level: ApprovalLevel,
    pub timestamp: DateTime<Utc>,
    pub comments: Option<String>,
    pub conditions: Vec<String>,
}

/// Rejection record
#[derive(Debug, Clone)]
pub struct RejectionRecord {
    pub approver_id: Uuid,
    pub reason: String,
    pub timestamp: DateTime<Utc>,
}

/// External approval component
#[derive(Component, Debug, Clone)]
pub struct ExternalApproval {
    pub provider: String,
    pub reference_id: String,
    pub verification_data: HashMap<String, serde_json::Value>,
    pub verified_at: Option<DateTime<Utc>>,
}

/// Approval workflow component
#[derive(Component, Debug, Clone)]
pub struct ApprovalWorkflowComponent {
    pub workflow_id: Uuid,
    pub approval_type: ApprovalType,
    pub status: ApprovalStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Approval type
#[derive(Debug, Clone, PartialEq)]
pub enum ApprovalType {
    Sequential,
    Parallel,
    Hierarchical,
    Quorum,
}

/// Approval exception component
#[derive(Component, Debug, Clone)]
pub struct ApprovalExceptionComponent {
    pub exception_id: Uuid,
    pub reason: String,
    pub approved_by: Uuid,
    pub valid_until: Option<DateTime<Utc>>,
}

impl ApprovalRequirementsComponent {
    /// Create new approval requirements
    pub fn new(min_approvals: u32) -> Self {
        Self {
            min_approvals,
            required_approvers: HashSet::new(),
            approval_roles: HashSet::new(),
            timeout: None,
            external_approvals: Vec::new(),
            metadata: super::ComponentMetadata::default(),
        }
    }
    
    /// Add a required approver
    pub fn add_required_approver(&mut self, approver_id: Uuid) {
        self.required_approvers.insert(approver_id);
        self.metadata.updated_at = Utc::now();
        self.metadata.version += 1;
    }
    
    /// Add an approval role
    pub fn add_approval_role(&mut self, role: String) {
        self.approval_roles.insert(role);
        self.metadata.updated_at = Utc::now();
        self.metadata.version += 1;
    }
    
    /// Set approval timeout
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = Some(timeout);
        self.metadata.updated_at = Utc::now();
        self.metadata.version += 1;
    }
    
    /// Add external approval requirement
    pub fn add_external_approval(&mut self, requirement: ExternalApprovalRequirement) {
        self.external_approvals.push(requirement);
        self.metadata.updated_at = Utc::now();
        self.metadata.version += 1;
    }
}

impl ApprovalStateComponent {
    /// Create new approval state
    pub fn new() -> Self {
        Self {
            approvals: Vec::new(),
            pending_external: Vec::new(),
            rejections: Vec::new(),
            started_at: Utc::now(),
            metadata: super::ComponentMetadata::default(),
        }
    }
    
    /// Add an approval
    pub fn add_approval(&mut self, approval: Approval) {
        self.approvals.push(approval);
        self.metadata.updated_at = Utc::now();
        self.metadata.version += 1;
    }
    
    /// Add a rejection
    pub fn add_rejection(&mut self, rejection: Rejection) {
        self.rejections.push(rejection);
        self.metadata.updated_at = Utc::now();
        self.metadata.version += 1;
    }
    
    /// Add a pending external approval
    pub fn add_pending_external(&mut self, pending: PendingExternalApproval) {
        self.pending_external.push(pending);
        self.metadata.updated_at = Utc::now();
        self.metadata.version += 1;
    }
    
    /// Complete an external approval
    pub fn complete_external_approval(
        &mut self,
        request_id: Uuid,
        verification: ExternalVerification
    ) -> Option<PendingExternalApproval> {
        if let Some(pos) = self.pending_external.iter().position(|p| p.request_id == request_id) {
            let pending = self.pending_external.remove(pos);
            
            // Find the corresponding approval and add verification
            if let Some(approval) = self.approvals.last_mut() {
                approval.external_verification = Some(verification);
            }
            
            self.metadata.updated_at = Utc::now();
            self.metadata.version += 1;
            
            Some(pending)
        } else {
            None
        }
    }
    
    /// Check if approval requirements are met
    pub fn is_approved(&self, requirements: &ApprovalRequirementsComponent) -> bool {
        // Check minimum approvals
        if self.approvals.len() < requirements.min_approvals as usize {
            return false;
        }
        
        // Check required approvers
        let approver_ids: HashSet<_> = self.approvals.iter()
            .map(|a| a.approver_id)
            .collect();
        
        if !requirements.required_approvers.is_subset(&approver_ids) {
            return false;
        }
        
        // Check for pending external approvals
        if !self.pending_external.is_empty() {
            return false;
        }
        
        // Check if any rejections exist
        if !self.rejections.is_empty() {
            return false;
        }
        
        true
    }
}

impl Default for ApprovalStateComponent {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_approval_requirements() {
        let mut requirements = ApprovalRequirementsComponent::new(2);
        let approver1 = Uuid::new_v4();
        let approver2 = Uuid::new_v4();
        
        requirements.add_required_approver(approver1);
        requirements.add_required_approver(approver2);
        requirements.add_approval_role("manager".to_string());
        
        assert_eq!(requirements.min_approvals, 2);
        assert!(requirements.required_approvers.contains(&approver1));
        assert!(requirements.required_approvers.contains(&approver2));
        assert!(requirements.approval_roles.contains("manager"));
    }
    
    #[test]
    fn test_approval_state() {
        let mut state = ApprovalStateComponent::new();
        let approver_id = Uuid::new_v4();
        
        let approval = Approval {
            approver_id,
            approved_at: Utc::now(),
            comments: Some("Looks good".to_string()),
            external_verification: None,
        };
        
        state.add_approval(approval);
        
        assert_eq!(state.approvals.len(), 1);
        assert_eq!(state.approvals[0].approver_id, approver_id);
    }
    
    #[test]
    fn test_approval_requirements_met() {
        let mut requirements = ApprovalRequirementsComponent::new(2);
        let approver1 = Uuid::new_v4();
        let approver2 = Uuid::new_v4();
        requirements.add_required_approver(approver1);
        
        let mut state = ApprovalStateComponent::new();
        
        // Add first approval
        state.add_approval(Approval {
            approver_id: approver1,
            approved_at: Utc::now(),
            comments: None,
            external_verification: None,
        });
        
        // Not enough approvals yet
        assert!(!state.is_approved(&requirements));
        
        // Add second approval
        state.add_approval(Approval {
            approver_id: approver2,
            approved_at: Utc::now(),
            comments: None,
            external_verification: None,
        });
        
        // Now requirements are met
        assert!(state.is_approved(&requirements));
    }
} 