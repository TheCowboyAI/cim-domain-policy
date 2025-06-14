//! Authentication-specific events for Policy domain
//!
//! These events represent authentication-related occurrences in the system.

use crate::value_objects::authentication::*;
use crate::aggregate::authentication::{
    AuthenticationRequirementsComponent, FederationConfig, AuthenticationAuditEvent,
};
use crate::commands::authentication::{RiskAssessment, SessionTerminationReason};
use cim_domain::DomainEvent;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Authentication was requested
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationRequested {
    /// Request identifier
    pub request_id: Uuid,

    /// Identity reference (if known)
    pub identity_ref: Option<IdentityRef>,

    /// Location context
    pub location: LocationContext,

    /// Available factors
    pub available_factors: Vec<AuthenticationFactor>,

    /// Timestamp
    pub requested_at: chrono::DateTime<chrono::Utc>,
}

impl DomainEvent for AuthenticationRequested {
    fn event_type(&self) -> &'static str {
        "AuthenticationRequested"
    }

    fn aggregate_id(&self) -> Uuid {
        self.request_id // Use request_id as aggregate_id for cross-domain events
    }

    fn subject(&self) -> String {
        "policy.authentication.requested.v1".to_string()
    }
}

/// Authentication policy was applied
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationPolicyApplied {
    /// Policy ID that was applied
    pub policy_id: Uuid,

    /// Request ID
    pub request_id: Uuid,

    /// Requirements determined by policy
    pub requirements: AuthenticationRequirementsComponent,

    /// Whether internal or external authentication
    pub authentication_type: AuthenticationType,
}

impl DomainEvent for AuthenticationPolicyApplied {
    fn event_type(&self) -> &'static str {
        "AuthenticationPolicyApplied"
    }

    fn aggregate_id(&self) -> Uuid {
        self.policy_id
    }

    fn subject(&self) -> String {
        "policy.authentication.policy_applied.v1".to_string()
    }
}

/// Authentication type (internal vs external)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthenticationType {
    /// Internal authentication (employee, trusted partner)
    Internal,

    /// External authentication (customer, unknown user)
    External,

    /// Federated authentication (through external provider)
    Federated { provider: String },
}

/// Authentication type was determined
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationTypeDetermined {
    /// Request ID
    pub request_id: Uuid,

    /// Determined type
    pub authentication_type: AuthenticationType,

    /// Criteria used for determination
    pub criteria_matched: Vec<String>,
}

impl DomainEvent for AuthenticationTypeDetermined {
    fn event_type(&self) -> &'static str {
        "AuthenticationTypeDetermined"
    }

    fn aggregate_id(&self) -> Uuid {
        self.request_id
    }

    fn subject(&self) -> String {
        "policy.authentication.type_determined.v1".to_string()
    }
}

/// MFA workflow was started
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaWorkflowStarted {
    /// Policy ID
    pub policy_id: Uuid,

    /// Workflow ID
    pub workflow_id: Uuid,

    /// Request ID
    pub request_id: Uuid,

    /// Identity being authenticated
    pub identity_ref: IdentityRef,

    /// Required factors
    pub required_factors: Vec<AuthenticationFactor>,

    /// Workflow timeout
    pub timeout: chrono::Duration,

    /// Started at
    pub started_at: chrono::DateTime<chrono::Utc>,
}

impl DomainEvent for MfaWorkflowStarted {
    fn event_type(&self) -> &'static str {
        "MfaWorkflowStarted"
    }

    fn aggregate_id(&self) -> Uuid {
        self.policy_id
    }

    fn subject(&self) -> String {
        "policy.authentication.mfa_workflow_started.v1".to_string()
    }
}

/// Authentication factor was completed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationFactorCompleted {
    /// Policy ID
    pub policy_id: Uuid,

    /// Workflow ID
    pub workflow_id: Uuid,

    /// Factor that was completed
    pub factor: AuthenticationFactor,

    /// Verification method used
    pub verification_method: String,

    /// Completed at
    pub completed_at: chrono::DateTime<chrono::Utc>,
}

impl DomainEvent for AuthenticationFactorCompleted {
    fn event_type(&self) -> &'static str {
        "AuthenticationFactorCompleted"
    }

    fn aggregate_id(&self) -> Uuid {
        self.policy_id
    }

    fn subject(&self) -> String {
        "policy.authentication.factor_completed.v1".to_string()
    }
}

/// Authentication decision was made
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationDecisionMade {
    /// Policy ID
    pub policy_id: Uuid,

    /// Request ID
    pub request_id: Uuid,

    /// Decision
    pub decision: AuthenticationDecision,

    /// Risk assessment used
    pub risk_assessment: RiskAssessment,

    /// Decision timestamp
    pub decided_at: chrono::DateTime<chrono::Utc>,
}

impl DomainEvent for AuthenticationDecisionMade {
    fn event_type(&self) -> &'static str {
        "AuthenticationDecisionMade"
    }

    fn aggregate_id(&self) -> Uuid {
        self.policy_id
    }

    fn subject(&self) -> String {
        "policy.authentication.decision_made.v1".to_string()
    }
}

/// Authentication session was created
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationSessionCreated {
    /// Policy ID
    pub policy_id: Uuid,

    /// Session ID
    pub session_id: Uuid,

    /// Identity
    pub identity_ref: IdentityRef,

    /// Factors used
    pub factors_used: Vec<AuthenticationFactor>,

    /// Trust level
    pub trust_level: TrustLevel,

    /// Session expiration
    pub expires_at: chrono::DateTime<chrono::Utc>,

    /// Location
    pub location: LocationContext,
}

impl DomainEvent for AuthenticationSessionCreated {
    fn event_type(&self) -> &'static str {
        "AuthenticationSessionCreated"
    }

    fn aggregate_id(&self) -> Uuid {
        self.policy_id
    }

    fn subject(&self) -> String {
        "policy.authentication.session_created.v1".to_string()
    }
}

/// Authentication session was terminated
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationSessionTerminated {
    /// Policy ID
    pub policy_id: Uuid,

    /// Session ID
    pub session_id: Uuid,

    /// Termination reason
    pub reason: SessionTerminationReason,

    /// Terminated at
    pub terminated_at: chrono::DateTime<chrono::Utc>,
}

impl DomainEvent for AuthenticationSessionTerminated {
    fn event_type(&self) -> &'static str {
        "AuthenticationSessionTerminated"
    }

    fn aggregate_id(&self) -> Uuid {
        self.policy_id
    }

    fn subject(&self) -> String {
        "policy.authentication.session_terminated.v1".to_string()
    }
}

/// Authentication failed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationFailed {
    /// Policy ID
    pub policy_id: Uuid,

    /// Request ID
    pub request_id: Uuid,

    /// Failure reason
    pub reason: DenialReason,

    /// Identity (if known)
    pub identity_ref: Option<IdentityRef>,

    /// Location
    pub location: LocationContext,

    /// Failed at
    pub failed_at: chrono::DateTime<chrono::Utc>,
}

impl DomainEvent for AuthenticationFailed {
    fn event_type(&self) -> &'static str {
        "AuthenticationFailed"
    }

    fn aggregate_id(&self) -> Uuid {
        self.policy_id
    }

    fn subject(&self) -> String {
        "policy.authentication.failed.v1".to_string()
    }
}

/// Authentication requirements were updated
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationRequirementsUpdated {
    /// Policy ID
    pub policy_id: Uuid,

    /// New requirements
    pub requirements: AuthenticationRequirementsComponent,

    /// Update reason
    pub reason: String,

    /// Updated at
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl DomainEvent for AuthenticationRequirementsUpdated {
    fn event_type(&self) -> &'static str {
        "AuthenticationRequirementsUpdated"
    }

    fn aggregate_id(&self) -> Uuid {
        self.policy_id
    }

    fn subject(&self) -> String {
        "policy.authentication.requirements_updated.v1".to_string()
    }
}

/// Federated authentication was configured
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedAuthenticationConfigured {
    /// Policy ID
    pub policy_id: Uuid,

    /// Provider name
    pub provider_name: String,

    /// Configuration
    pub config: FederationConfig,

    /// Configured at
    pub configured_at: chrono::DateTime<chrono::Utc>,
}

impl DomainEvent for FederatedAuthenticationConfigured {
    fn event_type(&self) -> &'static str {
        "FederatedAuthenticationConfigured"
    }

    fn aggregate_id(&self) -> Uuid {
        self.policy_id
    }

    fn subject(&self) -> String {
        "policy.authentication.federated_configured.v1".to_string()
    }
}

/// External authentication approval was requested
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalAuthenticationApprovalRequested {
    /// Policy ID
    pub policy_id: Uuid,

    /// Request ID
    pub request_id: Uuid,

    /// Approval request ID
    pub approval_request_id: Uuid,

    /// Approval type
    pub approval_type: String,

    /// Approvers notified
    pub approvers: Vec<Uuid>,

    /// Expires at
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

impl DomainEvent for ExternalAuthenticationApprovalRequested {
    fn event_type(&self) -> &'static str {
        "ExternalAuthenticationApprovalRequested"
    }

    fn aggregate_id(&self) -> Uuid {
        self.policy_id
    }

    fn subject(&self) -> String {
        "policy.authentication.external_approval_requested.v1".to_string()
    }
}

/// External authentication approval was received
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalAuthenticationApprovalReceived {
    /// Policy ID
    pub policy_id: Uuid,

    /// Approval request ID
    pub approval_request_id: Uuid,

    /// Approver ID
    pub approver_id: Uuid,

    /// Approved
    pub approved: bool,

    /// Comments
    pub comments: Option<String>,

    /// Received at
    pub received_at: chrono::DateTime<chrono::Utc>,
}

impl DomainEvent for ExternalAuthenticationApprovalReceived {
    fn event_type(&self) -> &'static str {
        "ExternalAuthenticationApprovalReceived"
    }

    fn aggregate_id(&self) -> Uuid {
        self.policy_id
    }

    fn subject(&self) -> String {
        "policy.authentication.external_approval_received.v1".to_string()
    }
}

/// Rate limit was exceeded
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationRateLimitExceeded {
    /// Policy ID
    pub policy_id: Uuid,

    /// Identity or IP that exceeded limit
    pub limited_entity: LimitedEntity,

    /// Attempts made
    pub attempts: u32,

    /// Limit
    pub limit: u32,

    /// Lockout until
    pub lockout_until: chrono::DateTime<chrono::Utc>,
}

impl DomainEvent for AuthenticationRateLimitExceeded {
    fn event_type(&self) -> &'static str {
        "AuthenticationRateLimitExceeded"
    }

    fn aggregate_id(&self) -> Uuid {
        self.policy_id
    }

    fn subject(&self) -> String {
        "policy.authentication.rate_limit_exceeded.v1".to_string()
    }
}

/// Entity that was rate limited
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LimitedEntity {
    /// Identity-based limit
    Identity(IdentityRef),

    /// IP-based limit
    IpAddress(std::net::IpAddr),

    /// Global limit
    Global,
}

/// Authentication audit event occurred
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationAuditEventOccurred {
    /// Policy ID
    pub policy_id: Uuid,

    /// Audit event type
    pub event_type: AuthenticationAuditEvent,

    /// Related entity
    pub entity: Option<IdentityRef>,

    /// Details
    pub details: HashMap<String, serde_json::Value>,

    /// Occurred at
    pub occurred_at: chrono::DateTime<chrono::Utc>,
}

impl DomainEvent for AuthenticationAuditEventOccurred {
    fn event_type(&self) -> &'static str {
        "AuthenticationAuditEventOccurred"
    }

    fn aggregate_id(&self) -> Uuid {
        self.policy_id
    }

    fn subject(&self) -> String {
        "policy.authentication.audit_event_occurred.v1".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_authentication_requested_event() {
        let event = AuthenticationRequested {
            request_id: Uuid::new_v4(),
            identity_ref: Some(IdentityRef::Person(Uuid::new_v4())),
            location: LocationContext {
                ip_address: Some("192.168.1.1".to_string()),
                coordinates: None,
                country: Some("US".to_string()),
                network_type: Some("corporate".to_string()),
                device_id: None,
            },
            available_factors: vec![AuthenticationFactor::Password],
            requested_at: chrono::Utc::now(),
        };

        assert_eq!(event.event_type(), "AuthenticationRequested");
        assert!(event.identity_ref.is_some());
    }

    #[test]
    fn test_authentication_type_enum() {
        let internal = AuthenticationType::Internal;
        let external = AuthenticationType::External;
        let federated = AuthenticationType::Federated { provider: "google".to_string() };

        assert_eq!(internal, AuthenticationType::Internal);
        assert_ne!(internal, external);

        match federated {
            AuthenticationType::Federated { provider } => assert_eq!(provider, "google"),
            _ => panic!("Expected federated type"),
        }
    }

    #[test]
    fn test_limited_entity_variants() {
        let identity_limit = LimitedEntity::Identity(IdentityRef::Person(Uuid::new_v4()));
        let ip_limit = LimitedEntity::IpAddress(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        let global_limit = LimitedEntity::Global;

        match identity_limit {
            LimitedEntity::Identity(_) => {}
            _ => panic!("Expected identity limit"),
        }

        match ip_limit {
            LimitedEntity::IpAddress(ip) => {
                assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
            }
            _ => panic!("Expected IP limit"),
        }

        match global_limit {
            LimitedEntity::Global => {}
            _ => panic!("Expected global limit"),
        }
    }
}
