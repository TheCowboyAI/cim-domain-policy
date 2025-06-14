//! Authentication-specific components for Policy aggregates
//!
//! These components enable policies to define and enforce authentication requirements.

use crate::value_objects::authentication::*;
use cim_domain::Component;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

/// Authentication requirements component for policies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationRequirementsComponent {
    /// Minimum number of authentication factors required
    pub min_factors: u8,

    /// Specific factor types that must be used
    pub required_factors: Vec<AuthenticationFactor>,

    /// Optional factors that can strengthen authentication
    pub optional_factors: Vec<AuthenticationFactor>,

    /// Location-based requirements
    pub location_requirements: Option<LocationRequirements>,

    /// Time-based requirements
    pub time_requirements: Option<TimeRequirements>,

    /// Risk-based adjustments to requirements
    pub risk_adjustments: RiskAdjustments,

    /// Minimum trust level required
    pub min_trust_level: TrustLevel,
}

impl Component for AuthenticationRequirementsComponent {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn clone_box(&self) -> Box<dyn Component> {
        Box::new(self.clone())
    }

    fn type_name(&self) -> &'static str {
        "AuthenticationRequirementsComponent"
    }
}

/// Location requirements for authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocationRequirements {
    /// Allowed location constraints
    pub allowed_locations: Vec<LocationConstraint>,

    /// Denied location constraints (blacklist)
    pub denied_locations: Vec<LocationConstraint>,

    /// Whether to require location verification
    pub require_location_verification: bool,

    /// Maximum allowed location uncertainty (in meters)
    pub max_location_uncertainty: Option<f64>,
}

/// Time-based requirements for authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRequirements {
    /// Time constraints for authentication
    pub time_constraints: Vec<TimeConstraint>,

    /// Session duration limits
    pub max_session_duration: chrono::Duration,

    /// Idle timeout before re-authentication
    pub idle_timeout: chrono::Duration,

    /// Whether to enforce strict time synchronization
    pub require_time_sync: bool,
}

/// Risk-based adjustments to authentication requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAdjustments {
    /// Risk thresholds that trigger additional requirements
    pub risk_thresholds: HashMap<RiskLevel, AdditionalRequirements>,

    /// Factors that contribute to risk calculation
    pub risk_factors: Vec<RiskFactor>,

    /// Default action for unspecified risk levels
    pub default_action: RiskAction,
}

/// Additional requirements based on risk level
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdditionalRequirements {
    /// Additional factors required at this risk level
    pub additional_factors: Vec<AuthenticationFactor>,

    /// Whether to require manual approval
    pub require_approval: bool,

    /// Notification targets for this risk level
    pub notify: Vec<Uuid>,

    /// Custom actions to take
    pub custom_actions: Vec<String>,
}

/// Authentication context component for tracking authentication state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationContextComponent {
    /// Rules for determining internal vs external authentication
    pub internal_criteria: InternalCriteria,

    /// External authentication handling configuration
    pub external_handling: ExternalHandling,

    /// Federated authentication mappings
    pub federation_mappings: HashMap<String, FederationConfig>,

    /// Active authentication sessions
    pub active_sessions: HashMap<Uuid, AuthenticationSession>,
}

impl Component for AuthenticationContextComponent {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn clone_box(&self) -> Box<dyn Component> {
        Box::new(self.clone())
    }

    fn type_name(&self) -> &'static str {
        "AuthenticationContextComponent"
    }
}

/// Configuration for federated authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationConfig {
    /// Provider identifier
    pub provider_id: String,

    /// Provider type
    pub provider_type: ProviderType,

    /// Attribute mappings from provider to internal
    pub attribute_mappings: HashMap<String, String>,

    /// Required attributes from provider
    pub required_attributes: HashSet<String>,

    /// Trust level granted by this provider
    pub granted_trust_level: TrustLevel,
}

/// Active authentication session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationSession {
    /// Session identifier
    pub session_id: Uuid,

    /// Identity reference
    pub identity_ref: IdentityRef,

    /// Factors used in this session
    pub factors_used: Vec<AuthenticationFactor>,

    /// Current trust level
    pub trust_level: TrustLevel,

    /// Session start time
    pub started_at: chrono::DateTime<chrono::Utc>,

    /// Last activity time
    pub last_activity: chrono::DateTime<chrono::Utc>,

    /// Session expiration
    pub expires_at: chrono::DateTime<chrono::Utc>,

    /// Location context
    pub location: LocationContext,
}

/// Authentication policy enforcement component
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationEnforcementComponent {
    /// How to enforce authentication requirements
    pub enforcement_mode: AuthenticationEnforcementMode,

    /// Actions to take on authentication failure
    pub failure_actions: Vec<AuthenticationFailureAction>,

    /// Audit configuration
    pub audit_config: AuthenticationAuditConfig,

    /// Rate limiting configuration
    pub rate_limits: RateLimitConfig,
}

impl Component for AuthenticationEnforcementComponent {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn clone_box(&self) -> Box<dyn Component> {
        Box::new(self.clone())
    }

    fn type_name(&self) -> &'static str {
        "AuthenticationEnforcementComponent"
    }
}

/// Authentication enforcement modes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthenticationEnforcementMode {
    /// Strictly enforce all requirements
    Strict,

    /// Allow grace period for compliance
    GracePeriod { duration: chrono::Duration },

    /// Monitor only, don't block
    Monitor,

    /// Adaptive based on risk
    Adaptive,
}

/// Actions to take on authentication failure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthenticationFailureAction {
    /// Block access
    Block,

    /// Log the failure
    Log { severity: LogSeverity },

    /// Send alert
    Alert { targets: Vec<Uuid> },

    /// Trigger incident response
    TriggerIncident { incident_type: String },

    /// Custom action
    Custom { action: String, parameters: HashMap<String, serde_json::Value> },
}

/// Log severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogSeverity {
    Debug,
    Info,
    Warning,
    Error,
    Critical,
}

/// Authentication audit configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationAuditConfig {
    /// What to audit
    pub audit_events: HashSet<AuthenticationAuditEvent>,

    /// Where to send audit logs
    pub audit_destinations: Vec<AuditDestination>,

    /// Retention period for audit logs
    pub retention_period: chrono::Duration,

    /// Whether to include sensitive data
    pub include_sensitive_data: bool,
}

/// Authentication events to audit
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AuthenticationAuditEvent {
    /// Successful authentication
    Success,

    /// Failed authentication attempt
    Failure,

    /// Account lockout
    Lockout,

    /// Privilege escalation
    PrivilegeEscalation,

    /// Session creation
    SessionCreated,

    /// Session termination
    SessionTerminated,

    /// Policy violation
    PolicyViolation,
}

/// Audit log destinations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditDestination {
    /// Local file
    File { path: String },

    /// Syslog
    Syslog { facility: String },

    /// NATS subject
    Nats { subject: String },

    /// External SIEM
    Siem { endpoint: String, api_key: String },
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum attempts per time window
    pub max_attempts: u32,

    /// Time window for rate limiting
    pub window: chrono::Duration,

    /// Lockout duration after exceeding limit
    pub lockout_duration: chrono::Duration,

    /// Whether to apply per-identity or global
    pub scope: RateLimitScope,
}

/// Rate limit scope
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RateLimitScope {
    /// Per identity
    PerIdentity,

    /// Per IP address
    PerIpAddress,

    /// Global
    Global,

    /// Combined (any limit triggers)
    Combined,
}

/// Multi-factor authentication workflow component
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaWorkflowComponent {
    /// MFA workflow identifier
    pub workflow_id: Uuid,

    /// Steps in the MFA process
    pub steps: Vec<MfaStep>,

    /// Current step index
    pub current_step: usize,

    /// Timeout for the entire workflow
    pub workflow_timeout: chrono::Duration,

    /// Completed factors
    pub completed_factors: Vec<CompletedFactor>,
}

impl Component for MfaWorkflowComponent {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn clone_box(&self) -> Box<dyn Component> {
        Box::new(self.clone())
    }

    fn type_name(&self) -> &'static str {
        "MfaWorkflowComponent"
    }
}

/// A step in the MFA workflow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaStep {
    /// Step identifier
    pub step_id: Uuid,

    /// Required factor for this step
    pub required_factor: AuthenticationFactor,

    /// Timeout for this step
    pub step_timeout: chrono::Duration,

    /// Whether this step is optional
    pub optional: bool,

    /// Fallback options if primary fails
    pub fallback_factors: Vec<AuthenticationFactor>,
}

/// Record of a completed authentication factor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletedFactor {
    /// Factor that was completed
    pub factor: AuthenticationFactor,

    /// When it was completed
    pub completed_at: chrono::DateTime<chrono::Utc>,

    /// Verification method used
    pub verification_method: String,

    /// Additional metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authentication_requirements_component() {
        let requirements = AuthenticationRequirementsComponent {
            min_factors: 2,
            required_factors: vec![AuthenticationFactor::Password],
            optional_factors: vec![
                AuthenticationFactor::SoftwareToken,
                AuthenticationFactor::Biometric(BiometricType::Fingerprint),
            ],
            location_requirements: None,
            time_requirements: None,
            risk_adjustments: RiskAdjustments {
                risk_thresholds: HashMap::new(),
                risk_factors: vec![],
                default_action: RiskAction::Allow,
            },
            min_trust_level: TrustLevel::Medium,
        };

        assert_eq!(requirements.min_factors, 2);
        assert_eq!(requirements.required_factors.len(), 1);
        assert_eq!(requirements.optional_factors.len(), 2);
        assert_eq!(requirements.type_name(), "AuthenticationRequirementsComponent");
    }

    #[test]
    fn test_authentication_context_component() {
        let mut context = AuthenticationContextComponent {
            internal_criteria: InternalCriteria {
                internal_organizations: HashSet::new(),
                internal_networks: vec![],
                internal_domains: vec!["example.com".to_string()],
                trusted_device_required: false,
            },
            external_handling: ExternalHandling {
                allowed_providers: vec![],
                verification_level: IdentityVerificationLevel::Email,
                risk_config: RiskConfiguration {
                    max_risk_score: 0.7,
                    risk_factors: vec![],
                    risk_actions: HashMap::new(),
                },
            },
            federation_mappings: HashMap::new(),
            active_sessions: HashMap::new(),
        };

        // Add a federation mapping
        context.federation_mappings.insert(
            "google".to_string(),
            FederationConfig {
                provider_id: "google-oauth".to_string(),
                provider_type: ProviderType::OAuth2,
                attribute_mappings: HashMap::new(),
                required_attributes: HashSet::new(),
                granted_trust_level: TrustLevel::Medium,
            },
        );

        assert_eq!(context.federation_mappings.len(), 1);
        assert!(context.federation_mappings.contains_key("google"));
    }

    #[test]
    fn test_mfa_workflow_component() {
        let workflow = MfaWorkflowComponent {
            workflow_id: Uuid::new_v4(),
            steps: vec![
                MfaStep {
                    step_id: Uuid::new_v4(),
                    required_factor: AuthenticationFactor::Password,
                    step_timeout: chrono::Duration::minutes(5),
                    optional: false,
                    fallback_factors: vec![],
                },
                MfaStep {
                    step_id: Uuid::new_v4(),
                    required_factor: AuthenticationFactor::SoftwareToken,
                    step_timeout: chrono::Duration::minutes(2),
                    optional: false,
                    fallback_factors: vec![AuthenticationFactor::SMSVerification],
                },
            ],
            current_step: 0,
            workflow_timeout: chrono::Duration::minutes(10),
            completed_factors: vec![],
        };

        assert_eq!(workflow.steps.len(), 2);
        assert_eq!(workflow.current_step, 0);
        assert!(!workflow.steps[0].optional);
        assert_eq!(workflow.steps[1].fallback_factors.len(), 1);
    }
}
