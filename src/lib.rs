//! Policy domain module
//!
//! This module contains all policy-related domain logic including:
//! - Policy aggregate and components
//! - Policy commands and events
//! - Policy command and query handlers

pub mod aggregate;
pub mod commands;
pub mod events;
pub mod handlers;
pub mod projections;
pub mod queries;
pub mod value_objects;

// Re-export main types
pub use aggregate::{
    Policy, PolicyMarker, PolicyMetadata, PolicyStatus, PolicyType,
    PolicyScope, PolicyException, ViolationSeverity, EnforcementMode,
    RulesComponent, ApprovalRequirementsComponent, ApprovalStateComponent,
    EnforcementComponent, ExternalApprovalRequirement, Approval, Rejection,
    PendingExternalApproval, ExternalVerification, ViolationAction,
    // Authentication components
    AuthenticationRequirementsComponent, LocationRequirements, TimeRequirements,
    RiskAdjustments, AdditionalRequirements, AuthenticationContextComponent,
    FederationConfig, AuthenticationSession, AuthenticationEnforcementComponent,
    AuthenticationEnforcementMode, AuthenticationFailureAction, LogSeverity,
    AuthenticationAuditConfig, AuthenticationAuditEvent, AuditDestination,
    RateLimitConfig, RateLimitScope, MfaWorkflowComponent, MfaStep, CompletedFactor,
};

pub use commands::{
    EnactPolicy, UpdatePolicyRules, SubmitPolicyForApproval,
    ApprovePolicy, RejectPolicy, SuspendPolicy, ReactivatePolicy,
    SupersedePolicy, ArchivePolicy, RequestPolicyExternalApproval,
    RecordPolicyExternalApproval,
    // Authentication commands
    RequestAuthentication, ApplyAuthenticationPolicy, DetermineAuthenticationType,
    StartMfaWorkflow, CompleteAuthenticationFactor, VerificationProof,
    MakeAuthenticationDecision, RiskAssessment, CreateAuthenticationSession,
    TerminateAuthenticationSession, SessionTerminationReason,
    UpdateAuthenticationRequirements, ConfigureFederatedAuthentication,
    HandleAuthenticationFailure, RequestExternalAuthenticationApproval,
};

pub use events::{
    PolicyEnacted, PolicySubmittedForApproval, PolicyApproved,
    PolicyRejected, PolicySuspended, PolicyReactivated,
    PolicySuperseded, PolicyArchived, PolicyExternalApprovalRequested,
    PolicyExternalApprovalReceived,
    // Authentication events
    AuthenticationRequested, AuthenticationPolicyApplied, AuthenticationType,
    AuthenticationTypeDetermined, MfaWorkflowStarted, AuthenticationFactorCompleted,
    AuthenticationDecisionMade, AuthenticationSessionCreated, AuthenticationSessionTerminated,
    AuthenticationFailed, AuthenticationRequirementsUpdated, FederatedAuthenticationConfigured,
    ExternalAuthenticationApprovalRequested, ExternalAuthenticationApprovalReceived,
    AuthenticationRateLimitExceeded, LimitedEntity, AuthenticationAuditEventOccurred,
};

pub use handlers::{
    PolicyCommandHandler,
    PolicyEventHandler,
};

pub use projections::PolicyView;

// Re-export queries
pub use queries::{FindPolicyById, ListPolicies};

// Re-export authentication value objects
pub use value_objects::{
    AuthenticationFactor, BiometricType, TokenType,
    TrustLevel, AuthenticationDecision, DenialReason,
    LocationConstraint, IpNetwork, GeoRegion,
    TimeConstraint, TimeRange, DateRange,
    AuthenticationContext, IdentityRef, LocationContext,
    GeoCoordinates, InternalCriteria, ExternalHandling,
    ExternalProvider, ProviderType, IdentityVerificationLevel,
    RiskConfiguration, RiskFactor, RiskLevel, RiskAction,
};
