//! Value objects for the Policy domain

pub mod authentication;

// Re-export authentication types
pub use authentication::{
    AuthenticationFactor, BiometricType, TokenType,
    TrustLevel, AuthenticationDecision, DenialReason,
    LocationConstraint, IpNetwork, GeoRegion,
    TimeConstraint, TimeRange, DateRange,
    AuthenticationContext, IdentityRef, LocationContext,
    GeoCoordinates, InternalCriteria, ExternalHandling,
    ExternalProvider, ProviderType, IdentityVerificationLevel,
    RiskConfiguration, RiskFactor, RiskLevel, RiskAction,
};
