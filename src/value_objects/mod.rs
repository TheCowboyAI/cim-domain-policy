//! Value objects for the Policy domain

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub mod authentication;

/// Policy identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PolicyId(pub Uuid);

impl PolicyId {
    /// Create a new policy ID
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for PolicyId {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Uuid> for PolicyId {
    fn from(id: Uuid) -> Self {
        Self(id)
    }
}

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
