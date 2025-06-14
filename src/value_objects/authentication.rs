//! Authentication-related value objects for the Policy domain
//!
//! These value objects support authentication policy composition with
//! Identity, Location, and Workflow domains.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use uuid::Uuid;

/// Authentication factors that can be required by policies
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AuthenticationFactor {
    /// Traditional password authentication
    Password,
    /// One-time password (OTP)
    Otp,
    /// SMS verification
    Sms,
    /// Email verification
    Email,
    /// Biometric authentication
    Biometric(BiometricType),
    /// Hardware token (e.g., YubiKey, smart card)
    HardwareToken(TokenType),
    /// Software token (e.g., TOTP, authenticator app)
    SoftwareToken,
    /// Security questions
    SecurityQuestion,
    /// Email verification (legacy)
    EmailVerification,
    /// SMS verification (legacy)
    SMSVerification,
    /// Push notification to registered device
    PushNotification,
    /// Certificate-based authentication
    CertificateBased,
}

/// Types of biometric authentication
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BiometricType {
    Fingerprint,
    FaceRecognition,
    IrisScanning,
    VoiceRecognition,
    BehavioralBiometrics,
}

/// Types of hardware tokens
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TokenType {
    YubiKey,
    SmartCard,
    USBToken,
    NFCToken,
    BluetoothToken,
}

/// Trust levels for identity verification
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TrustLevel {
    /// No trust established
    None = 0,
    /// Basic trust (e.g., password only)
    Low = 1,
    /// Medium trust (e.g., password + one factor)
    Medium = 2,
    /// High trust (e.g., multi-factor authentication)
    High = 3,
    /// Very high trust (e.g., biometric + hardware token)
    VeryHigh = 4,
}

impl TrustLevel {
    /// Check if this trust level meets or exceeds the required level
    pub fn meets_requirement(&self, required: TrustLevel) -> bool {
        *self >= required
    }
}

/// Authentication decision outcomes
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthenticationDecision {
    /// Authentication approved
    Approved {
        trust_level: TrustLevel,
        session_duration: chrono::Duration,
        restrictions: Vec<String>,
    },
    /// Authentication denied
    Denied {
        reason: DenialReason,
        retry_allowed: bool,
        lockout_until: Option<chrono::DateTime<chrono::Utc>>,
    },
    /// Step-up authentication required
    StepUpRequired {
        current_trust_level: TrustLevel,
        required_trust_level: TrustLevel,
        additional_factors: Vec<AuthenticationFactor>,
    },
    /// Manual review required
    ManualReviewRequired {
        reason: String,
        review_id: Uuid,
        timeout: chrono::Duration,
    },
    /// Additional factors required
    ChallengeRequired {
        required_factors: Vec<AuthenticationFactor>,
        timeout: chrono::Duration,
    },
    /// Pending external approval
    PendingApproval {
        approval_type: String,
        request_id: Uuid,
        expires_at: chrono::DateTime<chrono::Utc>,
    },
}

/// Reason for authentication denial
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DenialReason {
    InvalidCredentials,
    AccountLocked,
    AccountDisabled,
    AccountExpired,
    PasswordExpired,
    TooManyAttempts,
    RiskThresholdExceeded,
    LocationRestricted,
    TimeRestricted,
    DeviceNotTrusted,
    InsufficientFactors,
    Other(String),
}

/// Location constraints for authentication policies
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LocationConstraint {
    /// Specific IP addresses allowed
    IpAllowlist(HashSet<IpAddr>),
    /// IP ranges allowed (CIDR notation)
    IpRanges(Vec<IpNetwork>),
    /// Geographic regions allowed
    GeoRegions(Vec<GeoRegion>),
    /// Specific countries allowed
    Countries(HashSet<String>), // ISO 3166-1 alpha-2 codes
    /// Custom location rules
    Custom(HashMap<String, serde_json::Value>),
}

/// IP network range (simplified CIDR)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IpNetwork {
    pub network: IpAddr,
    pub prefix_len: u8,
}

impl IpNetwork {
    /// Check if an IP address is within this network
    pub fn contains(&self, addr: &IpAddr) -> bool {
        match (self.network, addr) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let net_bits = u32::from(net);
                let ip_bits = u32::from(*ip);
                let mask = !((1u32 << (32 - self.prefix_len)) - 1);
                (net_bits & mask) == (ip_bits & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let net_bits = u128::from(net);
                let ip_bits = u128::from(*ip);
                let mask = !((1u128 << (128 - self.prefix_len)) - 1);
                (net_bits & mask) == (ip_bits & mask)
            }
            _ => false, // IPv4 vs IPv6 mismatch
        }
    }
}

/// Geographic region definition
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GeoRegion {
    pub name: String,
    pub center_lat: f64,
    pub center_lon: f64,
    pub radius_km: f64,
}

impl Eq for GeoRegion {}

/// Time-based constraints for authentication
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeConstraint {
    /// Allowed days of week (0 = Sunday, 6 = Saturday)
    pub allowed_days: HashSet<u8>,
    /// Allowed time ranges (in UTC)
    pub allowed_hours: Vec<TimeRange>,
    /// Timezone for local time restrictions
    pub timezone: Option<String>,
    /// Blackout periods (e.g., holidays)
    pub blackout_periods: Vec<DateRange>,
}

/// Time range within a day
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeRange {
    pub start_hour: u8,
    pub start_minute: u8,
    pub end_hour: u8,
    pub end_minute: u8,
}

/// Date range for blackout periods
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DateRange {
    pub start: chrono::NaiveDate,
    pub end: chrono::NaiveDate,
}

/// Authentication context for policy evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationContext {
    /// Unique request identifier
    pub request_id: Uuid,
    /// Reference to identity (if known)
    pub identity_ref: Option<IdentityRef>,
    /// Location information
    pub location: LocationContext,
    /// Available authentication factors
    pub factors_available: Vec<AuthenticationFactor>,
    /// Applied policy ID
    pub policy_id: Option<Uuid>,
    /// Request timestamp
    pub requested_at: chrono::DateTime<chrono::Utc>,
}

/// Reference to an identity in the Identity domain
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdentityRef {
    /// Reference to a person
    Person(Uuid),
    /// Reference to an organization
    Organization(Uuid),
    /// Reference to a system/service account
    System(Uuid),
    /// External identity reference
    External {
        provider: String,
        external_id: String,
    },
}

/// Location context for authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocationContext {
    /// IP address of the request
    pub ip_address: Option<String>,
    /// Geographic coordinates (if available)
    pub coordinates: Option<(f64, f64)>,
    /// Country code (ISO 3166-1 alpha-2)
    pub country: Option<String>,
    /// Network type (e.g., "corporate", "public", "vpn")
    pub network_type: Option<String>,
    /// Device identifier
    pub device_id: Option<String>,
}

/// Geographic coordinates
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct GeoCoordinates {
    pub latitude: f64,
    pub longitude: f64,
}

/// Internal criteria for determining internal vs external authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalCriteria {
    /// Organization IDs considered internal
    pub internal_organizations: HashSet<Uuid>,
    /// Network ranges considered internal
    pub internal_networks: Vec<IpNetwork>,
    /// Domain patterns for internal emails
    pub internal_domains: Vec<String>,
    /// Device trust requirements
    pub trusted_device_required: bool,
}

impl InternalCriteria {
    /// Check if an identity reference is internal
    pub fn is_internal_identity(&self, identity: &IdentityRef) -> bool {
        match identity {
            IdentityRef::Organization(id) => self.internal_organizations.contains(id),
            IdentityRef::External { .. } => false,
            _ => false, // Persons and systems need organization association
        }
    }

    /// Check if an IP address is from an internal network
    pub fn is_internal_network(&self, ip: &IpAddr) -> bool {
        self.internal_networks.iter().any(|net| net.contains(ip))
    }

    /// Check if an email domain is internal
    pub fn is_internal_domain(&self, email: &str) -> bool {
        if let Some(domain) = email.split('@').nth(1) {
            self.internal_domains.iter().any(|pattern| {
                if pattern.starts_with('*') {
                    domain.ends_with(&pattern[1..])
                } else {
                    domain == pattern
                }
            })
        } else {
            false
        }
    }
}

/// External authentication handling configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalHandling {
    /// Allowed external identity providers
    pub allowed_providers: Vec<ExternalProvider>,
    /// Required verification level
    pub verification_level: IdentityVerificationLevel,
    /// Risk assessment configuration
    pub risk_config: RiskConfiguration,
}

/// External identity provider configuration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalProvider {
    pub provider_id: String,
    pub provider_type: ProviderType,
    pub trust_level: TrustLevel,
}

/// Types of external identity providers
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProviderType {
    OAuth2,
    SAML,
    OpenIDConnect,
    LDAP,
    Custom(String),
}

/// Identity verification levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum IdentityVerificationLevel {
    /// No verification required
    None = 0,
    /// Email verification only
    Email = 1,
    /// Phone verification
    Phone = 2,
    /// Government ID verification
    GovernmentId = 3,
    /// In-person verification
    InPerson = 4,
}

/// Risk assessment configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskConfiguration {
    /// Maximum acceptable risk score (0.0 - 1.0)
    pub max_risk_score: f32,
    /// Factors that increase risk
    pub risk_factors: Vec<RiskFactor>,
    /// Actions based on risk level
    pub risk_actions: HashMap<RiskLevel, RiskAction>,
}

/// Factors that contribute to risk assessment
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskFactor {
    UnknownLocation,
    UnusualTime,
    NewDevice,
    FailedAttempts,
    SuspiciousPattern,
    HighValueTransaction,
}

/// Risk levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Actions to take based on risk assessment
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskAction {
    Allow,
    RequireAdditionalFactor,
    RequireApproval,
    Deny,
    Alert(Vec<Uuid>), // User IDs to alert
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_trust_level_comparison() {
        assert!(TrustLevel::High.meets_requirement(TrustLevel::Medium));
        assert!(!TrustLevel::Low.meets_requirement(TrustLevel::High));
        assert!(TrustLevel::Medium.meets_requirement(TrustLevel::Medium));
    }

    #[test]
    fn test_ip_network_contains() {
        let network = IpNetwork {
            network: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)),
            prefix_len: 24,
        };

        assert!(network.contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        assert!(!network.contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 2, 100))));
    }

    #[test]
    fn test_internal_criteria() {
        let mut criteria = InternalCriteria {
            internal_organizations: HashSet::new(),
            internal_networks: vec![
                IpNetwork {
                    network: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                    prefix_len: 8,
                },
            ],
            internal_domains: vec!["example.com".to_string(), "*.internal.com".to_string()],
            trusted_device_required: true,
        };

        let org_id = Uuid::new_v4();
        criteria.internal_organizations.insert(org_id);

        // Test organization check
        assert!(criteria.is_internal_identity(&IdentityRef::Organization(org_id)));
        assert!(!criteria.is_internal_identity(&IdentityRef::Organization(Uuid::new_v4())));

        // Test network check
        assert!(criteria.is_internal_network(&IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))));
        assert!(!criteria.is_internal_network(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));

        // Test domain check
        assert!(criteria.is_internal_domain("user@example.com"));
        assert!(criteria.is_internal_domain("user@sub.internal.com"));
        assert!(!criteria.is_internal_domain("user@external.com"));
    }
}
