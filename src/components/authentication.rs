//! Authentication policy components

use bevy_ecs::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Authentication policy configuration
#[derive(Component, Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationPolicy {
    pub policy_id: Uuid,
    pub auth_methods: Vec<AuthMethod>,
    pub min_factors: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthMethod {
    Password,
    Biometric,
    Token,
    Certificate,
    Sms,
    Email,
}

/// Authentication requirements
#[derive(Component, Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequirement {
    pub policy_id: Uuid,
    pub required_level: TrustLevel,
    pub max_attempts: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TrustLevel {
    None = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

/// Authentication context
#[derive(Component, Debug, Clone, Serialize, Deserialize)]
pub struct AuthContext {
    pub session_id: Uuid,
    pub user_id: String,
    pub ip_address: String,
    pub user_agent: String,
}

/// Authentication decision
#[derive(Component, Debug, Clone, Serialize, Deserialize)]
pub struct AuthDecision {
    pub policy_id: Uuid,
    pub allowed: bool,
    pub reason: Option<String>,
}

/// Authentication challenge
#[derive(Component, Debug, Clone, Serialize, Deserialize)]
pub struct AuthChallenge {
    pub challenge_id: Uuid,
    pub challenge_type: ChallengeType,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChallengeType {
    Password,
    Totp,
    WebAuthn,
    EmailCode,
    SmsCode,
} 