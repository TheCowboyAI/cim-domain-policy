//! Authentication command handlers for the Policy domain
//!
//! These handlers process authentication-related commands and coordinate
//! with other domains through events.

use crate::aggregate::Policy;
use crate::aggregate::authentication::*;
use crate::commands::authentication::*;
use crate::events::authentication::*;
use crate::value_objects::authentication::*;
use cim_domain::{
    DomainError, DomainResult,
    AggregateRepository,
};
use std::collections::HashMap;
use uuid::Uuid;

/// Authentication command handler
pub struct AuthenticationCommandHandler<R: AggregateRepository<Policy>> {
    repository: R,
}

impl<R: AggregateRepository<Policy>> AuthenticationCommandHandler<R> {
    /// Create a new authentication command handler
    pub fn new(repository: R) -> Self {
        Self {
            repository,
        }
    }

    /// Handle request authentication command
    pub fn handle_request_authentication(
        &self,
        cmd: RequestAuthentication,
    ) -> DomainResult<Vec<Box<dyn cim_domain::DomainEvent>>> {
        // This is a cross-domain command, so we just emit an event
        let event = AuthenticationRequested {
            request_id: cmd.request_id,
            identity_ref: cmd.identity_ref,
            location: cmd.location,
            available_factors: cmd.available_factors,
            requested_at: chrono::Utc::now(),
        };

        Ok(vec![Box::new(event)])
    }

    /// Handle apply authentication policy command
    pub fn handle_apply_authentication_policy(
        &self,
        cmd: ApplyAuthenticationPolicy,
    ) -> DomainResult<Vec<Box<dyn cim_domain::DomainEvent>>> {
        // Load the policy aggregate
        let policy = self.repository
            .load(cim_domain::EntityId::from_uuid(cmd.policy_id))
            .map_err(DomainError::generic)?
            .ok_or_else(|| DomainError::generic("Policy not found"))?;

        // Get authentication requirements from policy
        let requirements = policy
            .get_component::<AuthenticationRequirementsComponent>()
            .ok_or_else(|| DomainError::generic(
                "Policy does not have authentication requirements"
            ))?
            .clone();

        // Determine authentication type based on context
        let auth_type = self.determine_authentication_type(&cmd.context, &policy)?;

        // Create event
        let event = AuthenticationPolicyApplied {
            policy_id: cmd.policy_id,
            request_id: cmd.request_id,
            requirements,
            authentication_type: auth_type,
        };

        Ok(vec![Box::new(event)])
    }

    /// Handle determine authentication type command
    pub fn handle_determine_authentication_type(
        &self,
        cmd: DetermineAuthenticationType,
    ) -> DomainResult<Vec<Box<dyn cim_domain::DomainEvent>>> {
        // This would typically query multiple policies to determine type
        // For now, we'll use a simple implementation

        let mut criteria_matched = Vec::new();
        let mut auth_type = AuthenticationType::External;

        // Check email domain
        if let Some(email) = &cmd.email {
            if email.ends_with("@company.com") || email.ends_with("@internal.com") {
                criteria_matched.push("Internal email domain".to_string());
                auth_type = AuthenticationType::Internal;
            }
        }

        // Check location
        if let Some(network_type) = &cmd.location.network_type {
            if network_type == "corporate" || network_type == "vpn" {
                criteria_matched.push("Corporate network".to_string());
                auth_type = AuthenticationType::Internal;
            }
        }

        let event = AuthenticationTypeDetermined {
            request_id: cmd.request_id,
            authentication_type: auth_type,
            criteria_matched,
        };

        Ok(vec![Box::new(event)])
    }

    /// Handle start MFA workflow command
    pub fn handle_start_mfa_workflow(
        &self,
        cmd: StartMfaWorkflow,
    ) -> DomainResult<Vec<Box<dyn cim_domain::DomainEvent>>> {
        // Load the policy
        let policy = self.repository
            .load(cim_domain::EntityId::from_uuid(cmd.policy_id))
            .map_err(DomainError::generic)?
            .ok_or_else(|| DomainError::generic("Policy not found"))?;

        // Verify policy has MFA requirements
        let requirements = policy
            .get_component::<AuthenticationRequirementsComponent>()
            .ok_or_else(|| DomainError::generic(
                "Policy does not have authentication requirements"
            ))?;

        // Validate required factors
        if cmd.required_factors.len() < requirements.min_factors as usize {
            return Err(DomainError::generic(
                format!("Minimum {} factors required", requirements.min_factors)
            ));
        }

        let event = MfaWorkflowStarted {
            policy_id: cmd.policy_id,
            workflow_id: Uuid::new_v4(),
            request_id: cmd.request_id,
            identity_ref: cmd.identity_ref,
            required_factors: cmd.required_factors,
            timeout: cmd.timeout,
            started_at: chrono::Utc::now(),
        };

        Ok(vec![Box::new(event)])
    }

    /// Handle complete authentication factor command
    pub fn handle_complete_authentication_factor(
        &self,
        cmd: CompleteAuthenticationFactor,
    ) -> DomainResult<Vec<Box<dyn cim_domain::DomainEvent>>> {
        // Load the policy
        let policy = self.repository
            .load(cim_domain::EntityId::from_uuid(cmd.policy_id))
            .map_err(DomainError::generic)?
            .ok_or_else(|| DomainError::generic("Policy not found"))?;

        // Get MFA workflow component
        let workflow = policy
            .get_component::<MfaWorkflowComponent>()
            .ok_or_else(|| DomainError::generic(
                "No active MFA workflow"
            ))?;

        // Verify workflow ID matches
        if workflow.workflow_id != cmd.workflow_id {
            return Err(DomainError::generic(
                "Invalid workflow ID"
            ));
        }

        // Verify factor is required
        let current_step = workflow.steps.get(workflow.current_step)
            .ok_or_else(|| DomainError::generic(
                "Invalid workflow step"
            ))?;

        if current_step.required_factor != cmd.factor &&
           !current_step.fallback_factors.contains(&cmd.factor) {
            return Err(DomainError::generic(
                "Factor not allowed for current step"
            ));
        }

        // Create verification method from proof
        let verification_method = match &cmd.verification_proof {
            VerificationProof::PasswordHash { .. } => "password-hash",
            VerificationProof::OtpCode { .. } => "otp",
            VerificationProof::BiometricMatch { .. } => "biometric",
            VerificationProof::TokenSignature { .. } => "token-signature",
            VerificationProof::EmailToken { .. } => "email-token",
            VerificationProof::SmsCode { .. } => "sms-code",
            VerificationProof::PushApproval { .. } => "push-notification",
            VerificationProof::Certificate { .. } => "certificate",
        }.to_string();

        let event = AuthenticationFactorCompleted {
            policy_id: cmd.policy_id,
            workflow_id: cmd.workflow_id,
            factor: cmd.factor,
            verification_method,
            completed_at: chrono::Utc::now(),
        };

        Ok(vec![Box::new(event)])
    }

    /// Handle make authentication decision command
    pub fn handle_make_authentication_decision(
        &self,
        cmd: MakeAuthenticationDecision,
    ) -> DomainResult<Vec<Box<dyn cim_domain::DomainEvent>>> {
        // Load the policy
        let policy = self.repository
            .load(cim_domain::EntityId::from_uuid(cmd.policy_id))
            .map_err(DomainError::generic)?
            .ok_or_else(|| DomainError::generic("Policy not found"))?;

        // Get requirements
        let requirements = policy
            .get_component::<AuthenticationRequirementsComponent>()
            .ok_or_else(|| DomainError::generic(
                "Policy does not have authentication requirements"
            ))?;

        // Check if minimum factors are met
        if cmd.completed_factors.len() < requirements.min_factors as usize {
            let event = AuthenticationDecisionMade {
                policy_id: cmd.policy_id,
                request_id: cmd.request_id,
                decision: AuthenticationDecision::Denied {
                    reason: DenialReason::InsufficientFactors,
                    retry_allowed: true,
                    lockout_until: None,
                },
                risk_assessment: cmd.risk_assessment,
                decided_at: chrono::Utc::now(),
            };
            return Ok(vec![Box::new(event)]);
        }

        // Check risk assessment
        let decision = match cmd.risk_assessment.risk_level {
            RiskLevel::Low | RiskLevel::Medium => {
                // Check trust level
                let achieved_trust = self.calculate_trust_level(&cmd.completed_factors);
                if achieved_trust >= requirements.min_trust_level {
                    AuthenticationDecision::Approved {
                        trust_level: achieved_trust,
                        session_duration: chrono::Duration::hours(8),
                        restrictions: vec![],
                    }
                } else {
                    AuthenticationDecision::StepUpRequired {
                        current_trust_level: achieved_trust,
                        required_trust_level: requirements.min_trust_level,
                        additional_factors: vec![AuthenticationFactor::SecurityQuestion],
                    }
                }
            }
            RiskLevel::High => {
                AuthenticationDecision::ManualReviewRequired {
                    reason: "High risk detected".to_string(),
                    review_id: Uuid::new_v4(),
                    timeout: chrono::Duration::hours(24),
                }
            }
            RiskLevel::Critical => {
                AuthenticationDecision::Denied {
                    reason: DenialReason::RiskThresholdExceeded,
                    retry_allowed: false,
                    lockout_until: Some(chrono::Utc::now() + chrono::Duration::hours(24)),
                }
            }
        };

        let event = AuthenticationDecisionMade {
            policy_id: cmd.policy_id,
            request_id: cmd.request_id,
            decision,
            risk_assessment: cmd.risk_assessment,
            decided_at: chrono::Utc::now(),
        };

        Ok(vec![Box::new(event)])
    }

    /// Handle create authentication session command
    pub fn handle_create_authentication_session(
        &self,
        cmd: CreateAuthenticationSession,
    ) -> DomainResult<Vec<Box<dyn cim_domain::DomainEvent>>> {
        // Load the policy
        let mut policy = self.repository
            .load(cim_domain::EntityId::from_uuid(cmd.policy_id))
            .map_err(DomainError::generic)?
            .ok_or_else(|| DomainError::generic("Policy not found"))?;

        // Get authentication context
        let mut context = policy
            .get_component::<AuthenticationContextComponent>()
            .cloned()
            .unwrap_or_else(|| AuthenticationContextComponent {
                internal_criteria: InternalCriteria {
                    internal_organizations: Default::default(),
                    internal_networks: vec![],
                    internal_domains: vec![],
                    trusted_device_required: false,
                },
                external_handling: ExternalHandling {
                    allowed_providers: vec![],
                    verification_level: IdentityVerificationLevel::Email,
                    risk_config: RiskConfiguration {
                        max_risk_score: 1.0,
                        risk_factors: vec![],
                        risk_actions: HashMap::new(),
                    },
                },
                federation_mappings: HashMap::new(),
                active_sessions: HashMap::new(),
            });

        // Create session
        let session_id = Uuid::new_v4();
        let expires_at = chrono::Utc::now() + cmd.session_duration;

        let session = AuthenticationSession {
            session_id,
            identity_ref: cmd.identity_ref.clone(),
            factors_used: cmd.factors_used.clone(),
            trust_level: cmd.trust_level,
            started_at: chrono::Utc::now(),
            last_activity: chrono::Utc::now(),
            expires_at,
            location: cmd.location.clone(),
        };

        // Add to active sessions
        context.active_sessions.insert(session_id, session);

        // Update policy
        policy.add_component(context)?;
        self.repository.save(&policy).map_err(DomainError::generic)?;

        let event = AuthenticationSessionCreated {
            policy_id: cmd.policy_id,
            session_id,
            identity_ref: cmd.identity_ref,
            factors_used: cmd.factors_used,
            trust_level: cmd.trust_level,
            expires_at,
            location: cmd.location,
        };

        Ok(vec![Box::new(event)])
    }

    /// Helper: Determine authentication type from context
    fn determine_authentication_type(
        &self,
        context: &AuthenticationContext,
        policy: &Policy,
    ) -> DomainResult<AuthenticationType> {
        // Get authentication context component
        let auth_context = policy
            .get_component::<AuthenticationContextComponent>()
            .ok_or_else(|| DomainError::generic(
                "Policy does not have authentication context"
            ))?;

        // Check internal criteria
        let internal_criteria = &auth_context.internal_criteria;

        // Check organization
        if let Some(IdentityRef::Organization(org_id)) = &context.identity_ref {
            if internal_criteria.internal_organizations.contains(org_id) {
                return Ok(AuthenticationType::Internal);
            }
        }

        // Check network
        if let Some(ip_str) = &context.location.ip_address {
            if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
                if internal_criteria.is_internal_network(&ip) {
                    return Ok(AuthenticationType::Internal);
                }
            }
        }

        // Check for federated providers
        for provider in auth_context.federation_mappings.keys() {
            // In real implementation, would check for provider tokens
            // For now, just check if provider is configured
            if !provider.is_empty() {
                return Ok(AuthenticationType::Federated {
                    provider: provider.clone(),
                });
            }
        }

        // Default to external
        Ok(AuthenticationType::External)
    }

    /// Helper: Calculate trust level from completed factors
    fn calculate_trust_level(&self, factors: &[CompletedFactor]) -> TrustLevel {
        // Simple implementation - more factors = higher trust
        match factors.len() {
            0 => TrustLevel::None,
            1 => TrustLevel::Low,
            2 => TrustLevel::Medium,
            3 => TrustLevel::High,
            _ => TrustLevel::VeryHigh,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cim_domain::InMemoryRepository;

    #[test]
    fn test_request_authentication_handler() {
        let repository = InMemoryRepository::<Policy>::new();
        let handler = AuthenticationCommandHandler::new(repository);

        let cmd = RequestAuthentication {
            request_id: Uuid::new_v4(),
            identity_ref: None,
            location: LocationContext {
                ip_address: None,
                coordinates: None,
                country: Some("US".to_string()),
                network_type: None,
                device_id: None,
            },
            available_factors: vec![AuthenticationFactor::Password],
            client_metadata: HashMap::new(),
        };

        let events = handler.handle_request_authentication(cmd).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type(), "AuthenticationRequested");
    }

    #[test]
    fn test_determine_authentication_type() {
        let repository = InMemoryRepository::<Policy>::new();
        let handler = AuthenticationCommandHandler::new(repository);

        // Test internal email
        let cmd = DetermineAuthenticationType {
            request_id: Uuid::new_v4(),
            identity_ref: None,
            location: LocationContext {
                ip_address: None,
                coordinates: None,
                country: Some("US".to_string()),
                network_type: Some("corporate".to_string()),
                device_id: None,
            },
            email: Some("user@company.com".to_string()),
        };

        let events = handler.handle_determine_authentication_type(cmd).unwrap();
        assert_eq!(events.len(), 1);

        // Can't downcast without as_any method, so just check event type
        assert_eq!(events[0].event_type(), "AuthenticationTypeDetermined");
    }
}
