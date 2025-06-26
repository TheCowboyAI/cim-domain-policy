//! Authentication systems for managing authentication state and sessions

use bevy_ecs::prelude::*;
use bevy_time::Time;
use chrono::{Duration, Utc};
use uuid::Uuid;

use crate::components::authentication::*;
use crate::components::PolicyRule;
use crate::components::metadata::ComponentMetadata;
use crate::events::authentication::*;
use crate::value_objects::{TrustLevel, RiskLevel, AuthenticationFactor, RiskFactor};

/// System for starting authentication sessions
pub fn start_authentication_session(
    mut commands: Commands,
    mut events: EventWriter<AuthenticationSessionStarted>,
    query: Query<(Entity, &PolicyRule, &AuthenticationRequirementsComponent), Without<AuthenticationSession>>,
    time: Res<Time>,
) {
    for (entity, rule, requirements) in query.iter() {
        // Create session context based on requirements
        let context = SessionContext {
            location: LocationContext {
                ip_address: "127.0.0.1".to_string(), // Would come from actual request
                country: Some("US".to_string()),
                region: None,
                city: None,
                coordinates: None,
            },
            device_info: None,
            risk_assessment: RiskAssessment {
                risk_level: requirements.minimum_trust_level.into(), // Convert trust to risk
                risk_factors: Vec::new(),
                risk_score: 0.0,
            },
            policy_constraints: PolicyConstraints {
                required_factors: requirements.required_factors.clone(),
                minimum_trust_level: requirements.minimum_trust_level.clone(),
                session_duration: Duration::seconds(requirements.session_timeout_seconds as i64),
                location_restrictions: None,
                time_restrictions: None,
            },
            started_at: Utc::now(),
            last_activity: Utc::now(),
            expires_at: Utc::now() + Duration::seconds(requirements.session_timeout_seconds as i64),
        };

        // Create the authentication session state machine
        let session = AuthenticationSession::new(
            requirements.identity_ref.clone(),
            context,
        );

        let session_id = session.session_id;
        let identity_ref = session.identity_ref.clone();

        // Add session component to entity
        commands.entity(entity).insert(session);

        // Emit session started event
        events.write(AuthenticationSessionStarted {
            session_id,
            identity_ref,
            initial_factors: requirements.required_factors.clone(),
            risk_level: requirements.minimum_trust_level.into(),
            timestamp: Utc::now(),
        });
    }
}

/// System for processing authentication inputs through the state machine
pub fn process_authentication_input(
    mut commands: Commands,
    mut sessions: Query<(Entity, &mut AuthenticationSession)>,
    mut state_changed_events: EventWriter<AuthenticationStateChanged>,
    mut completion_events: EventWriter<AuthenticationCompleted>,
    mut termination_events: EventWriter<AuthenticationSessionTerminated>,
    // Input events that trigger state transitions
    mut start_auth_events: EventReader<StartAuthenticationEvent>,
    mut provide_factor_events: EventReader<ProvideFactorEvent>,
    mut timeout_events: EventReader<TimeoutEvent>,
) {
    // Process start authentication events
    for event in start_auth_events.read() {
        if let Ok((entity, mut session)) = sessions.iter_mut().find(|(_, s)| s.session_id == event.session_id) {
            let from_state = session.current_state_name().to_string();
            
            let input = AuthenticationInput::StartAuthentication {
                available_factors: event.available_factors.clone(),
            };
            
            let output = session.process_input(input);
            let to_state = session.current_state_name().to_string();
            
            // Emit state change event
            state_changed_events.write(AuthenticationStateChanged {
                session_id: session.session_id,
                identity_ref: session.identity_ref.clone(),
                from_state,
                to_state,
                output: (&session.session_id, &session.identity_ref, &output).into(),
                timestamp: Utc::now(),
            });
            
            // Handle specific outputs
            match &output {
                AuthenticationOutput::AuthenticationComplete { session_token, trust_level, valid_until } => {
                    completion_events.write(AuthenticationCompleted {
                        session_id: session.session_id,
                        identity_ref: session.identity_ref.clone(),
                        factors_used: session.get_used_factors(),
                        trust_level: trust_level.clone(),
                        session_token_id: session_token.token_id,
                        valid_until: valid_until,
                        timestamp: Utc::now(),
                    });
                }
                AuthenticationOutput::SessionTerminated { final_state } => {
                    termination_events.write(AuthenticationSessionTerminated {
                        session_id: session.session_id,
                        reason: final_state.termination_reason.clone(),
                        factors_used: final_state.factors_used.clone(),
                        final_trust_level: final_state.final_trust_level.clone(),
                        duration_seconds: final_state.total_duration.num_seconds(),
                        timestamp: Utc::now(),
                    });
                    
                    // Remove session component when terminated
                    commands.entity(entity).remove::<AuthenticationSession>();
                }
                _ => {}
            }
        }
    }
    
    // Process provide factor events
    for event in provide_factor_events.read() {
        if let Ok((entity, mut session)) = sessions.iter_mut().find(|(_, s)| s.session_id == event.session_id) {
            let from_state = session.current_state_name().to_string();
            
            let input = AuthenticationInput::ProvideFactor {
                factor: event.factor.clone(),
                proof: event.proof.clone(),
            };
            
            let output = session.process_input(input);
            let to_state = session.current_state_name().to_string();
            
            // Emit state change event
            state_changed_events.write(AuthenticationStateChanged {
                session_id: session.session_id,
                identity_ref: session.identity_ref.clone(),
                from_state,
                to_state,
                output: (&session.session_id, &session.identity_ref, &output).into(),
                timestamp: Utc::now(),
            });
        }
    }
}

/// System for checking session timeouts
pub fn check_session_timeouts(
    mut commands: Commands,
    mut sessions: Query<(Entity, &mut AuthenticationSession)>,
    mut termination_events: EventWriter<AuthenticationSessionTerminated>,
    time: Res<Time>,
) {
    let now = Utc::now();
    
    for (entity, mut session) in sessions.iter_mut() {
        // Check for absolute timeout
        if now > session.context.expires_at {
            let input = AuthenticationInput::Timeout {
                timeout_type: TimeoutType::Absolute,
            };
            
            let output = session.process_input(input);
            
            if let AuthenticationOutput::SessionTerminated { final_state } = output {
                termination_events.write(AuthenticationSessionTerminated {
                    session_id: session.session_id,
                    reason: final_state.termination_reason,
                    factors_used: final_state.factors_used,
                    final_trust_level: final_state.final_trust_level,
                    duration_seconds: final_state.total_duration.num_seconds(),
                    timestamp: now,
                });
                
                commands.entity(entity).remove::<AuthenticationSession>();
            }
        }
        
        // Check for inactivity timeout (e.g., 15 minutes)
        let inactivity_threshold = Duration::minutes(15);
        if now.signed_duration_since(session.context.last_activity) > inactivity_threshold {
            let input = AuthenticationInput::Timeout {
                timeout_type: TimeoutType::Inactivity,
            };
            
            let output = session.process_input(input);
            
            if let AuthenticationOutput::SessionTerminated { final_state } = output {
                termination_events.write(AuthenticationSessionTerminated {
                    session_id: session.session_id,
                    reason: final_state.termination_reason,
                    factors_used: final_state.factors_used,
                    final_trust_level: final_state.final_trust_level,
                    duration_seconds: final_state.total_duration.num_seconds(),
                    timestamp: now,
                });
                
                commands.entity(entity).remove::<AuthenticationSession>();
            }
        }
    }
}

/// System for updating authentication status components
pub fn update_authentication_status(
    mut commands: Commands,
    sessions: Query<(Entity, &AuthenticationSession), Changed<AuthenticationSession>>,
    mut statuses: Query<&mut AuthenticationStatus>,
) {
    for (entity, session) in sessions.iter() {
        if let Ok(mut status) = statuses.get_mut(entity) {
            // Update existing status
            status.is_authenticated = session.is_authenticated();
            status.session_id = Some(session.session_id);
            
            match &session.current_state {
                AuthenticationState::Authenticated { factors_used, trust_level, established_at } => {
                    status.authentication_time = Some(established_at);
                    status.trust_level = trust_level.clone();
                    status.factors_used = factors_used.clone();
                }
                _ => {
                    status.authentication_time = None;
                    status.trust_level = TrustLevel::None;
                    status.factors_used.clear();
                }
            }
        } else {
            // Create new status component
            let mut status = AuthenticationStatus {
                is_authenticated: session.is_authenticated(),
                authentication_time: None,
                trust_level: TrustLevel::None,
                factors_used: Vec::new(),
                session_id: Some(session.session_id),
            };
            
            if let AuthenticationState::Authenticated { factors_used, trust_level, established_at } = &session.current_state {
                status.authentication_time = Some(established_at);
                status.trust_level = trust_level.clone();
                status.factors_used = factors_used.clone();
            }
            
            commands.entity(entity).insert(status);
        }
    }
}

/// System for handling risk assessment changes
pub fn handle_risk_assessment_changes(
    mut sessions: Query<&mut AuthenticationSession>,
    mut risk_events: EventReader<RiskAssessmentChangedEvent>,
    mut state_changed_events: EventWriter<AuthenticationStateChanged>,
) {
    for event in risk_events.read() {
        if let Ok(mut session) = sessions.iter_mut().find(|s| s.session_id == event.session_id) {
            // Update session context
            session.context.risk_assessment = RiskAssessment {
                risk_level: event.new_risk_level.clone(),
                risk_factors: event.risk_factors.clone(),
                risk_score: event.risk_score,
            };
            
            let from_state = session.current_state_name().to_string();
            
            let input = AuthenticationInput::RiskAssessmentChanged {
                new_risk_level: event.new_risk_level.clone(),
                risk_factors: event.risk_factors.clone(),
            };
            
            let output = session.process_input(input);
            let to_state = session.current_state_name().to_string();
            
            // Emit state change event
            state_changed_events.write(AuthenticationStateChanged {
                session_id: session.session_id,
                identity_ref: session.identity_ref.clone(),
                from_state,
                to_state,
                output: (&session.session_id, &session.identity_ref, &output).into(),
                timestamp: Utc::now(),
            });
        }
    }
}

// Input event types for the state machine
#[derive(Event)]
pub struct StartAuthenticationEvent {
    pub session_id: Uuid,
    pub available_factors: Vec<AuthenticationFactor>,
}

#[derive(Event)]
pub struct ProvideFactorEvent {
    pub session_id: Uuid,
    pub factor: AuthenticationFactor,
    pub proof: FactorProof,
}

#[derive(Event)]
pub struct TimeoutEvent {
    pub session_id: Uuid,
    pub timeout_type: TimeoutType,
}

#[derive(Event)]
pub struct RiskAssessmentChangedEvent {
    pub session_id: Uuid,
    pub new_risk_level: RiskLevel,
    pub risk_factors: Vec<RiskFactor>,
    pub risk_score: f32,
}

// Helper trait implementation for converting TrustLevel to RiskLevel
impl From<TrustLevel> for RiskLevel {
    fn from(trust: TrustLevel) -> Self {
        match trust {
            TrustLevel::None => RiskLevel::Critical,
            TrustLevel::Low => RiskLevel::High,
            TrustLevel::Medium => RiskLevel::Medium,
            TrustLevel::High => RiskLevel::Low,
        }
    }
}

// Extension methods are already defined in components/authentication.rs 