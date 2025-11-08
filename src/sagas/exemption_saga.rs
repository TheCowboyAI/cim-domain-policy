//! Policy exemption workflow saga implementation

use super::*;
use crate::aggregate::{ExemptionScope, ExemptionCondition};
use chrono::{Duration, Utc};

/// Saga for managing policy exemption workflow
pub struct ExemptionWorkflowSaga {
    metadata: SagaMetadata,
    policy_id: PolicyId,
    requester: String,
    current_state: SagaState,
    markov_chain: MarkovChain,
    risk_assessment: Option<(RiskLevel, String)>,
    business_justification: Option<(String, BusinessPriority)>,
    approvals: Vec<(String, ApprovalLevel)>,
    exemption_conditions: Vec<ExemptionCondition>,
    exemption_id: Option<ExemptionId>,
    expiry: Option<chrono::DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq)]
pub enum BusinessPriority {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ApprovalLevel {
    Manager,
    Director,
    Security,
    Compliance,
}

impl ExemptionWorkflowSaga {
    /// Create a new exemption workflow saga
    pub fn new(policy_id: PolicyId, requester: String) -> Self {
        let mut markov_chain = MarkovChain::new();

        // Define state transitions for exemption workflow
        markov_chain.add_transition(SagaState::ExemptionRequested, SagaState::ExemptionUnderReview, 0.9);
        markov_chain.add_transition(SagaState::ExemptionRequested, SagaState::ExemptionDenied, 0.1);
        markov_chain.add_transition(SagaState::ExemptionUnderReview, SagaState::ExemptionGranted, 0.5);
        markov_chain.add_transition(SagaState::ExemptionUnderReview, SagaState::ExemptionDenied, 0.4);
        markov_chain.add_transition(SagaState::ExemptionUnderReview, SagaState::ExemptionRequested, 0.1);
        markov_chain.add_transition(SagaState::ExemptionGranted, SagaState::ExemptionExpired, 1.0);

        // Set rewards
        markov_chain.set_state_reward(SagaState::ExemptionGranted, 30.0);
        markov_chain.set_state_reward(SagaState::ExemptionDenied, -20.0);
        markov_chain.set_state_reward(SagaState::ExemptionExpired, 0.0);

        Self {
            metadata: SagaMetadata::new(requester.clone()),
            policy_id,
            requester,
            current_state: SagaState::ExemptionRequested,
            markov_chain,
            risk_assessment: None,
            business_justification: None,
            approvals: Vec::new(),
            exemption_conditions: Vec::new(),
            exemption_id: None,
            expiry: None,
        }
    }

    /// Set risk assessment for the exemption
    pub fn set_risk_assessment(&mut self, level: RiskLevel, notes: String) {
        self.risk_assessment = Some((level, notes));
        self.metadata.update();
    }

    /// Set business justification
    pub fn set_business_justification(&mut self, justification: String, priority: BusinessPriority) {
        self.business_justification = Some((justification, priority));
        self.metadata.update();
    }

    /// Add an approval
    pub fn add_approval(&mut self, approver: String, level: ApprovalLevel) {
        self.approvals.push((approver, level));
        self.metadata.update();
    }

    /// Check if ready for approval
    pub fn ready_for_approval(&self) -> bool {
        self.risk_assessment.is_some() && self.business_justification.is_some()
    }

    /// Check if sufficient approvals obtained
    pub fn has_sufficient_approvals(&self) -> bool {
        // High-risk exemptions need more approvals
        let required_approvals = match &self.risk_assessment {
            Some((RiskLevel::Critical, _)) => 4,
            Some((RiskLevel::High, _)) => 3,
            Some((RiskLevel::Medium, _)) => 2,
            _ => 1,
        };

        self.approvals.len() >= required_approvals
    }

    /// Grant exemption with conditions
    pub fn grant_exemption(&mut self, conditions: Vec<ExemptionCondition>, duration: Duration) {
        self.exemption_conditions = conditions;
        self.exemption_id = Some(ExemptionId::new());
        self.expiry = Some(Utc::now() + duration);
        self.current_state = SagaState::ExemptionGranted;
        self.metadata.update();
    }

    /// Check if exemption needs expiry check
    pub fn needs_expiry_check(&self) -> bool {
        self.current_state == SagaState::ExemptionGranted && self.expiry.is_some()
    }

    /// Check if exemption has expired
    pub fn check_expiry(&mut self) {
        if let Some(expiry) = self.expiry {
            if Utc::now() > expiry {
                self.current_state = SagaState::ExemptionExpired;
                self.metadata.update();
            }
        }
    }
}

impl PolicySaga for ExemptionWorkflowSaga {
    fn current_state(&self) -> SagaState {
        self.current_state.clone()
    }

    fn available_transitions(&self) -> Vec<StateTransition> {
        match self.current_state {
            SagaState::ExemptionRequested => vec![
                StateTransition::ReviewExemption,
                StateTransition::DenyExemption,
            ],
            SagaState::ExemptionUnderReview => vec![
                StateTransition::GrantExemption,
                StateTransition::DenyExemption,
                StateTransition::RequestChanges,
            ],
            SagaState::ExemptionGranted => vec![StateTransition::ExpireExemption],
            _ => vec![],
        }
    }

    fn transition_probability(&self, from: &SagaState, to: &SagaState) -> f64 {
        self.markov_chain.transition_probability(from, to)
    }

    fn apply_event(&mut self, event: &PolicyEvent) -> Result<(), SagaError> {
        match event {
            PolicyEvent::PolicyExemptionGranted(e) if e.policy_id == self.policy_id => {
                self.exemption_id = Some(e.exemption_id);
                self.current_state = SagaState::ExemptionGranted;
                self.expiry = Some(e.valid_until);
                self.metadata.update();
                Ok(())
            }
            PolicyEvent::PolicyExemptionRevoked(e) => {
                if Some(e.exemption_id) == self.exemption_id {
                    self.current_state = SagaState::ExemptionDenied;
                    self.metadata.update();
                }
                Ok(())
            }
            PolicyEvent::PolicyExemptionExpired(e) => {
                if Some(e.exemption_id) == self.exemption_id {
                    self.current_state = SagaState::ExemptionExpired;
                    self.metadata.update();
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn get_commands(&self) -> Vec<PolicyCommand> {
        let mut commands = Vec::new();

        match self.current_state {
            SagaState::ExemptionRequested if self.ready_for_approval() => {
                // Move to review state
                commands.push(PolicyCommand::RequestExemption(RequestExemption {
                    identity: super::create_root_command(),
                    policy_id: self.policy_id,
                    requester: self.requester.clone(),
                    reason: self.risk_assessment
                        .as_ref()
                        .map(|(_, notes)| notes.clone())
                        .unwrap_or_default(),
                    justification: self.business_justification
                        .as_ref()
                        .map(|(just, _)| just.clone())
                        .unwrap_or_default(),
                    duration: Duration::days(30),
                    scope: ExemptionScope::User(self.requester.clone()),
                }));
            }
            SagaState::ExemptionUnderReview if self.has_sufficient_approvals() => {
                // Grant the exemption
                let risk_acceptance = self.risk_assessment
                    .as_ref()
                    .map(|(level, _)| format!("Risk level: {:?}", level));

                commands.push(PolicyCommand::GrantExemption(GrantExemption {
                    identity: super::create_root_command(),
                    policy_id: self.policy_id,
                    requester: self.requester.clone(),
                    approver: self.approvals
                        .last()
                        .map(|(approver, _)| approver.clone())
                        .unwrap_or_default(),
                    reason: self.risk_assessment
                        .as_ref()
                        .map(|(_, notes)| notes.clone())
                        .unwrap_or_default(),
                    justification: self.business_justification
                        .as_ref()
                        .map(|(just, _)| just.clone())
                        .unwrap_or_default(),
                    risk_acceptance,
                    valid_from: Utc::now(),
                    valid_until: self.expiry.unwrap_or_else(|| Utc::now() + Duration::days(30)),
                    conditions: self.exemption_conditions.clone(),
                }));
            }
            _ => {}
        }

        commands
    }

    fn is_complete(&self) -> bool {
        matches!(
            self.current_state,
            SagaState::ExemptionGranted | SagaState::ExemptionDenied | SagaState::ExemptionExpired
        )
    }

    fn has_failed(&self) -> bool {
        matches!(self.current_state, SagaState::ExemptionDenied)
    }

    fn metadata(&self) -> &SagaMetadata {
        &self.metadata
    }
}