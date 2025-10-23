//! Policy approval saga implementation

use super::*;
use crate::commands::*;
use crate::events::*;
use crate::value_objects::*;

/// Saga for managing policy approval workflow
pub struct PolicyApprovalSaga {
    metadata: SagaMetadata,
    policy_id: PolicyId,
    current_state: SagaState,
    markov_chain: MarkovChain,
    approvals: Vec<(String, ApprovalLevel)>,
    rejection_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ApprovalLevel {
    Manager,
    Director,
    Security,
    Compliance,
}

impl PolicyApprovalSaga {
    /// Create a new approval saga
    pub fn new(policy_id: PolicyId, initiated_by: String) -> Self {
        let mut markov_chain = MarkovChain::new();

        // Define state transitions for approval workflow
        markov_chain.add_transition(SagaState::Draft, SagaState::UnderReview, 1.0);
        markov_chain.add_transition(SagaState::UnderReview, SagaState::Approved, 0.6);
        markov_chain.add_transition(SagaState::UnderReview, SagaState::Rejected, 0.3);
        markov_chain.add_transition(SagaState::UnderReview, SagaState::Draft, 0.1);
        markov_chain.add_transition(SagaState::Approved, SagaState::Active, 0.95);
        markov_chain.add_transition(SagaState::Approved, SagaState::Failed, 0.05);

        // Set rewards for reaching states
        markov_chain.set_state_reward(SagaState::Active, 100.0);
        markov_chain.set_state_reward(SagaState::Approved, 50.0);
        markov_chain.set_state_reward(SagaState::Rejected, -30.0);
        markov_chain.set_state_reward(SagaState::Failed, -50.0);

        Self {
            metadata: SagaMetadata::new(initiated_by),
            policy_id,
            current_state: SagaState::Draft,
            markov_chain,
            approvals: Vec::new(),
            rejection_reason: None,
        }
    }

    /// Add an approval to the saga
    pub fn add_approval(&mut self, approver: String, level: ApprovalLevel) {
        self.approvals.push((approver, level));
        self.metadata.update();
    }

    /// Check if sufficient approvals have been obtained
    pub fn has_sufficient_approvals(&self) -> bool {
        // Requires at least Manager AND Director approval
        let has_manager = self.approvals.iter().any(|(_, l)| *l == ApprovalLevel::Manager);
        let has_director = self.approvals.iter().any(|(_, l)| *l == ApprovalLevel::Director);
        has_manager && has_director
    }

    /// Set rejection reason
    pub fn reject(&mut self, reason: String) {
        self.rejection_reason = Some(reason);
        self.current_state = SagaState::Rejected;
        self.metadata.update();
    }
}

impl PolicySaga for PolicyApprovalSaga {
    fn current_state(&self) -> SagaState {
        self.current_state.clone()
    }

    fn available_transitions(&self) -> Vec<StateTransition> {
        match self.current_state {
            SagaState::Draft => vec![StateTransition::SubmitForReview],
            SagaState::UnderReview => vec![
                StateTransition::Approve,
                StateTransition::Reject,
                StateTransition::RequestChanges,
            ],
            SagaState::Approved => vec![StateTransition::Activate],
            SagaState::Rejected => vec![StateTransition::Retry],
            _ => vec![],
        }
    }

    fn transition_probability(&self, from: &SagaState, to: &SagaState) -> f64 {
        self.markov_chain.transition_probability(from, to)
    }

    fn apply_event(&mut self, event: &PolicyEvent) -> Result<(), SagaError> {
        match event {
            PolicyEvent::PolicyCreated(_) => {
                if self.current_state != SagaState::Draft {
                    return Err(SagaError::InvalidTransition(
                        self.current_state.clone(),
                        SagaState::UnderReview,
                    ));
                }
                self.current_state = SagaState::UnderReview;
                self.metadata.update();
                Ok(())
            }
            PolicyEvent::PolicyApproved(e) if e.policy_id == self.policy_id => {
                if self.current_state != SagaState::UnderReview {
                    return Err(SagaError::InvalidTransition(
                        self.current_state.clone(),
                        SagaState::Approved,
                    ));
                }
                self.current_state = SagaState::Approved;
                self.metadata.update();
                Ok(())
            }
            PolicyEvent::PolicyActivated(e) if e.policy_id == self.policy_id => {
                if self.current_state != SagaState::Approved {
                    return Err(SagaError::InvalidTransition(
                        self.current_state.clone(),
                        SagaState::Active,
                    ));
                }
                self.current_state = SagaState::Active;
                self.metadata.update();
                Ok(())
            }
            _ => Ok(()), // Ignore irrelevant events
        }
    }

    fn get_commands(&self) -> Vec<PolicyCommand> {
        let mut commands = Vec::new();

        match self.current_state {
            SagaState::UnderReview if self.has_sufficient_approvals() => {
                // Generate approval command
                commands.push(PolicyCommand::ApprovePolicy(ApprovePolicy {
                    identity: super::create_root_command(),
                    policy_id: self.policy_id,
                    approved_by: self.metadata.initiated_by.clone(),
                    approval_notes: Some("Approved by required stakeholders".to_string()),
                }));
            }
            SagaState::Approved => {
                // Generate activation command
                commands.push(PolicyCommand::ActivatePolicy(ActivatePolicy {
                    identity: super::create_root_command(),
                    policy_id: self.policy_id,
                    activated_by: self.metadata.initiated_by.clone(),
                    effective_immediately: true,
                    schedule_activation: None,
                }));
            }
            _ => {}
        }

        commands
    }

    fn is_complete(&self) -> bool {
        matches!(self.current_state, SagaState::Active | SagaState::Rejected)
    }

    fn has_failed(&self) -> bool {
        matches!(self.current_state, SagaState::Failed | SagaState::Rejected)
    }

    fn metadata(&self) -> &SagaMetadata {
        &self.metadata
    }
}