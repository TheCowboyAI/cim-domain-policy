//! Policy enforcement saga implementation

use super::*;
use crate::aggregate::CompositionRule;
use std::collections::HashMap;

/// Saga for managing policy enforcement workflow
pub struct PolicyEnforcementSaga {
    metadata: SagaMetadata,
    policy_ids: Vec<PolicyId>,
    current_state: SagaState,
    markov_chain: MarkovChain,
    evaluation_results: HashMap<PolicyId, ComplianceResult>,
    enforcement_decision: Option<EnforcementDecision>,
    composition_rule: CompositionRule,
}

#[derive(Debug, Clone, PartialEq)]
pub enum EnforcementDecision {
    Allow,
    AllowWithWarning,
    Block,
    Quarantine,
    Redirect,
}

impl PolicyEnforcementSaga {
    /// Create a new enforcement saga
    pub fn new(policy_ids: Vec<PolicyId>, initiated_by: String, composition: CompositionRule) -> Self {
        let mut markov_chain = MarkovChain::new();

        // Define state transitions for enforcement workflow
        markov_chain.add_transition(SagaState::Initiated, SagaState::Evaluating, 1.0);
        markov_chain.add_transition(SagaState::Evaluating, SagaState::Enforcing, 0.8);
        markov_chain.add_transition(SagaState::Evaluating, SagaState::Failed, 0.2);
        markov_chain.add_transition(SagaState::Enforcing, SagaState::Allowed, 0.6);
        markov_chain.add_transition(SagaState::Enforcing, SagaState::Blocked, 0.3);
        markov_chain.add_transition(SagaState::Enforcing, SagaState::Remediation, 0.1);

        // Set rewards
        markov_chain.set_state_reward(SagaState::Allowed, 50.0);
        markov_chain.set_state_reward(SagaState::Blocked, -10.0);
        markov_chain.set_state_reward(SagaState::Remediation, 20.0);
        markov_chain.set_state_reward(SagaState::Failed, -100.0);

        Self {
            metadata: SagaMetadata::new(initiated_by),
            policy_ids,
            current_state: SagaState::Initiated,
            markov_chain,
            evaluation_results: HashMap::new(),
            enforcement_decision: None,
            composition_rule: composition,
        }
    }

    /// Add evaluation result for a policy
    pub fn add_evaluation_result(&mut self, policy_id: PolicyId, result: ComplianceResult) {
        self.evaluation_results.insert(policy_id, result);
        self.metadata.update();

        // Check if all policies have been evaluated
        if self.evaluation_results.len() == self.policy_ids.len() {
            self.make_enforcement_decision();
        }
    }

    /// Make enforcement decision based on composition rule
    fn make_enforcement_decision(&mut self) {
        let compliant_count = self.evaluation_results.values()
            .filter(|r| r.is_compliant())
            .count();
        let total = self.evaluation_results.len();

        self.enforcement_decision = Some(match self.composition_rule {
            CompositionRule::All => {
                if compliant_count == total {
                    EnforcementDecision::Allow
                } else {
                    EnforcementDecision::Block
                }
            }
            CompositionRule::Any => {
                if compliant_count > 0 {
                    EnforcementDecision::Allow
                } else {
                    EnforcementDecision::Block
                }
            }
            CompositionRule::Majority => {
                if compliant_count > total / 2 {
                    EnforcementDecision::AllowWithWarning
                } else {
                    EnforcementDecision::Block
                }
            }
            CompositionRule::AtLeast(n) => {
                if compliant_count >= n {
                    EnforcementDecision::Allow
                } else {
                    EnforcementDecision::Block
                }
            }
        });

        // Update state based on decision
        self.current_state = match self.enforcement_decision {
            Some(EnforcementDecision::Allow) | Some(EnforcementDecision::AllowWithWarning) => {
                SagaState::Allowed
            }
            Some(EnforcementDecision::Block) | Some(EnforcementDecision::Quarantine) => {
                SagaState::Blocked
            }
            _ => SagaState::Enforcing,
        };
    }

    /// Get remediation steps for non-compliant policies
    pub fn get_remediation_steps(&self) -> Vec<String> {
        let mut steps = Vec::new();

        for result in self.evaluation_results.values() {
            if let ComplianceResult::NonCompliant { violations } = result {
                for violation in violations {
                    if let Some(remediation) = &violation.suggested_remediation {
                        steps.push(remediation.clone());
                    }
                }
            }
        }

        steps
    }
}

impl PolicySaga for PolicyEnforcementSaga {
    fn current_state(&self) -> SagaState {
        self.current_state.clone()
    }

    fn available_transitions(&self) -> Vec<StateTransition> {
        match self.current_state {
            SagaState::Initiated => vec![StateTransition::Start],
            SagaState::Evaluating => vec![StateTransition::Evaluate],
            SagaState::Enforcing => vec![
                StateTransition::Allow,
                StateTransition::Block,
                StateTransition::Remediate,
            ],
            SagaState::Blocked => vec![StateTransition::Remediate],
            _ => vec![],
        }
    }

    fn transition_probability(&self, from: &SagaState, to: &SagaState) -> f64 {
        self.markov_chain.transition_probability(from, to)
    }

    fn apply_event(&mut self, event: &PolicyEvent) -> Result<(), SagaError> {
        match event {
            PolicyEvent::PolicyEvaluated(e) => {
                if self.policy_ids.contains(&e.policy_id) {
                    self.add_evaluation_result(e.policy_id, e.result.clone());
                    if self.current_state == SagaState::Initiated {
                        self.current_state = SagaState::Evaluating;
                    }
                }
                Ok(())
            }
            PolicyEvent::PolicyViolationDetected(e) => {
                if self.policy_ids.contains(&e.policy_id) {
                    // Add violation to results
                    let result = ComplianceResult::NonCompliant {
                        violations: e.violations.clone(),
                    };
                    self.add_evaluation_result(e.policy_id, result);
                }
                Ok(())
            }
            PolicyEvent::PolicyCompliancePassed(e) => {
                if self.policy_ids.contains(&e.policy_id) {
                    self.add_evaluation_result(e.policy_id, ComplianceResult::Compliant);
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn get_commands(&self) -> Vec<PolicyCommand> {
        let mut commands = Vec::new();

        match self.current_state {
            SagaState::Initiated | SagaState::Evaluating => {
                // Generate evaluation commands for policies not yet evaluated
                for policy_id in &self.policy_ids {
                    if !self.evaluation_results.contains_key(policy_id) {
                        commands.push(PolicyCommand::EvaluatePolicy(EvaluatePolicy {
                            identity: super::create_root_command(),
                            policy_id: *policy_id,
                            context: EvaluationContext::new(),
                            requester: self.metadata.initiated_by.clone(),
                            purpose: "Enforcement evaluation".to_string(),
                        }));
                    }
                }
            }
            SagaState::Enforcing => {
                // Generate enforcement command based on decision
                if let Some(decision) = &self.enforcement_decision {
                    let action = match decision {
                        EnforcementDecision::Allow => EnforcementAction::Allow,
                        EnforcementDecision::AllowWithWarning => EnforcementAction::AllowWithWarning,
                        EnforcementDecision::Block => EnforcementAction::Block,
                        EnforcementDecision::Quarantine => EnforcementAction::Quarantine,
                        EnforcementDecision::Redirect => EnforcementAction::Redirect,
                    };

                    // Apply enforcement to first policy (could be extended)
                    if let Some(policy_id) = self.policy_ids.first() {
                        commands.push(PolicyCommand::EnforcePolicy(EnforcePolicy {
                            identity: super::create_root_command(),
                            policy_id: *policy_id,
                            target: PolicyTarget::Global,
                            context: HashMap::new(),
                            enforced_by: self.metadata.initiated_by.clone(),
                            enforcement_action: action,
                        }));
                    }
                }
            }
            _ => {}
        }

        commands
    }

    fn is_complete(&self) -> bool {
        matches!(
            self.current_state,
            SagaState::Allowed | SagaState::Blocked | SagaState::Completed
        )
    }

    fn has_failed(&self) -> bool {
        matches!(self.current_state, SagaState::Failed)
    }

    fn metadata(&self) -> &SagaMetadata {
        &self.metadata
    }
}