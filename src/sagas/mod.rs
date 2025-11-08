//! Sagas for policy domain - aggregates of aggregates with Markov chain state machines

use crate::commands::*;
use crate::events::*;
use crate::value_objects::*;
use cim_domain::{MessageIdentity, CorrelationId, CausationId};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use uuid::Uuid;

/// Helper function to create a root command message identity
pub fn create_root_command() -> MessageIdentity {
    let id = Uuid::now_v7();
    MessageIdentity {
        correlation_id: CorrelationId::Single(id),
        causation_id: CausationId(id),
        message_id: id,
    }
}

pub mod approval_saga;
pub mod enforcement_saga;
pub mod exemption_saga;
pub mod audit_saga;

pub use approval_saga::PolicyApprovalSaga;
pub use enforcement_saga::PolicyEnforcementSaga;
pub use exemption_saga::ExemptionWorkflowSaga;
pub use audit_saga::ComplianceAuditSaga;

/// Base trait for all sagas (aggregates of aggregates)
pub trait PolicySaga: Send + Sync {
    /// Get the current state in the Markov chain
    fn current_state(&self) -> SagaState;

    /// Get available state transitions from current state
    fn available_transitions(&self) -> Vec<StateTransition>;

    /// Calculate transition probability (Markov chain)
    fn transition_probability(&self, from: &SagaState, to: &SagaState) -> f64;

    /// Apply an event to update the saga state
    fn apply_event(&mut self, event: &PolicyEvent) -> Result<(), SagaError>;

    /// Get commands to emit based on current state
    fn get_commands(&self) -> Vec<PolicyCommand>;

    /// Check if saga is complete
    fn is_complete(&self) -> bool;

    /// Check if saga has failed
    fn has_failed(&self) -> bool;

    /// Get saga metadata
    fn metadata(&self) -> &SagaMetadata;
}

/// States in the saga state machine (Markov chain nodes)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SagaState {
    // Lifecycle states
    Initiated,
    InProgress,
    Waiting,
    Completed,
    Failed,
    Cancelled,

    // Policy-specific states
    Draft,
    UnderReview,
    Approved,
    Rejected,
    Active,
    Suspended,
    Archived,

    // Evaluation states
    Evaluating,
    Enforcing,
    Blocked,
    Allowed,
    Remediation,

    // Exemption states
    ExemptionRequested,
    ExemptionUnderReview,
    ExemptionGranted,
    ExemptionDenied,
    ExemptionExpired,

    // Audit states
    AuditScheduled,
    AuditInProgress,
    AuditComplete,
    NonCompliant,
    ComplianceVerified,
}

/// State transitions (Markov chain edges)
#[derive(Debug, Clone, PartialEq)]
pub enum StateTransition {
    // Lifecycle transitions
    Start,
    Progress,
    Complete,
    Fail,
    Cancel,
    Retry,

    // Policy transitions
    SubmitForReview,
    Approve,
    Reject,
    RequestChanges,
    Activate,
    Suspend,
    Archive,

    // Evaluation transitions
    Evaluate,
    Enforce,
    Allow,
    Block,
    Remediate,

    // Exemption transitions
    RequestExemption,
    ReviewExemption,
    GrantExemption,
    DenyExemption,
    ExpireExemption,

    // Audit transitions
    ScheduleAudit,
    StartAudit,
    CompleteAudit,
    VerifyCompliance,
    ReportViolation,
}

/// Metadata for saga tracking
#[derive(Debug, Clone)]
pub struct SagaMetadata {
    pub id: Uuid,
    pub correlation_id: Uuid,
    pub causation_id: Option<Uuid>,
    pub initiated_at: DateTime<Utc>,
    pub initiated_by: String,
    pub last_updated: DateTime<Utc>,
    pub version: u32,
    pub tags: HashMap<String, String>,
}

impl SagaMetadata {
    pub fn new(initiated_by: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::now_v7(),
            correlation_id: Uuid::now_v7(),
            causation_id: None,
            initiated_at: now,
            initiated_by,
            last_updated: now,
            version: 1,
            tags: HashMap::new(),
        }
    }

    pub fn with_causation(mut self, causation_id: Uuid) -> Self {
        self.causation_id = Some(causation_id);
        self
    }

    pub fn update(&mut self) {
        self.last_updated = Utc::now();
        self.version += 1;
    }
}

/// Errors that can occur in sagas
#[derive(Debug, thiserror::Error)]
pub enum SagaError {
    #[error("Invalid state transition from {0:?} to {1:?}")]
    InvalidTransition(SagaState, SagaState),

    #[error("Saga already completed")]
    AlreadyCompleted,

    #[error("Saga has failed: {0}")]
    SagaFailed(String),

    #[error("Missing required data: {0}")]
    MissingData(String),

    #[error("Timeout waiting for event")]
    Timeout,

    #[error("Concurrent modification detected")]
    ConcurrentModification,
}

/// Markov chain for state transitions
pub struct MarkovChain {
    transitions: HashMap<(SagaState, SagaState), f64>,
    state_rewards: HashMap<SagaState, f64>,
}

impl MarkovChain {
    pub fn new() -> Self {
        Self {
            transitions: HashMap::new(),
            state_rewards: HashMap::new(),
        }
    }

    /// Add a transition probability
    pub fn add_transition(&mut self, from: SagaState, to: SagaState, probability: f64) {
        self.transitions.insert((from, to), probability);
    }

    /// Set reward for reaching a state
    pub fn set_state_reward(&mut self, state: SagaState, reward: f64) {
        self.state_rewards.insert(state, reward);
    }

    /// Get transition probability
    pub fn transition_probability(&self, from: &SagaState, to: &SagaState) -> f64 {
        self.transitions
            .get(&(from.clone(), to.clone()))
            .copied()
            .unwrap_or(0.0)
    }

    /// Calculate expected value from a state
    pub fn expected_value(&self, from: &SagaState, horizon: usize) -> f64 {
        if horizon == 0 {
            return self.state_rewards.get(from).copied().unwrap_or(0.0);
        }

        let mut value = self.state_rewards.get(from).copied().unwrap_or(0.0);

        // Sum over all possible next states
        for (transition, probability) in &self.transitions {
            if &transition.0 == from {
                let future_value = self.expected_value(&transition.1, horizon - 1);
                value += probability * 0.9 * future_value; // 0.9 is discount factor
            }
        }

        value
    }

    /// Find optimal path using value iteration
    pub fn optimal_path(&self, from: &SagaState, to: &SagaState) -> Vec<SagaState> {
        // Simplified pathfinding - in production would use dynamic programming
        let mut path = vec![from.clone()];
        let mut current = from.clone();

        for _ in 0..10 {
            // Maximum path length
            if current == *to {
                break;
            }

            // Find best next state
            let mut best_next = None;
            let mut best_value = f64::NEG_INFINITY;

            for (transition, probability) in &self.transitions {
                if transition.0 == current {
                    let value = probability * self.expected_value(&transition.1, 5);
                    if value > best_value {
                        best_value = value;
                        best_next = Some(transition.1.clone());
                    }
                }
            }

            if let Some(next) = best_next {
                path.push(next.clone());
                current = next;
            } else {
                break;
            }
        }

        path
    }
}

/// Composite saga that coordinates multiple sub-sagas
pub struct CompositeSaga {
    metadata: SagaMetadata,
    sub_sagas: Vec<Box<dyn PolicySaga>>,
    current_state: SagaState,
    markov_chain: MarkovChain,
    completion_criteria: CompletionCriteria,
}

impl CompositeSaga {
    pub fn new(initiated_by: String, criteria: CompletionCriteria) -> Self {
        let mut markov_chain = MarkovChain::new();

        // Define composite state transitions
        markov_chain.add_transition(SagaState::Initiated, SagaState::InProgress, 1.0);
        markov_chain.add_transition(SagaState::InProgress, SagaState::Completed, 0.7);
        markov_chain.add_transition(SagaState::InProgress, SagaState::Failed, 0.2);
        markov_chain.add_transition(SagaState::InProgress, SagaState::Waiting, 0.1);
        markov_chain.add_transition(SagaState::Waiting, SagaState::InProgress, 0.8);
        markov_chain.add_transition(SagaState::Waiting, SagaState::Failed, 0.2);

        // Set state rewards
        markov_chain.set_state_reward(SagaState::Completed, 100.0);
        markov_chain.set_state_reward(SagaState::Failed, -50.0);
        markov_chain.set_state_reward(SagaState::InProgress, 10.0);

        Self {
            metadata: SagaMetadata::new(initiated_by),
            sub_sagas: Vec::new(),
            current_state: SagaState::Initiated,
            markov_chain,
            completion_criteria: criteria,
        }
    }

    /// Add a sub-saga to coordinate
    pub fn add_sub_saga(&mut self, saga: Box<dyn PolicySaga>) {
        self.sub_sagas.push(saga);
    }

    /// Check if all sub-sagas meet completion criteria
    pub fn check_completion(&self) -> bool {
        match self.completion_criteria {
            CompletionCriteria::All => {
                self.sub_sagas.iter().all(|s| s.is_complete())
            }
            CompletionCriteria::Any => {
                self.sub_sagas.iter().any(|s| s.is_complete())
            }
            CompletionCriteria::Majority => {
                let completed = self.sub_sagas.iter().filter(|s| s.is_complete()).count();
                completed > self.sub_sagas.len() / 2
            }
            CompletionCriteria::AtLeast(n) => {
                let completed = self.sub_sagas.iter().filter(|s| s.is_complete()).count();
                completed >= n
            }
        }
    }

    /// Coordinate sub-sagas based on events
    pub fn coordinate(&mut self, event: &PolicyEvent) -> Result<Vec<PolicyCommand>, SagaError> {
        let mut commands = Vec::new();

        // Apply event to all relevant sub-sagas
        for saga in &mut self.sub_sagas {
            if let Err(e) = saga.apply_event(event) {
                // Log error but continue with other sagas
                eprintln!("Sub-saga error: {:?}", e);
            }
            commands.extend(saga.get_commands());
        }

        // Update composite state based on sub-sagas
        if self.check_completion() {
            self.current_state = SagaState::Completed;
        } else if self.sub_sagas.iter().any(|s| s.has_failed()) {
            self.current_state = SagaState::Failed;
        } else if self.sub_sagas.iter().all(|s| s.current_state() == SagaState::Waiting) {
            self.current_state = SagaState::Waiting;
        } else {
            self.current_state = SagaState::InProgress;
        }

        self.metadata.update();
        Ok(commands)
    }

    /// Get optimal execution path
    pub fn optimal_execution_path(&self) -> Vec<SagaState> {
        self.markov_chain.optimal_path(&self.current_state, &SagaState::Completed)
    }
}

/// Criteria for composite saga completion
#[derive(Debug, Clone)]
pub enum CompletionCriteria {
    All,              // All sub-sagas must complete
    Any,              // Any sub-saga completion is sufficient
    Majority,         // Majority must complete
    AtLeast(usize),   // At least N must complete
}

/// Saga compensation for rollback
pub struct SagaCompensation {
    pub saga_id: Uuid,
    pub compensating_commands: Vec<PolicyCommand>,
    pub compensation_order: CompensationOrder,
}

#[derive(Debug, Clone)]
pub enum CompensationOrder {
    Reverse,    // Execute compensations in reverse order
    Forward,    // Execute compensations in forward order
    Parallel,   // Execute all compensations in parallel
}

impl SagaCompensation {
    pub fn new(saga_id: Uuid) -> Self {
        Self {
            saga_id,
            compensating_commands: Vec::new(),
            compensation_order: CompensationOrder::Reverse,
        }
    }

    pub fn add_compensation(&mut self, command: PolicyCommand) {
        self.compensating_commands.push(command);
    }

    pub fn execute(&self) -> Vec<PolicyCommand> {
        match self.compensation_order {
            CompensationOrder::Reverse => {
                let mut commands = self.compensating_commands.clone();
                commands.reverse();
                commands
            }
            CompensationOrder::Forward => self.compensating_commands.clone(),
            CompensationOrder::Parallel => self.compensating_commands.clone(),
        }
    }
}