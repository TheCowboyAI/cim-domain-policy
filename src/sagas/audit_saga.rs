//! Compliance audit saga implementation

use super::*;
use crate::commands::*;
use crate::events::*;
use crate::value_objects::*;
use std::collections::HashMap;

/// Saga for managing compliance audit workflow
pub struct ComplianceAuditSaga {
    metadata: SagaMetadata,
    policy_ids: Vec<PolicyId>,
    current_state: SagaState,
    markov_chain: MarkovChain,
    audit_results: HashMap<PolicyId, ComplianceResult>,
    findings: Vec<AuditFinding>,
    overall_compliance: Option<ComplianceStatus>,
}

#[derive(Debug, Clone)]
pub struct AuditFinding {
    pub policy_id: PolicyId,
    pub finding_type: FindingType,
    pub severity: Severity,
    pub description: String,
    pub evidence: Vec<String>,
    pub remediation_required: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FindingType {
    Violation,
    Weakness,
    Observation,
    Strength,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ComplianceStatus {
    FullyCompliant,
    PartiallyCompliant,
    NonCompliant,
    CriticalNonCompliance,
}

impl ComplianceAuditSaga {
    /// Create a new compliance audit saga
    pub fn new(policy_ids: Vec<PolicyId>, initiated_by: String) -> Self {
        let mut markov_chain = MarkovChain::new();

        // Define state transitions for audit workflow
        markov_chain.add_transition(SagaState::AuditScheduled, SagaState::AuditInProgress, 0.95);
        markov_chain.add_transition(SagaState::AuditScheduled, SagaState::Cancelled, 0.05);
        markov_chain.add_transition(SagaState::AuditInProgress, SagaState::AuditComplete, 0.8);
        markov_chain.add_transition(SagaState::AuditInProgress, SagaState::Failed, 0.2);
        markov_chain.add_transition(SagaState::AuditComplete, SagaState::ComplianceVerified, 0.6);
        markov_chain.add_transition(SagaState::AuditComplete, SagaState::NonCompliant, 0.4);

        // Set rewards
        markov_chain.set_state_reward(SagaState::ComplianceVerified, 100.0);
        markov_chain.set_state_reward(SagaState::NonCompliant, -50.0);
        markov_chain.set_state_reward(SagaState::Failed, -100.0);

        Self {
            metadata: SagaMetadata::new(initiated_by),
            policy_ids,
            current_state: SagaState::AuditScheduled,
            markov_chain,
            audit_results: HashMap::new(),
            findings: Vec::new(),
            overall_compliance: None,
        }
    }

    /// Add an audit result for a policy
    pub fn add_audit_result(&mut self, policy_id: PolicyId, result: ComplianceResult) {
        self.audit_results.insert(policy_id, result.clone());

        // Generate findings from result
        if let ComplianceResult::NonCompliant { violations } = result {
            for violation in violations {
                self.findings.push(AuditFinding {
                    policy_id,
                    finding_type: if violation.severity >= Severity::High {
                        FindingType::Violation
                    } else {
                        FindingType::Weakness
                    },
                    severity: violation.severity,
                    description: violation.details,
                    evidence: vec![violation.rule_description],
                    remediation_required: violation.severity >= Severity::Medium,
                });
            }
        }

        self.metadata.update();

        // Check if audit is complete
        if self.audit_results.len() == self.policy_ids.len() {
            self.determine_compliance_status();
        }
    }

    /// Determine overall compliance status
    fn determine_compliance_status(&mut self) {
        let total = self.audit_results.len();
        let compliant = self.audit_results.values()
            .filter(|r| r.is_compliant())
            .count();
        let critical_findings = self.findings.iter()
            .filter(|f| f.severity == Severity::Critical)
            .count();

        self.overall_compliance = Some(if critical_findings > 0 {
            ComplianceStatus::CriticalNonCompliance
        } else if compliant == total {
            ComplianceStatus::FullyCompliant
        } else if compliant > total / 2 {
            ComplianceStatus::PartiallyCompliant
        } else {
            ComplianceStatus::NonCompliant
        });

        // Update state based on compliance
        self.current_state = match self.overall_compliance {
            Some(ComplianceStatus::FullyCompliant) => SagaState::ComplianceVerified,
            Some(_) => SagaState::NonCompliant,
            None => SagaState::AuditComplete,
        };
    }

    /// Get high-priority remediation items
    pub fn get_priority_remediations(&self) -> Vec<String> {
        self.findings
            .iter()
            .filter(|f| f.remediation_required && f.severity >= Severity::High)
            .map(|f| f.description.clone())
            .collect()
    }

    /// Calculate compliance score (0-100)
    pub fn compliance_score(&self) -> f64 {
        if self.audit_results.is_empty() {
            return 0.0;
        }

        let total = self.audit_results.len() as f64;
        let compliant = self.audit_results.values()
            .filter(|r| r.is_compliant())
            .count() as f64;

        // Adjust for severity of findings
        let severity_penalty = self.findings.iter()
            .map(|f| match f.severity {
                Severity::Critical => 10.0,
                Severity::High => 5.0,
                Severity::Medium => 2.0,
                Severity::Low => 1.0,
                Severity::Info => 0.5,
            })
            .sum::<f64>();

        ((compliant / total * 100.0) - severity_penalty).max(0.0)
    }
}

impl PolicySaga for ComplianceAuditSaga {
    fn current_state(&self) -> SagaState {
        self.current_state.clone()
    }

    fn available_transitions(&self) -> Vec<StateTransition> {
        match self.current_state {
            SagaState::AuditScheduled => vec![StateTransition::StartAudit, StateTransition::Cancel],
            SagaState::AuditInProgress => vec![StateTransition::CompleteAudit],
            SagaState::AuditComplete => vec![StateTransition::VerifyCompliance, StateTransition::ReportViolation],
            SagaState::NonCompliant => vec![StateTransition::Remediate],
            _ => vec![],
        }
    }

    fn transition_probability(&self, from: &SagaState, to: &SagaState) -> f64 {
        self.markov_chain.transition_probability(from, to)
    }

    fn apply_event(&mut self, event: &PolicyEvent) -> Result<(), SagaError> {
        match event {
            PolicyEvent::PolicyEvaluated(e) if self.policy_ids.contains(&e.policy_id) => {
                self.add_audit_result(e.policy_id, e.result.clone());
                if self.current_state == SagaState::AuditScheduled {
                    self.current_state = SagaState::AuditInProgress;
                }
                Ok(())
            }
            PolicyEvent::PolicyViolationDetected(e) if self.policy_ids.contains(&e.policy_id) => {
                let result = ComplianceResult::NonCompliant {
                    violations: e.violations.clone(),
                };
                self.add_audit_result(e.policy_id, result);
                Ok(())
            }
            PolicyEvent::PolicyCompliancePassed(e) if self.policy_ids.contains(&e.policy_id) => {
                self.add_audit_result(e.policy_id, ComplianceResult::Compliant);
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn get_commands(&self) -> Vec<PolicyCommand> {
        let mut commands = Vec::new();

        match self.current_state {
            SagaState::AuditScheduled | SagaState::AuditInProgress => {
                // Generate evaluation commands for policies not yet audited
                for policy_id in &self.policy_ids {
                    if !self.audit_results.contains_key(policy_id) {
                        commands.push(PolicyCommand::EvaluatePolicy(EvaluatePolicy {
                            identity: super::create_root_command(),
                            policy_id: *policy_id,
                            context: EvaluationContext::new()
                                .with_field("audit_mode", true)
                                .with_field("audit_id", self.metadata.id.to_string()),
                            requester: self.metadata.initiated_by.clone(),
                            purpose: "Compliance audit".to_string(),
                        }));
                    }
                }
            }
            SagaState::NonCompliant => {
                // Generate remediation commands for critical findings
                for finding in &self.findings {
                    if finding.severity >= Severity::High && finding.remediation_required {
                        // In a real system, this would generate specific remediation commands
                        // For now, we'll create a suspension command for critical violations
                        if finding.severity == Severity::Critical {
                            commands.push(PolicyCommand::SuspendPolicy(SuspendPolicy {
                                identity: super::create_root_command(),
                                policy_id: finding.policy_id,
                                suspended_by: self.metadata.initiated_by.clone(),
                                reason: format!("Critical compliance violation: {}", finding.description),
                                expected_resume_date: Some(Utc::now() + chrono::Duration::days(7)),
                            }));
                        }
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
            SagaState::ComplianceVerified | SagaState::NonCompliant | SagaState::Cancelled
        )
    }

    fn has_failed(&self) -> bool {
        matches!(self.current_state, SagaState::Failed)
    }

    fn metadata(&self) -> &SagaMetadata {
        &self.metadata
    }
}