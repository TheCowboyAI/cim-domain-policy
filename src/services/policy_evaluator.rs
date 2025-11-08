//! Policy evaluation service

use crate::aggregate::{Policy, PolicyExemption};
use crate::entities::{PolicyEvaluation, PolicyRule, RuleResult};
use crate::value_objects::*;
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EvaluationError {
    #[error("Policy not found: {0}")]
    PolicyNotFound(PolicyId),

    #[error("Policy not active: {0:?}")]
    PolicyNotActive(PolicyId),

    #[error("Evaluation context missing required field: {0}")]
    MissingContextField(String),

    #[error("Rule evaluation failed: {0}")]
    RuleEvaluationFailed(String),
}

/// Service for evaluating policies against contexts
pub struct PolicyEvaluator {
    exemptions: HashMap<PolicyId, Vec<PolicyExemption>>,
}

impl PolicyEvaluator {
    /// Create a new evaluator
    pub fn new() -> Self {
        Self {
            exemptions: HashMap::new(),
        }
    }

    /// Register exemptions for consideration during evaluation
    pub fn register_exemptions(&mut self, exemptions: Vec<PolicyExemption>) {
        for exemption in exemptions {
            if exemption.is_valid() {
                self.exemptions
                    .entry(exemption.policy_id)
                    .or_insert_with(Vec::new)
                    .push(exemption);
            }
        }
    }

    /// Evaluate a policy against a context
    pub fn evaluate(
        &self,
        policy: &Policy,
        context: &EvaluationContext,
    ) -> Result<PolicyEvaluation, EvaluationError> {
        // Check if policy is active
        if !policy.is_effective() {
            return Err(EvaluationError::PolicyNotActive(policy.id));
        }

        let start = std::time::Instant::now();
        let mut evaluation = PolicyEvaluation::new(policy.id, context.clone());

        // Check for exemptions first
        if let Some(exemptions) = self.exemptions.get(&policy.id) {
            for exemption in exemptions {
                if self.exemption_applies(exemption, context) {
                    evaluation.overall_result = ComplianceResult::CompliantWithExemption {
                        exemption_id: exemption.id,
                    };
                    evaluation.execution_time_ms = start.elapsed().as_millis() as u64;
                    return Ok(evaluation);
                }
            }
        }

        // Evaluate each rule
        for rule in &policy.rules {
            let result = self.evaluate_rule(rule, context)?;
            evaluation.add_rule_result(result);
        }

        evaluation.execution_time_ms = start.elapsed().as_millis() as u64;
        Ok(evaluation)
    }

    /// Evaluate multiple policies as a set
    pub fn evaluate_set(
        &self,
        policies: Vec<&Policy>,
        context: &EvaluationContext,
        composition: crate::aggregate::CompositionRule,
    ) -> Result<ComplianceResult, EvaluationError> {
        let results: Result<Vec<_>, _> = policies
            .into_iter()
            .map(|p| self.evaluate(p, context))
            .collect();

        let evaluations = results?;

        match composition {
            crate::aggregate::CompositionRule::All => {
                // All must be compliant
                let violations: Vec<_> = evaluations
                    .iter()
                    .flat_map(|e| e.violations())
                    .collect();

                if violations.is_empty() {
                    Ok(ComplianceResult::Compliant)
                } else {
                    Ok(ComplianceResult::NonCompliant { violations })
                }
            }
            crate::aggregate::CompositionRule::Any => {
                // At least one must be compliant
                if evaluations.iter().any(|e| e.is_compliant()) {
                    Ok(ComplianceResult::Compliant)
                } else {
                    let violations: Vec<_> = evaluations
                        .iter()
                        .flat_map(|e| e.violations())
                        .collect();
                    Ok(ComplianceResult::NonCompliant { violations })
                }
            }
            crate::aggregate::CompositionRule::Majority => {
                // More than half must be compliant
                let compliant = evaluations.iter().filter(|e| e.is_compliant()).count();
                let total = evaluations.len();

                if compliant > total / 2 {
                    Ok(ComplianceResult::Compliant)
                } else {
                    let violations: Vec<_> = evaluations
                        .iter()
                        .flat_map(|e| e.violations())
                        .collect();
                    Ok(ComplianceResult::NonCompliant { violations })
                }
            }
            crate::aggregate::CompositionRule::AtLeast(n) => {
                // At least N must be compliant
                let compliant = evaluations.iter().filter(|e| e.is_compliant()).count();

                if compliant >= n {
                    Ok(ComplianceResult::Compliant)
                } else {
                    let violations: Vec<_> = evaluations
                        .iter()
                        .flat_map(|e| e.violations())
                        .collect();
                    Ok(ComplianceResult::NonCompliant { violations })
                }
            }
        }
    }

    /// Check if an exemption applies to the context
    fn exemption_applies(&self, exemption: &PolicyExemption, context: &EvaluationContext) -> bool {
        // Check if exemption is valid
        if !exemption.is_valid() {
            return false;
        }

        // Check scope
        match &exemption.scope {
            crate::aggregate::ExemptionScope::Global => {
                // Global exemptions always apply
            }
            crate::aggregate::ExemptionScope::User(user) => {
                if context.requester.as_ref() != Some(user) {
                    return false;
                }
            }
            crate::aggregate::ExemptionScope::Resource(resource) => {
                if context.get_field("resource")
                    .and_then(|v| if let Value::String(s) = v { Some(s) } else { None })
                    != Some(resource)
                {
                    return false;
                }
            }
            _ => {
                // Other scopes need custom logic
                return false;
            }
        }

        // Check conditions
        for condition in &exemption.conditions {
            if !self.evaluate_condition(condition, context) {
                return false;
            }
        }

        true
    }

    /// Evaluate a single condition
    fn evaluate_condition(
        &self,
        condition: &crate::aggregate::ExemptionCondition,
        context: &EvaluationContext,
    ) -> bool {
        let field_value = match context.get_field(&condition.field) {
            Some(v) => v,
            None => return false,
        };

        match condition.operator {
            crate::aggregate::ConditionOperator::Equals => {
                field_value == &condition.value
            }
            crate::aggregate::ConditionOperator::NotEquals => {
                field_value != &condition.value
            }
            crate::aggregate::ConditionOperator::GreaterThan => {
                self.compare_values(field_value, &condition.value) == Some(std::cmp::Ordering::Greater)
            }
            crate::aggregate::ConditionOperator::LessThan => {
                self.compare_values(field_value, &condition.value) == Some(std::cmp::Ordering::Less)
            }
            crate::aggregate::ConditionOperator::Contains => {
                match (field_value, &condition.value) {
                    (Value::String(s), Value::String(needle)) => s.contains(needle.as_str()),
                    (Value::List(list), value) => list.contains(value),
                    _ => false,
                }
            }
            crate::aggregate::ConditionOperator::NotContains => {
                !self.evaluate_condition(
                    &crate::aggregate::ExemptionCondition {
                        field: condition.field.clone(),
                        operator: crate::aggregate::ConditionOperator::Contains,
                        value: condition.value.clone(),
                    },
                    context,
                )
            }
        }
    }

    /// Compare two values
    fn compare_values(&self, a: &Value, b: &Value) -> Option<std::cmp::Ordering> {
        match (a, b) {
            (Value::Integer(x), Value::Integer(y)) => Some(x.cmp(y)),
            (Value::Float(x), Value::Float(y)) => x.partial_cmp(y),
            (Value::String(x), Value::String(y)) => Some(x.cmp(y)),
            _ => None,
        }
    }

    /// Evaluate a single rule
    fn evaluate_rule(
        &self,
        rule: &PolicyRule,
        context: &EvaluationContext,
    ) -> Result<RuleResult, EvaluationError> {
        let passed = self.evaluate_expression(&rule.expression, context)?;

        let result = RuleResult {
            rule_id: rule.id,
            rule_name: rule.name.clone(),
            passed,
            message: if passed {
                format!("Rule '{}' passed", rule.name)
            } else {
                rule.error_message.clone()
                    .unwrap_or_else(|| format!("Rule '{}' failed", rule.name))
            },
            severity: rule.severity,
            actual_value: None,  // Could extract from context
            expected_value: None,  // Could extract from rule
        };

        Ok(result)
    }

    /// Evaluate a rule expression
    fn evaluate_expression(
        &self,
        expr: &RuleExpression,
        context: &EvaluationContext,
    ) -> Result<bool, EvaluationError> {
        match expr {
            RuleExpression::Equal { field, value } => {
                let field_value = context.get_field(field)
                    .ok_or_else(|| EvaluationError::MissingContextField(field.clone()))?;
                Ok(field_value == value)
            }
            RuleExpression::NotEqual { field, value } => {
                let field_value = context.get_field(field)
                    .ok_or_else(|| EvaluationError::MissingContextField(field.clone()))?;
                Ok(field_value != value)
            }
            RuleExpression::GreaterThan { field, value } => {
                let field_value = context.get_field(field)
                    .ok_or_else(|| EvaluationError::MissingContextField(field.clone()))?;
                Ok(self.compare_values(field_value, value) == Some(std::cmp::Ordering::Greater))
            }
            RuleExpression::GreaterThanOrEqual { field, value } => {
                let field_value = context.get_field(field)
                    .ok_or_else(|| EvaluationError::MissingContextField(field.clone()))?;
                Ok(matches!(
                    self.compare_values(field_value, value),
                    Some(std::cmp::Ordering::Greater) | Some(std::cmp::Ordering::Equal)
                ))
            }
            RuleExpression::LessThan { field, value } => {
                let field_value = context.get_field(field)
                    .ok_or_else(|| EvaluationError::MissingContextField(field.clone()))?;
                Ok(self.compare_values(field_value, value) == Some(std::cmp::Ordering::Less))
            }
            RuleExpression::LessThanOrEqual { field, value } => {
                let field_value = context.get_field(field)
                    .ok_or_else(|| EvaluationError::MissingContextField(field.clone()))?;
                Ok(matches!(
                    self.compare_values(field_value, value),
                    Some(std::cmp::Ordering::Less) | Some(std::cmp::Ordering::Equal)
                ))
            }
            RuleExpression::And(exprs) => {
                for expr in exprs {
                    if !self.evaluate_expression(expr, context)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            RuleExpression::Or(exprs) => {
                for expr in exprs {
                    if self.evaluate_expression(expr, context)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            RuleExpression::Not(expr) => {
                Ok(!self.evaluate_expression(expr, context)?)
            }
            RuleExpression::In { field, values } => {
                let field_value = context.get_field(field)
                    .ok_or_else(|| EvaluationError::MissingContextField(field.clone()))?;
                Ok(values.contains(field_value))
            }
            RuleExpression::NotIn { field, values } => {
                let field_value = context.get_field(field)
                    .ok_or_else(|| EvaluationError::MissingContextField(field.clone()))?;
                Ok(!values.contains(field_value))
            }
            RuleExpression::Contains { field, value } => {
                let field_value = context.get_field(field)
                    .ok_or_else(|| EvaluationError::MissingContextField(field.clone()))?;
                match (field_value, value) {
                    (Value::String(s), Value::String(needle)) => Ok(s.contains(needle.as_str())),
                    (Value::List(list), v) => Ok(list.contains(v)),
                    _ => Ok(false),
                }
            }
            RuleExpression::Matches { field, pattern } => {
                let field_value = context.get_field(field)
                    .ok_or_else(|| EvaluationError::MissingContextField(field.clone()))?;
                if let Value::String(s) = field_value {
                    // Simple pattern matching (could use regex)
                    Ok(s.contains(pattern))
                } else {
                    Ok(false)
                }
            }
            RuleExpression::StartsWith { field, prefix } => {
                let field_value = context.get_field(field)
                    .ok_or_else(|| EvaluationError::MissingContextField(field.clone()))?;
                if let Value::String(s) = field_value {
                    Ok(s.starts_with(prefix))
                } else {
                    Ok(false)
                }
            }
            RuleExpression::EndsWith { field, suffix } => {
                let field_value = context.get_field(field)
                    .ok_or_else(|| EvaluationError::MissingContextField(field.clone()))?;
                if let Value::String(s) = field_value {
                    Ok(s.ends_with(suffix))
                } else {
                    Ok(false)
                }
            }
            RuleExpression::Exists { field } => {
                Ok(context.get_field(field).is_some())
            }
            RuleExpression::NotExists { field } => {
                Ok(context.get_field(field).is_none())
            }
            RuleExpression::Custom { predicate, args: _ } => {
                // Custom predicates would be registered separately
                Err(EvaluationError::RuleEvaluationFailed(
                    format!("Custom predicate '{}' not implemented", predicate)
                ))
            }
        }
    }
}

impl Default for PolicyEvaluator {
    fn default() -> Self {
        Self::new()
    }
}