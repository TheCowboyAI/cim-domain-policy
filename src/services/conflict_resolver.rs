//! Policy conflict resolution service

use crate::aggregate::{ConflictResolution, Policy};
use crate::entities::{PolicyConflict, ConflictType, PolicyRule};
use crate::value_objects::*;
use std::collections::{HashMap, HashSet};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum ConflictResolutionError {
    #[error("No policies provided for conflict resolution")]
    NoPolicies,

    #[error("Conflict resolution failed: {0}")]
    ResolutionFailed(String),

    #[error("Irreconcilable conflict: {0}")]
    IrreconcilableConflict(String),
}

/// Service for detecting and resolving policy conflicts
pub struct PolicyConflictResolver {
    resolution_strategy: ConflictResolution,
}

impl PolicyConflictResolver {
    /// Create a new resolver with a default strategy
    pub fn new(resolution_strategy: ConflictResolution) -> Self {
        Self { resolution_strategy }
    }

    /// Detect conflicts between policies
    pub fn detect_conflicts(&self, policies: &[Policy]) -> Vec<PolicyConflict> {
        let mut conflicts = Vec::new();

        // Check each pair of policies
        for i in 0..policies.len() {
            for j in i + 1..policies.len() {
                if let Some(conflict) = self.check_policy_pair(&policies[i], &policies[j]) {
                    conflicts.push(conflict);
                }
            }
        }

        conflicts
    }

    /// Check for conflicts between two policies
    fn check_policy_pair(&self, policy1: &Policy, policy2: &Policy) -> Option<PolicyConflict> {
        // Check if targets overlap
        if !self.targets_overlap(&policy1.target, &policy2.target) {
            return None;
        }

        // Check for rule conflicts
        for rule1 in &policy1.rules {
            for rule2 in &policy2.rules {
                if let Some(conflict_type) = self.check_rule_conflict(rule1, rule2) {
                    return Some(PolicyConflict {
                        id: Uuid::now_v7(),
                        policy_ids: vec![policy1.id, policy2.id],
                        conflict_type,
                        description: format!(
                            "Conflict between rule '{}' in policy '{}' and rule '{}' in policy '{}'",
                            rule1.name, policy1.name, rule2.name, policy2.name
                        ),
                        detected_at: chrono::Utc::now(),
                        resolution: Some(self.resolution_strategy),
                    });
                }
            }
        }

        None
    }

    /// Check if two targets overlap
    fn targets_overlap(&self, target1: &PolicyTarget, target2: &PolicyTarget) -> bool {
        match (target1, target2) {
            (PolicyTarget::Global, _) | (_, PolicyTarget::Global) => true,
            (PolicyTarget::Organization(id1), PolicyTarget::Organization(id2)) => id1 == id2,
            (PolicyTarget::OrganizationUnit(id1), PolicyTarget::OrganizationUnit(id2)) => id1 == id2,
            (PolicyTarget::Role(role1), PolicyTarget::Role(role2)) => role1 == role2,
            (PolicyTarget::Resource(res1), PolicyTarget::Resource(res2)) => res1 == res2,
            (PolicyTarget::Operation(op1), PolicyTarget::Operation(op2)) => op1 == op2,
            (PolicyTarget::Composite(targets1), PolicyTarget::Composite(targets2)) => {
                // Check if any targets in the composites overlap
                targets1.iter().any(|t1|
                    targets2.iter().any(|t2| self.targets_overlap(t1, t2))
                )
            }
            (PolicyTarget::Composite(targets), other) | (other, PolicyTarget::Composite(targets)) => {
                targets.iter().any(|t| self.targets_overlap(t, other))
            }
            _ => false,
        }
    }

    /// Check for conflicts between two rules
    fn check_rule_conflict(&self, rule1: &PolicyRule, rule2: &PolicyRule) -> Option<ConflictType> {
        // Check if rules operate on the same field
        let fields1 = self.extract_fields(&rule1.expression);
        let fields2 = self.extract_fields(&rule2.expression);

        let common_fields: HashSet<_> = fields1.intersection(&fields2).collect();

        if common_fields.is_empty() {
            return None;
        }

        // Check for contradictions
        if self.are_contradictory(&rule1.expression, &rule2.expression) {
            return Some(ConflictType::Contradiction);
        }

        // Check for overlaps with different requirements
        if self.are_overlapping(&rule1.expression, &rule2.expression) {
            return Some(ConflictType::Overlap);
        }

        // Check for impossible conditions
        if self.create_impossible_condition(&rule1.expression, &rule2.expression) {
            return Some(ConflictType::Impossible);
        }

        None
    }

    /// Extract field names from a rule expression
    fn extract_fields(&self, expr: &RuleExpression) -> HashSet<String> {
        let mut fields = HashSet::new();

        match expr {
            RuleExpression::Equal { field, .. } |
            RuleExpression::NotEqual { field, .. } |
            RuleExpression::GreaterThan { field, .. } |
            RuleExpression::GreaterThanOrEqual { field, .. } |
            RuleExpression::LessThan { field, .. } |
            RuleExpression::LessThanOrEqual { field, .. } |
            RuleExpression::In { field, .. } |
            RuleExpression::NotIn { field, .. } |
            RuleExpression::Contains { field, .. } |
            RuleExpression::Matches { field, .. } |
            RuleExpression::StartsWith { field, .. } |
            RuleExpression::EndsWith { field, .. } |
            RuleExpression::Exists { field } |
            RuleExpression::NotExists { field } => {
                fields.insert(field.clone());
            }
            RuleExpression::And(exprs) | RuleExpression::Or(exprs) => {
                for expr in exprs {
                    fields.extend(self.extract_fields(expr));
                }
            }
            RuleExpression::Not(expr) => {
                fields.extend(self.extract_fields(expr));
            }
            RuleExpression::Custom { args, .. } => {
                // Extract field names from args
                for key in args.keys() {
                    fields.insert(key.clone());
                }
            }
        }

        fields
    }

    /// Check if two expressions are contradictory
    fn are_contradictory(&self, expr1: &RuleExpression, expr2: &RuleExpression) -> bool {
        match (expr1, expr2) {
            // Direct contradictions
            (RuleExpression::Equal { field: f1, value: v1 },
             RuleExpression::Equal { field: f2, value: v2 }) => {
                f1 == f2 && v1 != v2
            }
            (RuleExpression::Equal { field: f1, value: v1 },
             RuleExpression::NotEqual { field: f2, value: v2 }) => {
                f1 == f2 && v1 == v2
            }
            (RuleExpression::GreaterThan { field: f1, value: v1 },
             RuleExpression::LessThanOrEqual { field: f2, value: v2 }) => {
                f1 == f2 && self.compare_values(v1, v2) != Some(std::cmp::Ordering::Less)
            }
            (RuleExpression::Exists { field: f1 },
             RuleExpression::NotExists { field: f2 }) => {
                f1 == f2
            }
            _ => false,
        }
    }

    /// Check if two expressions overlap with different requirements
    fn are_overlapping(&self, expr1: &RuleExpression, expr2: &RuleExpression) -> bool {
        match (expr1, expr2) {
            (RuleExpression::In { field: f1, values: v1 },
             RuleExpression::In { field: f2, values: v2 }) => {
                if f1 == f2 {
                    // Check if there are different values required
                    let set1: HashSet<_> = v1.iter().collect();
                    let set2: HashSet<_> = v2.iter().collect();
                    !set1.is_subset(&set2) && !set2.is_subset(&set1)
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    /// Check if two expressions create an impossible condition
    fn create_impossible_condition(&self, expr1: &RuleExpression, expr2: &RuleExpression) -> bool {
        match (expr1, expr2) {
            // Example: x > 10 AND x < 5 is impossible
            (RuleExpression::GreaterThan { field: f1, value: v1 },
             RuleExpression::LessThan { field: f2, value: v2 }) => {
                f1 == f2 && self.compare_values(v1, v2) != Some(std::cmp::Ordering::Less)
            }
            _ => false,
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

    /// Resolve conflicts between policies
    pub fn resolve_conflicts(
        &self,
        policies: Vec<Policy>,
        conflicts: Vec<PolicyConflict>,
    ) -> Result<Vec<Policy>, ConflictResolutionError> {
        if policies.is_empty() {
            return Err(ConflictResolutionError::NoPolicies);
        }

        if conflicts.is_empty() {
            // No conflicts to resolve
            return Ok(policies);
        }

        match self.resolution_strategy {
            ConflictResolution::MostRestrictive => {
                // Keep the most restrictive rules
                Ok(self.apply_most_restrictive(policies))
            }
            ConflictResolution::LeastRestrictive => {
                // Keep the least restrictive rules
                Ok(self.apply_least_restrictive(policies))
            }
            ConflictResolution::FirstWins => {
                // First policy takes precedence
                Ok(policies)
            }
            ConflictResolution::LastWins => {
                // Last policy takes precedence
                let mut reversed = policies;
                reversed.reverse();
                Ok(reversed)
            }
            ConflictResolution::FailOnConflict => {
                // Cannot resolve, return error
                Err(ConflictResolutionError::IrreconcilableConflict(
                    format!("Found {} unresolvable conflicts", conflicts.len())
                ))
            }
        }
    }

    /// Apply most restrictive resolution
    fn apply_most_restrictive(&self, policies: Vec<Policy>) -> Vec<Policy> {
        // Sort policies by enforcement level (most restrictive first)
        let mut sorted = policies;
        sorted.sort_by_key(|p| std::cmp::Reverse(p.enforcement_level));
        sorted
    }

    /// Apply least restrictive resolution
    fn apply_least_restrictive(&self, policies: Vec<Policy>) -> Vec<Policy> {
        // Sort policies by enforcement level (least restrictive first)
        let mut sorted = policies;
        sorted.sort_by_key(|p| p.enforcement_level);
        sorted
    }

    /// Merge policies to eliminate conflicts
    pub fn merge_policies(
        &self,
        policies: Vec<Policy>,
    ) -> Result<Policy, ConflictResolutionError> {
        if policies.is_empty() {
            return Err(ConflictResolutionError::NoPolicies);
        }

        let mut merged = policies[0].clone();
        merged.name = format!("Merged Policy Set ({})", policies.len());
        merged.description = "Automatically merged policy set".to_string();

        // Collect all rules from all policies
        let mut all_rules = Vec::new();
        for policy in &policies[1..] {
            all_rules.extend(policy.rules.clone());
        }

        // Deduplicate and resolve conflicts in rules
        for rule in all_rules {
            let conflicts_with_existing = merged.rules.iter().any(|existing|
                self.check_rule_conflict(existing, &rule).is_some()
            );

            if !conflicts_with_existing {
                merged.rules.push(rule);
            } else {
                // Apply resolution strategy
                match self.resolution_strategy {
                    ConflictResolution::MostRestrictive => {
                        // Keep rule with higher severity
                        if rule.severity > merged.rules[0].severity {
                            merged.rules.insert(0, rule);
                        }
                    }
                    ConflictResolution::LeastRestrictive => {
                        // Keep rule with lower severity
                        if rule.severity < merged.rules[0].severity {
                            merged.rules.insert(0, rule);
                        }
                    }
                    ConflictResolution::LastWins => {
                        // Replace with new rule
                        merged.rules.push(rule);
                    }
                    ConflictResolution::FirstWins => {
                        // Keep existing rules
                    }
                    ConflictResolution::FailOnConflict => {
                        return Err(ConflictResolutionError::IrreconcilableConflict(
                            "Cannot merge policies with conflicts".to_string()
                        ));
                    }
                }
            }
        }

        Ok(merged)
    }
}