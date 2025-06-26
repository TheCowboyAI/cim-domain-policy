//! Rules component for policy domain
//!
//! Defines the actual rules and logic that make up a policy

use bevy_ecs::component::Component;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;
use std::collections::HashMap;

/// Rules component - defines the policy rules
#[derive(Component, Debug, Clone, Serialize, Deserialize)]
pub struct RulesComponent {
    /// Rule definitions (could be JSON, DSL, or structured data)
    pub rules: Value,
    
    /// Rule engine type (e.g., "json-logic", "rego", "custom")
    pub engine: RuleEngine,
    
    /// Rule version
    pub version: String,
    
    /// Metadata about the rules
    pub metadata: super::ComponentMetadata,
}

/// Supported rule engines
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RuleEngine {
    /// JSON Logic rules engine
    JsonLogic,
    
    /// Open Policy Agent (Rego)
    Rego,
    
    /// Custom rule engine
    Custom,
    
    /// Simple expression language
    SimpleExpression,
    
    /// Workflow-based rules
    Workflow,
}

/// Policy ID component
#[derive(Component, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PolicyId(pub Uuid);

/// Policy rule component - represents a single policy rule
#[derive(Component, Debug, Clone)]
pub struct PolicyRule {
    pub rule_id: Uuid,
    pub name: String,
    pub description: String,
    pub policy_type: crate::value_objects::PolicyType,
    pub scope: crate::value_objects::PolicyScope,
    pub conditions: Vec<PolicyCondition>,
    pub actions: Vec<PolicyAction>,
    pub priority: u32,
    pub enabled: bool,
}

/// Policy rules component - collection of rules
#[derive(Component, Debug, Clone)]
pub struct PolicyRules {
    pub conditions: Vec<PolicyCondition>,
    pub actions: Vec<PolicyAction>,
    pub exceptions: Vec<PolicyException>,
}

/// Policy metadata component
#[derive(Component, Debug, Clone)]
pub struct PolicyMetadata {
    pub name: String,
    pub description: String,
    pub version: u32,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub created_by: Uuid,
    pub tags: Vec<String>,
    pub expiration_date: Option<chrono::DateTime<chrono::Utc>>,
}

/// Policy condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCondition {
    pub condition_type: String,
    pub parameters: HashMap<String, serde_json::Value>,
    pub operator: ConditionOperator,
}

/// Policy action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyAction {
    pub action_type: String,
    pub parameters: HashMap<String, serde_json::Value>,
    pub priority: u32,
}

/// Policy exception
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyException {
    pub exception_type: String,
    pub conditions: Vec<PolicyCondition>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Condition operator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConditionOperator {
    Equals,
    NotEquals,
    GreaterThan,
    LessThan,
    Contains,
    NotContains,
    Matches,
    In,
    NotIn,
}

impl RulesComponent {
    /// Create a new rules component
    pub fn new(rules: Value, engine: RuleEngine, version: String) -> Self {
        Self {
            rules,
            engine,
            version,
            metadata: super::ComponentMetadata::default(),
        }
    }
    
    /// Create a JSON Logic rules component
    pub fn json_logic(rules: Value) -> Self {
        Self::new(rules, RuleEngine::JsonLogic, "1.0.0".to_string())
    }
    
    /// Create a Rego rules component
    pub fn rego(policy: String) -> Self {
        Self::new(
            Value::String(policy),
            RuleEngine::Rego,
            "1.0.0".to_string()
        )
    }
    
    /// Create a simple expression rules component
    pub fn simple_expression(expression: String) -> Self {
        Self::new(
            Value::String(expression),
            RuleEngine::SimpleExpression,
            "1.0.0".to_string()
        )
    }
    
    /// Update the rules
    pub fn update_rules(&mut self, new_rules: Value) {
        self.rules = new_rules;
        self.metadata.updated_at = chrono::Utc::now();
        self.metadata.version += 1;
    }
    
    /// Change the rule engine
    pub fn change_engine(&mut self, new_engine: RuleEngine) {
        self.engine = new_engine;
        self.metadata.updated_at = chrono::Utc::now();
        self.metadata.version += 1;
    }
}

impl Default for RulesComponent {
    fn default() -> Self {
        Self {
            rules: Value::Object(serde_json::Map::new()),
            engine: RuleEngine::JsonLogic,
            version: "1.0.0".to_string(),
            metadata: super::ComponentMetadata::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    
    #[test]
    fn test_create_rules_component() {
        let rules = json!({
            "and": [
                { "==": [{ "var": "role" }, "admin"] },
                { ">=": [{ "var": "level" }, 5] }
            ]
        });
        
        let component = RulesComponent::json_logic(rules.clone());
        
        assert_eq!(component.engine, RuleEngine::JsonLogic);
        assert_eq!(component.rules, rules);
        assert_eq!(component.version, "1.0.0");
    }
    
    #[test]
    fn test_update_rules() {
        let mut component = RulesComponent::default();
        let original_version = component.metadata.version;
        
        let new_rules = json!({
            "or": [
                { "==": [{ "var": "department" }, "IT"] },
                { "==": [{ "var": "department" }, "Security"] }
            ]
        });
        
        component.update_rules(new_rules.clone());
        
        assert_eq!(component.rules, new_rules);
        assert_eq!(component.metadata.version, original_version + 1);
    }
    
    #[test]
    fn test_rego_rules() {
        let policy = r#"
            package example
            
            allow {
                input.method == "GET"
                input.path == ["public", "data"]
            }
        "#.to_string();
        
        let component = RulesComponent::rego(policy.clone());
        
        assert_eq!(component.engine, RuleEngine::Rego);
        assert_eq!(component.rules, Value::String(policy));
    }
} 