//! Policy template engine for creating policies from templates

use crate::aggregate::Policy;
use crate::entities::{PolicyTemplate, TemplateParameter, ParameterType, PolicyRule};
use crate::value_objects::*;
use std::collections::HashMap;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum TemplateError {
    #[error("Template not found: {0}")]
    TemplateNotFound(String),

    #[error("Missing required parameter: {0}")]
    MissingParameter(String),

    #[error("Invalid parameter value for {0}: {1}")]
    InvalidParameterValue(String, String),

    #[error("Parameter validation failed: {0}")]
    ValidationFailed(String),

    #[error("Template instantiation failed: {0}")]
    InstantiationFailed(String),
}

/// Engine for creating policies from templates
pub struct PolicyTemplateEngine {
    templates: HashMap<Uuid, PolicyTemplate>,
    template_registry: HashMap<String, Uuid>,
}

impl PolicyTemplateEngine {
    /// Create a new template engine
    pub fn new() -> Self {
        let mut engine = Self {
            templates: HashMap::new(),
            template_registry: HashMap::new(),
        };

        // Register built-in templates
        engine.register_builtin_templates();
        engine
    }

    /// Register built-in templates
    fn register_builtin_templates(&mut self) {
        // PKI Certificate Template
        let mut pki_template = PolicyTemplate::new(
            "PKI Certificate Policy",
            "Standard template for certificate issuance policies"
        );
        pki_template.category = "PKI".to_string();
        pki_template.add_parameter(TemplateParameter {
            name: "min_key_size".to_string(),
            description: "Minimum key size in bits".to_string(),
            parameter_type: ParameterType::Integer,
            default_value: Some(Value::Integer(2048)),
            required: false,
            validation: Some(RuleExpression::GreaterThanOrEqual {
                field: "value".to_string(),
                value: Value::Integer(1024),
            }),
        });
        pki_template.add_parameter(TemplateParameter {
            name: "max_validity_days".to_string(),
            description: "Maximum certificate validity in days".to_string(),
            parameter_type: ParameterType::Integer,
            default_value: Some(Value::Integer(365)),
            required: false,
            validation: Some(RuleExpression::LessThanOrEqual {
                field: "value".to_string(),
                value: Value::Integer(825),
            }),
        });
        pki_template.add_parameter(TemplateParameter {
            name: "allowed_algorithms".to_string(),
            description: "List of allowed algorithms".to_string(),
            parameter_type: ParameterType::StringList,
            default_value: Some(Value::List(vec![
                Value::String("RSA".to_string()),
                Value::String("ECDSA".to_string()),
            ])),
            required: false,
            validation: None,
        });
        pki_template.tags = vec!["pki".to_string(), "certificate".to_string()];
        self.register_template(pki_template);

        // Authorization Template
        let mut auth_template = PolicyTemplate::new(
            "Authorization Policy",
            "Template for role-based access control"
        );
        auth_template.category = "Authorization".to_string();
        auth_template.add_parameter(TemplateParameter {
            name: "required_role".to_string(),
            description: "Role required for access".to_string(),
            parameter_type: ParameterType::String,
            default_value: None,
            required: true,
            validation: None,
        });
        auth_template.add_parameter(TemplateParameter {
            name: "min_role_level".to_string(),
            description: "Minimum role level required".to_string(),
            parameter_type: ParameterType::Integer,
            default_value: Some(Value::Integer(1)),
            required: false,
            validation: Some(RuleExpression::GreaterThanOrEqual {
                field: "value".to_string(),
                value: Value::Integer(0),
            }),
        });
        auth_template.tags = vec!["authorization".to_string(), "rbac".to_string()];
        self.register_template(auth_template);

        // Compliance Template
        let mut compliance_template = PolicyTemplate::new(
            "Compliance Policy",
            "Template for regulatory compliance requirements"
        );
        compliance_template.category = "Compliance".to_string();
        compliance_template.add_parameter(TemplateParameter {
            name: "compliance_standard".to_string(),
            description: "Compliance standard (e.g., PCI-DSS, HIPAA)".to_string(),
            parameter_type: ParameterType::String,
            default_value: None,
            required: true,
            validation: None,
        });
        compliance_template.add_parameter(TemplateParameter {
            name: "audit_frequency_days".to_string(),
            description: "Frequency of compliance audits in days".to_string(),
            parameter_type: ParameterType::Integer,
            default_value: Some(Value::Integer(90)),
            required: false,
            validation: Some(RuleExpression::GreaterThan {
                field: "value".to_string(),
                value: Value::Integer(0),
            }),
        });
        compliance_template.tags = vec!["compliance".to_string(), "audit".to_string()];
        self.register_template(compliance_template);
    }

    /// Register a template
    pub fn register_template(&mut self, template: PolicyTemplate) {
        self.template_registry.insert(template.name.clone(), template.id);
        self.templates.insert(template.id, template);
    }

    /// Get a template by name
    pub fn get_template(&self, name: &str) -> Option<&PolicyTemplate> {
        self.template_registry.get(name)
            .and_then(|id| self.templates.get(id))
    }

    /// List all available templates
    pub fn list_templates(&self) -> Vec<&PolicyTemplate> {
        self.templates.values().collect()
    }

    /// List templates by category
    pub fn list_templates_by_category(&self, category: &str) -> Vec<&PolicyTemplate> {
        self.templates.values()
            .filter(|t| t.category == category)
            .collect()
    }

    /// List templates by tag
    pub fn list_templates_by_tag(&self, tag: &str) -> Vec<&PolicyTemplate> {
        self.templates.values()
            .filter(|t| t.tags.contains(&tag.to_string()))
            .collect()
    }

    /// Instantiate a policy from a template
    pub fn instantiate(
        &self,
        template_name: &str,
        parameters: HashMap<String, Value>,
        policy_name: String,
        policy_description: String,
    ) -> Result<Policy, TemplateError> {
        // Get the template
        let template = self.get_template(template_name)
            .ok_or_else(|| TemplateError::TemplateNotFound(template_name.to_string()))?;

        // Validate and merge parameters
        let final_parameters = self.validate_and_merge_parameters(template, parameters)?;

        // Create the policy
        let mut policy = Policy::new(policy_name, policy_description);

        // Apply template rules with parameter substitution
        for base_rule in &template.base_rules {
            let rule = self.apply_parameters_to_rule(base_rule, &final_parameters)?;
            policy.add_rule(rule);
        }

        // Set default enforcement level from template
        policy.enforcement_level = template.default_enforcement;

        // Add template tags to policy
        policy.metadata.tags = template.tags.clone();

        Ok(policy)
    }

    /// Validate and merge parameters with defaults
    fn validate_and_merge_parameters(
        &self,
        template: &PolicyTemplate,
        provided: HashMap<String, Value>,
    ) -> Result<HashMap<String, Value>, TemplateError> {
        let mut final_parameters = HashMap::new();

        for param in &template.parameters {
            let value = if let Some(provided_value) = provided.get(&param.name) {
                // Validate type
                if !self.validate_parameter_type(provided_value, &param.parameter_type) {
                    return Err(TemplateError::InvalidParameterValue(
                        param.name.clone(),
                        format!("Expected type {:?}", param.parameter_type),
                    ));
                }

                // Validate against rule if present
                if let Some(validation) = &param.validation {
                    let _context = EvaluationContext::new()
                        .with_field("value", provided_value.clone());

                    // Simple validation check (in production would use PolicyEvaluator)
                    // For now, just check basic constraints
                    match validation {
                        RuleExpression::GreaterThanOrEqual { field, value } if field == "value" => {
                            if !self.compare_values(provided_value, value, std::cmp::Ordering::Greater)
                                && !self.compare_values(provided_value, value, std::cmp::Ordering::Equal) {
                                return Err(TemplateError::ValidationFailed(
                                    format!("{} must be >= {:?}", param.name, value)
                                ));
                            }
                        }
                        RuleExpression::LessThanOrEqual { field, value } if field == "value" => {
                            if !self.compare_values(provided_value, value, std::cmp::Ordering::Less)
                                && !self.compare_values(provided_value, value, std::cmp::Ordering::Equal) {
                                return Err(TemplateError::ValidationFailed(
                                    format!("{} must be <= {:?}", param.name, value)
                                ));
                            }
                        }
                        _ => {}
                    }
                }

                provided_value.clone()
            } else if let Some(default) = &param.default_value {
                default.clone()
            } else if param.required {
                return Err(TemplateError::MissingParameter(param.name.clone()));
            } else {
                continue;
            };

            final_parameters.insert(param.name.clone(), value);
        }

        Ok(final_parameters)
    }

    /// Validate parameter type
    fn validate_parameter_type(&self, value: &Value, expected_type: &ParameterType) -> bool {
        match (value, expected_type) {
            (Value::String(_), ParameterType::String) => true,
            (Value::Integer(_), ParameterType::Integer) => true,
            (Value::Float(_), ParameterType::Float) => true,
            (Value::Bool(_), ParameterType::Boolean) => true,
            (Value::List(items), ParameterType::StringList) => {
                items.iter().all(|v| matches!(v, Value::String(_)))
            }
            (Value::List(items), ParameterType::IntegerList) => {
                items.iter().all(|v| matches!(v, Value::Integer(_)))
            }
            (Value::DateTime(_), ParameterType::DateTime) => true,
            _ => false,
        }
    }

    /// Compare values for validation
    fn compare_values(&self, a: &Value, b: &Value, expected: std::cmp::Ordering) -> bool {
        match (a, b) {
            (Value::Integer(x), Value::Integer(y)) => x.cmp(y) == expected,
            (Value::Float(x), Value::Float(y)) => {
                x.partial_cmp(y).map_or(false, |ord| ord == expected)
            }
            _ => false,
        }
    }

    /// Apply parameters to a rule
    fn apply_parameters_to_rule(
        &self,
        rule: &PolicyRule,
        parameters: &HashMap<String, Value>,
    ) -> Result<PolicyRule, TemplateError> {
        let mut new_rule = rule.clone();

        // Apply parameter substitution to the expression
        new_rule.expression = self.substitute_expression(&rule.expression, parameters)?;

        // Apply parameter substitution to rule parameters
        for (key, value) in &rule.parameters {
            if let Value::String(s) = value {
                if s.starts_with("${") && s.ends_with('}') {
                    let param_name = &s[2..s.len() - 1];
                    if let Some(param_value) = parameters.get(param_name) {
                        new_rule.parameters.insert(key.clone(), param_value.clone());
                    }
                }
            }
        }

        Ok(new_rule)
    }

    /// Substitute parameters in an expression
    fn substitute_expression(
        &self,
        expr: &RuleExpression,
        parameters: &HashMap<String, Value>,
    ) -> Result<RuleExpression, TemplateError> {
        match expr {
            RuleExpression::Equal { field, value } => {
                Ok(RuleExpression::Equal {
                    field: field.clone(),
                    value: self.substitute_value(value, parameters)?,
                })
            }
            RuleExpression::GreaterThanOrEqual { field, value } => {
                Ok(RuleExpression::GreaterThanOrEqual {
                    field: field.clone(),
                    value: self.substitute_value(value, parameters)?,
                })
            }
            RuleExpression::LessThanOrEqual { field, value } => {
                Ok(RuleExpression::LessThanOrEqual {
                    field: field.clone(),
                    value: self.substitute_value(value, parameters)?,
                })
            }
            RuleExpression::In { field, values } => {
                Ok(RuleExpression::In {
                    field: field.clone(),
                    values: values.iter()
                        .map(|v| self.substitute_value(v, parameters))
                        .collect::<Result<Vec<_>, _>>()?,
                })
            }
            _ => Ok(expr.clone()),
        }
    }

    /// Substitute a value with parameters
    fn substitute_value(
        &self,
        value: &Value,
        parameters: &HashMap<String, Value>,
    ) -> Result<Value, TemplateError> {
        match value {
            Value::String(s) if s.starts_with("${") && s.ends_with('}') => {
                let param_name = &s[2..s.len() - 1];
                parameters.get(param_name)
                    .cloned()
                    .ok_or_else(|| TemplateError::MissingParameter(param_name.to_string()))
            }
            _ => Ok(value.clone()),
        }
    }
}

impl Default for PolicyTemplateEngine {
    fn default() -> Self {
        Self::new()
    }
}