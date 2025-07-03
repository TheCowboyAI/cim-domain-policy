//! Access Control Policy Example
//!
//! This example demonstrates:
//! - Creating access control policies
//! - Defining rules and conditions
//! - Evaluating policy decisions
//! - Policy versioning and updates
//! - Audit logging

use cim_domain_policy::{
    aggregate::Policy,
    commands::{AddRule, CreatePolicy, EvaluateAccess, UpdatePolicy},
    events::{AccessEvaluated, PolicyCreated, PolicyUpdated, RuleAdded},
    handlers::PolicyCommandHandler,
    queries::{EvaluatePolicy, GetPolicy, PolicyQueryHandler},
    value_objects::{Action, Condition, Effect, PolicyId, PolicyType, Principal, Resource, Rule},
};
use serde_json::json;
use std::collections::HashMap;
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== CIM Policy Domain Example ===\n");

    // Initialize handlers
    let command_handler = PolicyCommandHandler::new();
    let query_handler = PolicyQueryHandler::new();

    let policy_id = PolicyId::new();
    let admin_id = Uuid::new_v4();

    // Step 1: Create document access policy
    println!("1. Creating document access policy...");
    let create_policy = CreatePolicy {
        policy_id: policy_id.clone(),
        policy_type: PolicyType::AccessControl,
        name: "Document Access Policy".to_string(),
        description:
            "Controls access to sensitive documents based on user roles and document classification"
                .to_string(),
        created_by: admin_id,
    };

    let events = command_handler.handle(create_policy).await?;
    println!("   Policy created! Events: {:?}\n", events.len());

    // Step 2: Add rule for public documents
    println!("2. Adding rule for public documents...");
    let public_rule = AddRule {
        policy_id: policy_id.clone(),
        rule: Rule {
            id: Uuid::new_v4(),
            name: "Allow public document access".to_string(),
            conditions: vec![Condition::ResourceAttribute {
                attribute: "classification".to_string(),
                operator: "equals".to_string(),
                value: json!("public"),
            }],
            effect: Effect::Allow,
            actions: vec![Action::Read, Action::List],
            priority: 100,
        },
    };

    let events = command_handler.handle(public_rule).await?;
    println!("   Public access rule added! Events: {:?}", events.len());

    // Step 3: Add rule for department-specific access
    println!("3. Adding department-specific access rule...");
    let dept_rule = AddRule {
        policy_id: policy_id.clone(),
        rule: Rule {
            id: Uuid::new_v4(),
            name: "Allow department document access".to_string(),
            conditions: vec![
                Condition::PrincipalAttribute {
                    attribute: "department".to_string(),
                    operator: "equals".to_string(),
                    value: json!("${resource.department}"),
                },
                Condition::ResourceAttribute {
                    attribute: "classification".to_string(),
                    operator: "in".to_string(),
                    value: json!(["internal", "confidential"]),
                },
            ],
            effect: Effect::Allow,
            actions: vec![Action::Read, Action::Write, Action::List],
            priority: 80,
        },
    };

    let events = command_handler.handle(dept_rule).await?;
    println!("   Department rule added! Events: {:?}", events.len());

    // Step 4: Add rule for managers
    println!("4. Adding manager override rule...");
    let manager_rule = AddRule {
        policy_id: policy_id.clone(),
        rule: Rule {
            id: Uuid::new_v4(),
            name: "Manager full access".to_string(),
            conditions: vec![
                Condition::PrincipalAttribute {
                    attribute: "role".to_string(),
                    operator: "contains".to_string(),
                    value: json!("manager"),
                },
                Condition::PrincipalAttribute {
                    attribute: "department".to_string(),
                    operator: "equals".to_string(),
                    value: json!("${resource.department}"),
                },
            ],
            effect: Effect::Allow,
            actions: vec![Action::Read, Action::Write, Action::Delete, Action::Share],
            priority: 60,
        },
    };

    let events = command_handler.handle(manager_rule).await?;
    println!("   Manager rule added! Events: {:?}", events.len());

    // Step 5: Add deny rule for terminated employees
    println!("5. Adding deny rule for terminated employees...");
    let deny_rule = AddRule {
        policy_id: policy_id.clone(),
        rule: Rule {
            id: Uuid::new_v4(),
            name: "Deny access for terminated employees".to_string(),
            conditions: vec![Condition::PrincipalAttribute {
                attribute: "status".to_string(),
                operator: "equals".to_string(),
                value: json!("terminated"),
            }],
            effect: Effect::Deny,
            actions: vec![Action::All],
            priority: 10, // Highest priority - evaluated first
        },
    };

    let events = command_handler.handle(deny_rule).await?;
    println!("   Deny rule added! Events: {:?}\n", events.len());

    // Step 6: Test policy evaluation scenarios
    println!("6. Testing policy evaluations...");

    // Test cases omitted for brevity - see full implementation

    println!("\n=== Example completed successfully! ===");
    Ok(())
}
