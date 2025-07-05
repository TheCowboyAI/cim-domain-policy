# CIM Domain: Policy

## Overview

The Policy domain manages rules, permissions, compliance requirements, and automated enforcement in the CIM system. It provides a flexible policy engine that can evaluate complex rules, enforce security constraints, and ensure compliance with organizational requirements.

## Key Features

- **Policy Definition**: Create and manage complex policy rules
- **Permission Management**: Fine-grained access control
- **Compliance Tracking**: Monitor and enforce compliance requirements
- **Automated Enforcement**: Real-time policy evaluation and enforcement
- **Audit Trail**: Complete history of policy decisions
- **Claims-Based Authorization**: Support for claims-based and attribute-based access control
- **Policy Templates**: Reusable policy patterns

## Architecture

### Domain Structure
- **Aggregates**: `Policy`, `PolicySet`, `Permission`
- **Value Objects**: `PolicyRule`, `PolicyEffect`, `PolicyCondition`, `ResourcePattern`
- **Commands**: `CreatePolicy`, `UpdatePolicy`, `AssignPolicy`, `EvaluateAccess`
- **Events**: `PolicyCreated`, `PolicyUpdated`, `PolicyAssigned`, `AccessGranted`, `AccessDenied`
- **Queries**: `GetPolicy`, `ListPolicies`, `EvaluatePermission`, `GetAuditLog`

### Integration Points
- **Identity Domain**: Apply policies to identities
- **Agent Domain**: Control agent permissions
- **Document Domain**: Document access policies
- **Workflow Domain**: Workflow authorization rules

## Usage Example

```rust
use cim_domain_policy::{
    commands::{CreatePolicy, AssignPolicy},
    value_objects::{PolicyRule, PolicyEffect, PolicyCondition},
};

// Create a document access policy
let create_policy = CreatePolicy {
    id: PolicyId::new(),
    name: "Document Read Policy".to_string(),
    description: "Allow reading documents in project folder".to_string(),
    rules: vec![
        PolicyRule {
            effect: PolicyEffect::Allow,
            actions: vec!["document:read".to_string()],
            resources: vec!["project/*".to_string()],
            conditions: vec![
                PolicyCondition::TimeRange {
                    start: "09:00".to_string(),
                    end: "17:00".to_string(),
                },
            ],
        },
    ],
};

// Assign policy to a user
let assign_policy = AssignPolicy {
    policy_id,
    principal_id: user_id,
    principal_type: PrincipalType::User,
};
```

## Testing

Run domain tests:
```bash
cargo test -p cim-domain-policy
```

## Documentation

- [User Stories](doc/user-stories.md) - Business requirements and use cases
- [API Documentation](doc/api.md) - Technical API reference

## Contributing

See the main project [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines. 