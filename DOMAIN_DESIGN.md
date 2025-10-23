# CIM Domain Policy - Domain Design

## 1. Domain Boundaries & Context

### What IS in the Policy Domain:
- **Policy Definition**: Rules, constraints, and requirements
- **Policy Lifecycle**: Creation, updates, versioning, deprecation
- **Policy Evaluation**: Checking if actions comply with policies
- **Policy Enforcement**: Ensuring policies are applied
- **Policy Composition**: Combining multiple policies
- **Policy Templates**: Reusable policy patterns
- **Compliance Standards**: Mapping to regulatory requirements
- **Policy Exceptions**: Temporary overrides with justification

### What is NOT in the Policy Domain:
- **Policy Execution**: The actual action (belongs to other domains)
- **Identity Management**: Who the policies apply to (Person domain)
- **Resource Management**: What policies apply to (other domains)
- **Audit Logs**: The actual logs (belongs to audit domain)

### Ubiquitous Language:
- **Policy**: A set of rules that govern behavior
- **Rule**: A single constraint or requirement
- **Constraint**: A limitation that must be respected
- **Requirement**: Something that must be present/true
- **Violation**: When a policy rule is not met
- **Exemption**: Authorized exception to a policy
- **Enforcement**: The act of applying a policy
- **Evaluation**: Checking compliance without enforcement
- **Policy Set**: A collection of related policies
- **Policy Target**: What/who a policy applies to
- **Policy Scope**: The boundaries of policy application

## 2. Event Storming Results

### Domain Events (Orange Stickies)

#### Policy Lifecycle Events:
- **PolicyDrafted**: Initial policy creation in draft state
- **PolicyReviewed**: Policy has been reviewed by authority
- **PolicyApproved**: Policy approved for use
- **PolicyActivated**: Policy is now in effect
- **PolicyUpdated**: Policy rules or parameters changed
- **PolicySuspended**: Temporarily disabled
- **PolicyRevoked**: Permanently disabled
- **PolicyVersioned**: New version created
- **PolicyArchived**: Moved to historical storage

#### Policy Evaluation Events:
- **PolicyEvaluationRequested**: Someone wants to check compliance
- **PolicyEvaluated**: Evaluation completed
- **PolicyViolationDetected**: Non-compliance found
- **PolicyCompliancePassed**: All rules satisfied
- **PolicyExceptionGranted**: Override approved
- **PolicyExceptionExpired**: Override time limit reached

#### Policy Enforcement Events:
- **PolicyEnforcementTriggered**: Enforcement action initiated
- **PolicyEnforcementCompleted**: Action taken
- **PolicyEnforcementFailed**: Could not enforce
- **PolicyEnforcementOverridden**: Manual override applied

#### Policy Composition Events:
- **PolicySetCreated**: Multiple policies grouped
- **PolicyAddedToSet**: Policy joined a set
- **PolicyRemovedFromSet**: Policy left a set
- **PolicySetActivated**: All policies in set activated
- **PolicyConflictDetected**: Policies have conflicting rules

### Commands (Blue Stickies)

#### Policy Management Commands:
- **CreatePolicy**: Draft a new policy
- **UpdatePolicy**: Modify policy rules
- **ApprovePolicy**: Authorize policy for use
- **ActivatePolicy**: Put policy into effect
- **SuspendPolicy**: Temporarily disable
- **RevokePolicy**: Permanently disable
- **VersionPolicy**: Create new version
- **ArchivePolicy**: Move to history

#### Policy Evaluation Commands:
- **EvaluatePolicy**: Check compliance
- **RequestPolicyExemption**: Ask for override
- **GrantPolicyExemption**: Approve override
- **RevokePolicyExemption**: Cancel override

#### Policy Enforcement Commands:
- **EnforcePolicy**: Apply policy rules
- **OverrideEnforcement**: Manual bypass
- **EscalateViolation**: Report non-compliance

#### Policy Composition Commands:
- **CreatePolicySet**: Group policies
- **AddPolicyToSet**: Include policy
- **RemovePolicyFromSet**: Exclude policy
- **ValidatePolicySet**: Check for conflicts

### External Events (Purple Stickies)
- **RegulatoryRequirementChanged**: External compliance update
- **AuditRequested**: Compliance audit triggered
- **SecurityIncidentReported**: May trigger policy changes

## 3. Aggregates

### Policy Aggregate (Root)
```rust
pub struct Policy {
    pub id: PolicyId,
    pub name: String,
    pub description: String,
    pub version: PolicyVersion,
    pub status: PolicyStatus,
    pub rules: Vec<PolicyRule>,
    pub target: PolicyTarget,
    pub scope: PolicyScope,
    pub enforcement_level: EnforcementLevel,
    pub effective_date: Option<DateTime<Utc>>,
    pub expiry_date: Option<DateTime<Utc>>,
    pub metadata: PolicyMetadata,
}
```

### PolicySet Aggregate
```rust
pub struct PolicySet {
    pub id: PolicySetId,
    pub name: String,
    pub policies: Vec<PolicyId>,
    pub composition_rules: CompositionRules,
    pub conflict_resolution: ConflictResolution,
    pub status: PolicySetStatus,
}
```

### PolicyExemption Aggregate
```rust
pub struct PolicyExemption {
    pub id: ExemptionId,
    pub policy_id: PolicyId,
    pub reason: ExemptionReason,
    pub approved_by: ApproverId,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub conditions: Vec<ExemptionCondition>,
}
```

## 4. Entities

### PolicyRule Entity
```rust
pub struct PolicyRule {
    pub id: RuleId,
    pub rule_type: RuleType,
    pub expression: RuleExpression,
    pub parameters: HashMap<String, Value>,
    pub severity: Severity,
    pub description: String,
}
```

### PolicyEvaluation Entity
```rust
pub struct PolicyEvaluation {
    pub id: EvaluationId,
    pub policy_id: PolicyId,
    pub evaluated_at: DateTime<Utc>,
    pub context: EvaluationContext,
    pub results: Vec<RuleResult>,
    pub overall_result: ComplianceResult,
}
```

## 5. Value Objects

### PolicyTarget
```rust
pub enum PolicyTarget {
    Global,                           // Applies to everything
    Organization(OrganizationId),     // Specific org
    OrganizationUnit(UnitId),        // Department/team
    Role(RoleId),                     // Specific role
    Resource(ResourceType),           // Type of resource
    Operation(OperationType),        // Specific operation
    Composite(Vec<PolicyTarget>),    // Multiple targets
}
```

### RuleExpression
```rust
pub enum RuleExpression {
    // Comparison rules
    Equal { field: String, value: Value },
    NotEqual { field: String, value: Value },
    GreaterThan { field: String, value: Value },
    LessThan { field: String, value: Value },

    // Logical operators
    And(Vec<RuleExpression>),
    Or(Vec<RuleExpression>),
    Not(Box<RuleExpression>),

    // Set operations
    In { field: String, values: Vec<Value> },
    Contains { field: String, value: Value },

    // Regular expressions
    Matches { field: String, pattern: String },

    // Custom predicates
    Custom { predicate: String, args: HashMap<String, Value> },
}
```

### EnforcementLevel
```rust
pub enum EnforcementLevel {
    Advisory,      // Just a recommendation
    Soft,         // Log violations but allow
    Hard,         // Block if violated
    Critical,     // Block and alert
}
```

### PolicyStatus
```rust
pub enum PolicyStatus {
    Draft,
    UnderReview,
    Approved,
    Active,
    Suspended,
    Revoked,
    Archived,
}
```

### ComplianceResult
```rust
pub enum ComplianceResult {
    Compliant,
    NonCompliant { violations: Vec<Violation> },
    CompliantWithExemption { exemption_id: ExemptionId },
    PartiallyCompliant { passed: usize, failed: usize },
}
```

## 6. Sagas (Long-Running Processes)

### PolicyApprovalSaga
```rust
pub struct PolicyApprovalSaga {
    pub policy_id: PolicyId,
    pub state: ApprovalState,
    pub required_approvers: Vec<ApproverId>,
    pub received_approvals: Vec<Approval>,
    pub started_at: DateTime<Utc>,
    pub deadline: Option<DateTime<Utc>>,
}
```
Flow: Draft → Review → Collect Approvals → Approve/Reject → Activate

### PolicyEnforcementSaga
```rust
pub struct PolicyEnforcementSaga {
    pub policy_id: PolicyId,
    pub target_id: TargetId,
    pub enforcement_actions: Vec<EnforcementAction>,
    pub state: EnforcementState,
}
```
Flow: Evaluate → Detect Violations → Determine Actions → Execute → Report

### ComplianceAuditSaga
```rust
pub struct ComplianceAuditSaga {
    pub audit_id: AuditId,
    pub policies: Vec<PolicyId>,
    pub targets: Vec<PolicyTarget>,
    pub findings: Vec<Finding>,
    pub state: AuditState,
}
```
Flow: Initialize → Collect Policies → Evaluate Each → Aggregate Results → Generate Report

## 7. Domain Services

### PolicyEvaluator
```rust
pub trait PolicyEvaluator {
    async fn evaluate(
        &self,
        policy: &Policy,
        context: &EvaluationContext,
    ) -> Result<PolicyEvaluation, EvaluationError>;

    async fn evaluate_set(
        &self,
        policy_set: &PolicySet,
        context: &EvaluationContext,
    ) -> Result<Vec<PolicyEvaluation>, EvaluationError>;
}
```

### PolicyConflictResolver
```rust
pub trait PolicyConflictResolver {
    fn detect_conflicts(
        &self,
        policies: &[Policy],
    ) -> Vec<PolicyConflict>;

    fn resolve_conflict(
        &self,
        conflict: &PolicyConflict,
        strategy: ResolutionStrategy,
    ) -> ResolvedPolicy;
}
```

### PolicyTemplateEngine
```rust
pub trait PolicyTemplateEngine {
    fn instantiate_template(
        &self,
        template: &PolicyTemplate,
        parameters: HashMap<String, Value>,
    ) -> Result<Policy, TemplateError>;
}
```

## 8. Integration Points

### For PKI (cim-keys):
- Certificate issuance policies
- Key generation constraints
- Algorithm requirements
- Validity period limits
- Extension requirements
- Revocation policies

### For Organizations:
- Role-based access policies
- Organizational hierarchy policies
- Delegation policies
- Approval workflows

### For Audit/Compliance:
- Compliance verification
- Policy violation reporting
- Audit trail requirements
- Retention policies

## 9. NATS Subject Patterns

```
policy.{policy_id}.created
policy.{policy_id}.updated
policy.{policy_id}.activated
policy.{policy_id}.evaluation.requested
policy.{policy_id}.evaluation.completed
policy.{policy_id}.violation.detected
policy.{policy_id}.enforcement.triggered
policy.set.{set_id}.created
policy.set.{set_id}.conflict.detected
policy.exemption.{exemption_id}.granted
policy.audit.{audit_id}.started
policy.audit.{audit_id}.completed
```

## 10. Example Policy for PKI

```rust
let cert_issuance_policy = Policy {
    id: PolicyId::new(),
    name: "Certificate Issuance Policy".to_string(),
    description: "Controls certificate generation requirements".to_string(),
    rules: vec![
        PolicyRule {
            rule_type: RuleType::Constraint,
            expression: RuleExpression::And(vec![
                RuleExpression::GreaterThan {
                    field: "key_size".to_string(),
                    value: Value::Integer(2048),
                },
                RuleExpression::In {
                    field: "algorithm".to_string(),
                    values: vec![
                        Value::String("RSA".to_string()),
                        Value::String("ECDSA".to_string()),
                    ],
                },
                RuleExpression::LessThan {
                    field: "validity_days".to_string(),
                    value: Value::Integer(365),
                },
            ]),
            severity: Severity::Critical,
            description: "Certificate must meet security requirements".to_string(),
        },
    ],
    target: PolicyTarget::Operation(OperationType::CertificateIssuance),
    enforcement_level: EnforcementLevel::Hard,
    ..Default::default()
};
```