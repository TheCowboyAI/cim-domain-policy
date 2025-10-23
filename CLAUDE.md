# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 🔴 PRIME DIRECTIVE: CONTINUOUS LEARNING & BEST PRACTICES

**You are a constantly learning system. When you write your progress at natural breaks, you also:**

1. **ANALYZE** the instructions you were given and how well you performed them
2. **UPDATE** your "best practices" with new instructions to use in your memory going forward
3. **MAINTAIN** an ordered list of these best practices and shall not violate them when operating
4. **RECITE** these best practices when asked, and prove you are following them

### Current Best Practices (Updated Continuously):
1. **UUID v7 MANDATE**: Always use `Uuid::now_v7()` for time-ordered UUIDs, NEVER v4 or v5
2. **Event Sourcing Pattern**: All state changes through immutable events, no CRUD operations
3. **NATS JetStream for Testing**: Use real event stores for workflow validation, not artificial unit tests
4. **Progress Documentation**: Create and maintain PROGRESS_LOG.md at every significant checkpoint
5. **Domain Module Pattern**: Define boundaries → Event storm → Create aggregates → Design sagas → Implement services
6. **Saga State Machines**: Implement sagas as aggregates of aggregates with Markov chain transitions
7. **Test-First for Policies**: Create comprehensive TDD tests for PKI and authorization before implementation
8. **MessageIdentity Creation**: Use cim_domain's factory methods, not direct construction
9. **Compilation Before Proceeding**: Always fix compilation errors before moving to new features
10. **Context Awareness**: Check which repository/module you're in before making changes
11. **Display Trait Implementation**: Always implement Display for ID types used in error messages
12. **Import ConflictResolution**: When using ConflictResolution in entities, import from aggregate module
13. **Hash/Eq for Enums**: Implement Hash and Eq for Value types that will be used in HashSets/HashMaps
14. **Unused Imports Cleanup**: Remove unused imports and variables to reduce warnings
15. **NATS Subject Patterns**: Follow semantic naming: `organization.unit.entity.operation`

## 🔴 CRITICAL DIRECTIVE: PROGRESS LOGGING

**YOU MUST maintain a progress log at EVERY natural break point:**
- After completing each file modification
- Before switching between major components
- When encountering errors or design decisions
- At the end of each work session

Use TodoWrite tool to track:
1. What was just completed
2. What is currently being worked on
3. What needs to be done next
4. Any blockers or decisions needed

**NEVER proceed without updating the todo list when switching tasks**

## Policy Domain Specific Guidelines

### Domain Concepts
- **Policy**: A set of rules that must be followed
- **Rule**: A single constraint or requirement with RuleExpression
- **Evaluation**: Checking if context complies with a policy
- **Enforcement**: Ensuring policies are applied
- **Exemption**: Authorized exception to a policy with conditions
- **Saga**: Aggregate of aggregates with Markov chain state transitions

### PKI Policy Patterns
- Certificate issuance policies (min key size, allowed algorithms)
- Key rotation policies (age-based rules)
- Certificate chain validation (trust chain depth)
- YubiKey provisioning requirements
- NATS operator key specifications (Ed25519, offline storage)

### Authorization Policy Patterns
- Human approval workflows (manager/director chains)
- Delegation authorization (depth limits, expiry)
- Automated event-driven authorization
- Time-based access control
- Role-based authorization (RBAC)

### Testing Requirements
- Create comprehensive TDD tests for all policy types
- Test PKI policies: certificate issuance, key rotation, chain validation
- Test authorization: human approval, delegation, automated rules
- Test sagas: state transitions, Markov chain probabilities

### Service Design Patterns
- **PolicyEvaluator**: Evaluates policies against contexts with exemptions
- **ConflictResolver**: Detects and resolves policy conflicts
- **TemplateEngine**: Creates policies from predefined templates
- **Sagas**: Manage long-running workflows with state machines

## Development Workflow

1. **Define Domain Boundaries**: Event storm to identify events, commands, aggregates
2. **Create Value Objects**: PolicyId, RuleExpression, ComplianceResult, etc.
3. **Design Aggregates**: Policy, PolicySet, PolicyExemption
4. **Implement Sagas**: State machines with Markov chains
5. **Create Services**: Evaluator, Resolver, Template Engine
6. **Write TDD Tests**: Comprehensive coverage for all scenarios
7. **Fix Compilation**: Resolve all errors before proceeding
8. **Document Progress**: Update PROGRESS_LOG.md at each checkpoint