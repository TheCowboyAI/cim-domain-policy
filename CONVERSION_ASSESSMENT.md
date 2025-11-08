# Policy Domain v0.8.0 Conversion Assessment

**Date**: 2025-11-07
**Current Version**: 0.7.8
**Target Version**: 0.8.0
**Assessment Status**: READY FOR CONVERSION

## Executive Summary

The Policy domain is ready for conversion to pure functional CT/FRP architecture with NATS JetStream event sourcing. The domain is comprehensive with **3 aggregates** and **17 event types**, making it one of the most complex CIM domains to convert.

### Complexity Assessment

**Aggregates**: 3 (Policy, PolicySet, PolicyExemption)
**Events**: 17 types
**Sagas**: 4 (approval, audit, enforcement, exemption)
**Services**: 3 (conflict resolver, policy evaluator, template engine)
**Domain Purity**: EXCELLENT ✅
**Estimated Effort**: **12-16 hours**

## Current Architecture (v0.7.8)

### Aggregate Structure

**1. Policy Aggregate** (`src/aggregate.rs`):
```rust
pub struct Policy {
    pub id: PolicyId,
    pub name: String,
    pub description: String,
    pub version: u32,
    pub status: PolicyStatus,
    pub rules: Vec<PolicyRule>,
    pub target: PolicyTarget,
    pub enforcement_level: EnforcementLevel,
    pub effective_date: Option<DateTime<Utc>>,
    pub expiry_date: Option<DateTime<Utc>>,
    pub parent_policy_id: Option<PolicyId>,
    pub metadata: PolicyMetadata,
}
```

**Mutable Methods**:
- `add_rule(&mut self, rule: PolicyRule)`
- `update_status(&mut self, status: PolicyStatus) -> Result<()>`
- `create_version(&self) -> Self` (already pure!)

**2. PolicySet Aggregate**:
```rust
pub struct PolicySet {
    pub id: PolicySetId,
    pub name: String,
    pub description: String,
    pub policies: Vec<PolicyId>,
    pub composition_rule: CompositionRule,
    pub conflict_resolution: ConflictResolution,
    pub status: PolicyStatus,
    pub metadata: PolicyMetadata,
}
```

**Mutable Methods**:
- `add_policy(&mut self, policy_id: PolicyId)`
- `remove_policy(&mut self, policy_id: &PolicyId)`

**3. PolicyExemption Aggregate**:
```rust
pub struct PolicyExemption {
    pub id: ExemptionId,
    pub policy_id: PolicyId,
    pub reason: String,
    pub justification: String,
    pub risk_acceptance: Option<String>,
    pub approved_by: String,
    pub approved_at: DateTime<Utc>,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub scope: ExemptionScope,
    pub conditions: Vec<ExemptionCondition>,
    pub status: ExemptionStatus,
}
```

**Mutable Methods**:
- `revoke(&mut self, revoked_by: String, reason: String)`

### Event Structure

The domain has **17 comprehensive events** across 4 categories:

**Lifecycle Events (7)**:
1. PolicyCreated
2. PolicyUpdated
3. PolicyApproved
4. PolicyActivated
5. PolicySuspended
6. PolicyRevoked
7. PolicyArchived

**Evaluation Events (3)**:
8. PolicyEvaluated
9. PolicyViolationDetected
10. PolicyCompliancePassed

**Exemption Events (3)**:
11. PolicyExemptionGranted
12. PolicyExemptionRevoked
13. PolicyExemptionExpired

**PolicySet Events (4)**:
14. PolicySetCreated
15. PolicyAddedToSet
16. PolicyRemovedFromSet
17. PolicyConflictDetected

All events implement `DomainEvent` trait with `event_type()` and `aggregate_id()`.

### Services

**1. PolicyEvaluator** (`src/services/policy_evaluator.rs`):
- Evaluates policies against context
- Returns compliance results
- Determines violations

**2. ConflictResolver** (`src/services/conflict_resolver.rs`):
- Resolves conflicts between policies
- Implements composition rules
- Handles conflict resolution strategies

**3. TemplateEngine** (`src/services/template_engine.rs`):
- Policy template management
- Rule template processing

### Sagas

**1. ApprovalSaga** (`src/sagas/approval_saga.rs`):
- Handles policy approval workflow
- Coordinates review process

**2. AuditSaga** (`src/sagas/audit_saga.rs`):
- Tracks policy changes
- Maintains audit trail

**3. EnforcementSaga** (`src/sagas/enforcement_saga.rs`):
- Enforces active policies
- Handles violations

**4. ExemptionSaga** (`src/sagas/exemption_saga.rs`):
- Manages exemption lifecycle
- Handles expiration and revocation

## Domain Purity Analysis

### ✅ EXCELLENT - No Violations Found

**What Policy Domain Owns**:
- ✅ Policy definitions and rules
- ✅ Policy lifecycle (draft, review, approved, active, suspended, revoked, archived)
- ✅ Policy sets and composition
- ✅ Policy exemptions
- ✅ Policy evaluation and compliance
- ✅ Conflict resolution strategies
- ✅ Policy metadata and versioning

**No Cross-Domain Dependencies**:
- ❌ No person-specific logic (uses generic identifiers)
- ❌ No organization-specific logic (policies can target any entity)
- ❌ No location-specific logic
- ✅ Pure policy management concepts only

**Boundary Analysis**:
- **PolicyTarget**: Generic enum (Global, Organization, User, Resource, Operation)
- **ExemptionScope**: Generic scoping (not tied to specific domains)
- **Policy Rules**: Generic rule definitions

**Result**: No domain refactoring needed! The policy domain is already pure. 🎉

## Conversion Requirements

### 1. Pure Functional Event Application

Add `apply_event_pure(&self) → Result<Self>` to all three aggregates:

**Policy Aggregate**:
```rust
pub fn apply_event_pure(&self, event: &PolicyEvent) -> Result<Self> {
    let mut new_aggregate = self.clone();

    match event {
        PolicyEvent::PolicyCreated(e) => {
            // Initialize policy from event
        }
        PolicyEvent::PolicyUpdated(e) => {
            // Apply updates
        }
        PolicyEvent::PolicyApproved(e) => {
            // Update status to Approved
        }
        PolicyEvent::PolicyActivated(e) => {
            // Activate policy with effective dates
        }
        PolicyEvent::PolicySuspended(e) => {
            // Suspend policy
        }
        PolicyEvent::PolicyRevoked(e) => {
            // Revoke policy
        }
        PolicyEvent::PolicyArchived(e) => {
            // Archive policy
        }
        _ => {} // Other events don't modify Policy aggregate
    }

    Ok(new_aggregate)
}
```

**PolicySet Aggregate**:
```rust
pub fn apply_event_pure(&self, event: &PolicyEvent) -> Result<Self> {
    let mut new_aggregate = self.clone();

    match event {
        PolicyEvent::PolicySetCreated(e) => {
            // Initialize policy set
        }
        PolicyEvent::PolicyAddedToSet(e) => {
            // Add policy to set
        }
        PolicyEvent::PolicyRemovedFromSet(e) => {
            // Remove policy from set
        }
        _ => {} // Other events don't modify PolicySet
    }

    Ok(new_aggregate)
}
```

**PolicyExemption Aggregate**:
```rust
pub fn apply_event_pure(&self, event: &PolicyEvent) -> Result<Self> {
    let mut new_aggregate = self.clone();

    match event {
        PolicyEvent::PolicyExemptionGranted(e) => {
            // Initialize exemption
        }
        PolicyEvent::PolicyExemptionRevoked(e) => {
            // Revoke exemption
        }
        PolicyEvent::PolicyExemptionExpired(e) => {
            // Mark as expired
        }
        _ => {}
    }

    Ok(new_aggregate)
}
```

### 2. NATS JetStream Infrastructure

**Event Store** (`src/infrastructure/nats_integration.rs`):
```rust
pub struct NatsEventStore {
    jetstream: jetstream::Context,
    stream: Stream,
    stream_name: String,
}

impl NatsEventStore {
    pub async fn append_event(&self, event: PolicyEvent) -> Result<()>;
    pub async fn load_events(&self, aggregate_id: Uuid) -> Result<Vec<PolicyEvent>>;
    pub fn event_subject(&self, event: &PolicyEvent) -> String;
}
```

**Subject Pattern**: `events.policy.{aggregate_id}.{event_type}`

Examples:
- `events.policy.{policy_id}.created`
- `events.policy.{policy_id}.approved`
- `events.policy.{set_id}.policy_added`
- `events.policy.{exemption_id}.granted`

**Stream Configuration**:
- Name: `POLICY_EVENTS`
- Subjects: `events.policy.>`
- Retention: 1 year
- Storage: File-based
- Replicas: 1 (configurable)

### 3. Event Sourcing Repository

**PolicyRepository** (`src/infrastructure/policy_repository.rs`):
```rust
pub struct PolicyRepository {
    event_store: Arc<NatsEventStore>,
    snapshot_frequency: u64,
}

impl PolicyRepository {
    pub async fn load(&self, policy_id: PolicyId) -> Result<Option<Policy>>;
    pub async fn save(&self, events: Vec<PolicyEvent>) -> Result<()>;
}
```

**PolicySetRepository** (`src/infrastructure/policy_set_repository.rs`):
```rust
pub struct PolicySetRepository {
    event_store: Arc<NatsEventStore>,
    snapshot_frequency: u64,
}

impl PolicySetRepository {
    pub async fn load(&self, set_id: PolicySetId) -> Result<Option<PolicySet>>;
    pub async fn save(&self, events: Vec<PolicyEvent>) -> Result<()>;
}
```

**ExemptionRepository** (`src/infrastructure/exemption_repository.rs`):
```rust
pub struct ExemptionRepository {
    event_store: Arc<NatsEventStore>,
    snapshot_frequency: u64,
}

impl ExemptionRepository {
    pub async fn load(&self, exemption_id: ExemptionId) -> Result<Option<PolicyExemption>>;
    pub async fn save(&self, events: Vec<PolicyEvent>) -> Result<()>;
}
```

### 4. Hexagonal Architecture (Ports/Adapters)

**Port** (`src/ports/event_publisher.rs`):
```rust
#[async_trait]
pub trait EventPublisher: Send + Sync {
    async fn publish(&self, event: &PolicyEvent) -> Result<()>;
    async fn publish_batch(&self, events: &[PolicyEvent]) -> Result<()>;
    async fn query_by_correlation(&self, correlation_id: Uuid) -> Result<Vec<PolicyEvent>>;
    async fn query_by_aggregate(&self, aggregate_id: Uuid) -> Result<Vec<PolicyEvent>>;
}
```

**Adapter** (`src/adapters/nats_event_publisher.rs`):
```rust
pub struct NatsEventPublisher {
    jetstream: jetstream::Context,
    stream_name: String,
}

#[async_trait]
impl EventPublisher for NatsEventPublisher {
    async fn publish(&self, event: &PolicyEvent) -> Result<()>;
    // ... implementations
}
```

### 5. Policy Service Binary

**Service** (`src/bin/policy-service.rs`):

NATS-enabled service handling **17 command types**:

**Policy Commands**:
- `policy.commands.create` → PolicyCreated
- `policy.commands.update` → PolicyUpdated
- `policy.commands.approve` → PolicyApproved
- `policy.commands.activate` → PolicyActivated
- `policy.commands.suspend` → PolicySuspended
- `policy.commands.revoke` → PolicyRevoked
- `policy.commands.archive` → PolicyArchived

**PolicySet Commands**:
- `policy.commands.create_set` → PolicySetCreated
- `policy.commands.add_to_set` → PolicyAddedToSet
- `policy.commands.remove_from_set` → PolicyRemovedFromSet

**Exemption Commands**:
- `policy.commands.grant_exemption` → PolicyExemptionGranted
- `policy.commands.revoke_exemption` → PolicyExemptionRevoked

**Evaluation Commands**:
- `policy.commands.evaluate` → PolicyEvaluated
- `policy.commands.check_compliance` → PolicyCompliancePassed or PolicyViolationDetected

**Environment Variables**:
- `NATS_URL` - NATS server (default: nats://localhost:4222)
- `STREAM_NAME` - JetStream stream (default: POLICY_EVENTS)
- `LOG_LEVEL` - Logging level (default: info)
- `SNAPSHOT_FREQUENCY` - Snapshot frequency (default: 100)

### 6. Deployment Support

**Leaf Node Module** (`deployment/nix/leaf.nix`):
- Unified NixOS/nix-darwin module
- Platform detection
- Service configuration

**Container Options**:
- NixOS systemd container (`deployment/nix/container.nix`)
- Proxmox LXC (`deployment/nix/lxc.nix`)
- macOS launchd (`deployment/nix/darwin.nix`)

**Flake Outputs**:
- `leafModule` - Primary deployment method
- `nixosModules.policy-service`
- `nixosConfigurations.policy-container`
- `nixosConfigurations.policy-lxc`
- `packages.policy-service`
- `darwinModules.policy-service`

## Backward Compatibility Strategy

**100% backward compatibility** maintained:

```rust
// Existing mutable methods wrapped
impl Policy {
    pub fn add_rule(&mut self, rule: PolicyRule) {
        *self = self.add_rule_pure(rule);
    }

    pub fn update_status(&mut self, status: PolicyStatus) -> Result<()> {
        *self = self.update_status_pure(status)?;
        Ok(())
    }
}

impl PolicySet {
    pub fn add_policy(&mut self, policy_id: PolicyId) {
        *self = self.add_policy_pure(policy_id);
    }

    pub fn remove_policy(&mut self, policy_id: &PolicyId) {
        *self = self.remove_policy_pure(policy_id);
    }
}

impl PolicyExemption {
    pub fn revoke(&mut self, revoked_by: impl Into<String>, reason: impl Into<String>) {
        *self = self.revoke_pure(revoked_by, reason);
    }
}
```

## Dependencies to Add

```toml
[dependencies]
# NATS messaging
async-nats = "0.38"
futures = "0.3"

# Existing dependencies already include:
# - tokio (async runtime)
# - serde/serde_json (serialization)
# - chrono (time handling)
# - tracing (logging)
```

## Conversion Checklist

### Phase 1: Pure Functional Architecture ⏳
- [ ] Add `apply_event_pure` to Policy aggregate
- [ ] Add `apply_event_pure` to PolicySet aggregate
- [ ] Add `apply_event_pure` to PolicyExemption aggregate
- [ ] Add backward-compatible mutable wrappers
- [ ] Update event handlers for all 17 event types
- [ ] Add unit tests for pure event application

### Phase 2: NATS Infrastructure ⏳
- [ ] Create `NatsEventStore` with subject patterns
- [ ] Create `PolicyRepository` with event sourcing
- [ ] Create `PolicySetRepository` with event sourcing
- [ ] Create `ExemptionRepository` with event sourcing
- [ ] Create `EventPublisher` port
- [ ] Create `NatsEventPublisher` adapter
- [ ] Update `Cargo.toml` with async-nats dependency
- [ ] Update `src/lib.rs` with new exports

### Phase 3: Service Binary ⏳
- [ ] Create `src/bin/policy-service.rs`
- [ ] Implement 14 command handlers
- [ ] Add request/reply pattern
- [ ] Add environment configuration
- [ ] Add graceful shutdown
- [ ] Add comprehensive logging
- [ ] Update `Cargo.toml` with `[[bin]]` entry

### Phase 4: Deployment Support ⏳
- [ ] Create `deployment/nix/leaf.nix`
- [ ] Create `deployment/nix/container.nix`
- [ ] Create `deployment/nix/lxc.nix`
- [ ] Create `deployment/nix/darwin.nix`
- [ ] Update `flake.nix` with outputs
- [ ] Create `deployment/LEAF_NODE_DEPLOYMENT.md`
- [ ] Create `deployment/CONTAINER_DEPLOYMENT.md`

### Phase 5: Documentation ⏳
- [ ] Create `CHANGELOG.md` for v0.8.0
- [ ] Create `CONVERSION_COMPLETE.md`
- [ ] Create `README.md`
- [ ] Update version to 0.8.0 in `Cargo.toml`
- [ ] Tag release `v0.8.0`

## Testing Strategy

### Unit Tests
- ✅ Existing aggregate tests (to be maintained)
- ⏳ Pure event application tests (new)
- ⏳ Event sourcing reconstruction tests (new)

### Integration Tests
- ⏳ NATS event store tests
- ⏳ Repository save/load tests
- ⏳ Event publishing tests

### Service Tests
- ⏳ Command handler tests
- ⏳ Request/reply pattern tests

## Estimated Timeline

**Total Effort**: 12-16 hours

| Phase | Duration | Complexity |
|-------|----------|------------|
| Analysis & Assessment | 1 hour | ✅ Complete |
| Pure Functional Architecture | 3-4 hours | Medium (3 aggregates, 17 events) |
| NATS Infrastructure | 3-4 hours | Medium (3 repositories) |
| Service Binary | 3-4 hours | Medium (14 command handlers) |
| Deployment Support | 2 hours | Low (pattern established) |
| Documentation | 2 hours | Low (pattern established) |

**Complexity Factors**:
- 3 aggregates to convert (vs 1 for location)
- 17 event types (vs 6 for location)
- 4 sagas to verify compatibility
- 3 services to verify compatibility
- But: Pattern is well-established from organization and location

## Risks and Mitigations

### Risk 1: Event Application Complexity
**Risk**: 17 event types across 3 aggregates is complex
**Mitigation**: Follow established pattern, implement incrementally, comprehensive tests

### Risk 2: Aggregate Relationship Management
**Risk**: PolicySet references Policy IDs, Exemption references Policy IDs
**Mitigation**: Treat as value types, don't load referenced aggregates in event application

### Risk 3: Saga Compatibility
**Risk**: 4 sagas may need updates for event sourcing
**Mitigation**: Sagas work with events, should be compatible out of the box

## Success Criteria

- ✅ All 17 event types have pure event application handlers
- ✅ All 3 aggregates support event sourcing reconstruction
- ✅ NATS event store persists and retrieves events correctly
- ✅ Policy service binary handles all command types
- ✅ All existing tests pass
- ✅ 100% backward compatibility maintained
- ✅ Unified leaf module deployment works
- ✅ Comprehensive documentation completed

## Comparison with Previous Conversions

| Aspect | Organization | Location | Policy |
|--------|-------------|----------|---------|
| Aggregates | 3 | 1 | 3 |
| Events | 16 | 6 | 17 |
| Sagas | 4 | 0 | 4 |
| Services | 3 | 3 | 3 |
| Domain Violations | 9 removed | 0 | 0 |
| Migration Effort | Medium | Zero | Zero |
| Estimated Hours | 18-24 | 6 | 12-16 |

**Policy is between Organization and Location in complexity**:
- More events than Location (17 vs 6)
- Same number of aggregates as Organization (3)
- Already pure boundaries like Location
- Established conversion pattern reduces risk

## Conclusion

The Policy domain is **READY FOR CONVERSION** to v0.8.0. The domain has excellent purity with no boundary violations. The conversion follows the well-established pattern from Organization and Location domains.

**Key Advantages**:
- ✅ Pure domain boundaries (no refactoring needed)
- ✅ Comprehensive event model already defined
- ✅ Well-structured aggregates
- ✅ Established conversion pattern

**Recommended Approach**:
1. Start with pure functional event application (3-4 hours)
2. Add NATS infrastructure following Location pattern (3-4 hours)
3. Create service binary with command handlers (3-4 hours)
4. Add deployment support (2 hours)
5. Complete documentation (2 hours)

**Expected Outcome**: Clean v0.8.0 release with pure functional CT/FRP architecture, NATS event sourcing, and unified leaf deployment, maintaining 100% backward compatibility.
