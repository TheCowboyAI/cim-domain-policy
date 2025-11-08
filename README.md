# CIM Policy Domain

[![Version](https://img.shields.io/badge/version-0.8.0-blue.svg)](https://github.com/thecowboyai/cim-domain-policy)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Pure functional policy management domain with NATS event sourcing for CIM (Composable Information Machine) systems.

## Features

- **Pure Functional Architecture**: Category Theory / FRP-based event sourcing
- **NATS JetStream Integration**: Durable event streaming and storage
- **Production-Ready Service**: NATS-enabled policy-service binary
- **Easy Deployment**: Unified leaf node module for NixOS/nix-darwin
- **Security Hardened**: Built-in systemd security features
- **Rich Domain Model**: Policies, policy sets, exemptions, and rules
- **Clean Break from v0.7.x**: Pure functional only, no mutable API

## Quick Start

### For Leaf Nodes (Recommended)

Add to your NixOS or nix-darwin configuration:

```nix
{
  inputs.cim-domain-policy.url = "github:thecowboyai/cim-domain-policy/v0.8.0";

  outputs = { cim-domain-policy, ... }: {
    # NixOS leaf node
    nixosConfigurations.my-leaf = {
      modules = [
        cim-domain-policy.leafModule
        { services.policy-service.enable = true; }
      ];
    };

    # macOS leaf node (nix-darwin)
    darwinConfigurations.my-mac = {
      modules = [
        cim-domain-policy.leafModule
        { services.policy-service.enable = true; }
      ];
    };
  };
}
```

See [Leaf Node Deployment Guide](deployment/LEAF_NODE_DEPLOYMENT.md) for complete instructions.

### As a Library

Add to your `Cargo.toml`:

```toml
[dependencies]
cim-domain-policy = { git = "https://github.com/thecowboyai/cim-domain-policy", tag = "v0.8.0" }
```

## What's New in v0.8.0

### Pure Functional Event Sourcing

Policies are now reconstructed from immutable event history:

```rust
use cim_domain_policy::aggregate::{Policy, PolicySet, PolicyExemption};
use cim_domain_policy::events::PolicyEvent;

// Pure functional event application
let new_policy = policy.apply_event_pure(&event)?;

// Event sourcing repositories (3 aggregates)
let policy_repo = PolicyRepository::new(event_store);
let policy_set_repo = PolicySetRepository::new(event_store);
let exemption_repo = ExemptionRepository::new(event_store);

// Load aggregates from events
let policy = policy_repo.load(policy_id).await?;
let policy_set = policy_set_repo.load(set_id).await?;
let exemption = exemption_repo.load(exemption_id).await?;
```

### NATS Service Binary

Production-ready NATS-enabled service with 14 command handlers:

```bash
# Environment configuration
export NATS_URL="nats://localhost:4222"
export STREAM_NAME="POLICY_EVENTS"
export LOG_LEVEL="info"
export SNAPSHOT_FREQUENCY="100"

# Run the service
policy-service
```

**NATS Subject Patterns:**
- Commands: `policy.commands.{create|update|approve|activate|...}`
- Events: `events.policy.{aggregate_id}.{event_type}`

### Deployment Options

**Leaf Nodes** (Primary):
- Single module works on NixOS and nix-darwin
- Automatic platform detection
- See [LEAF_NODE_DEPLOYMENT.md](deployment/LEAF_NODE_DEPLOYMENT.md)

**Containers** (Alternative):
- NixOS systemd containers
- Proxmox LXC containers
- macOS launchd services

## Domain Concepts

### Policy Lifecycle

```
Draft → Approved → Active → Suspended/Revoked → Archived
                      ↓
                  (Exemptions granted during Active)
```

**Policy States:**
- `Draft` - Initial creation, editable
- `Approved` - Reviewed and approved, not yet active
- `Active` - Currently enforced
- `Suspended` - Temporarily not enforced
- `Revoked` - Permanently cancelled
- `Archived` - Soft-deleted

### Three Core Aggregates

**1. Policy** - Individual policy definitions:
```rust
Policy::new(
    id: PolicyId,
    name: String,
    description: String,
    policy_type: PolicyType,          // Regulatory, Operational, Security, etc.
    enforcement: PolicyEnforcement,    // Advisory, Recommended, Mandatory, Critical
    scope: PolicyScope,                // System, Organization, Department, etc.
)
```

**2. PolicySet** - Collections of related policies:
```rust
PolicySet::new(
    id: PolicySetId,
    name: String,
    description: String,
    policies: Vec<PolicyId>,
)
```

**3. PolicyExemption** - Temporary exceptions:
```rust
PolicyExemption::new(
    id: ExemptionId,
    policy_id: PolicyId,
    entity_id: Uuid,                   // Who/what is exempted
    reason: String,
    granted_by: String,
    expires_at: Option<DateTime<Utc>>,
)
```

### Policy Types

- **Regulatory** - Legal compliance requirements
- **Operational** - Business process guidelines
- **Security** - Security controls and requirements
- **Privacy** - Data protection and privacy rules
- **Compliance** - Compliance standards
- **Governance** - Governance frameworks
- **Safety** - Safety protocols
- **Quality** - Quality assurance standards
- **Environmental** - Environmental policies
- **Financial** - Financial controls
- **HR** - Human resources policies
- **IT** - Information technology policies

### Policy Enforcement Levels

- **Advisory** - Suggested best practices
- **Recommended** - Should be followed
- **Mandatory** - Must be followed
- **Critical** - Critical requirements with severe consequences

### Policy Scopes

- **System** - Entire CIM system
- **Organization** - Entire organization
- **Department** - Specific department
- **Project** - Specific project
- **Team** - Specific team
- **Individual** - Individual person

### Events

All state changes produce events (17 total):

**Policy Lifecycle (7 events):**
- `PolicyCreated` - New policy created
- `PolicyUpdated` - Policy modified
- `PolicyApproved` - Policy approved
- `PolicyActivated` - Policy activated with effective dates
- `PolicySuspended` - Policy temporarily suspended
- `PolicyRevoked` - Policy permanently revoked
- `PolicyArchived` - Policy archived

**Policy Sets (3 events):**
- `PolicySetCreated` - New policy set created
- `PolicyAddedToSet` - Policy added to set
- `PolicyRemovedFromSet` - Policy removed from set

**Policy Exemptions (3 events):**
- `PolicyExemptionGranted` - Exemption granted
- `PolicyExemptionRevoked` - Exemption revoked
- `PolicyExemptionExpired` - Exemption expired

**Policy Rules (4 events):**
- `PolicyRuleAdded` - Rule added to policy
- `PolicyRuleUpdated` - Rule modified
- `PolicyRuleRemoved` - Rule removed
- `PolicyRuleReordered` - Rule priority changed

## Architecture

### Hexagonal Architecture (Ports & Adapters)

```
┌─────────────────────────────────────┐
│         Domain Core                 │
│  ┌──────────────────────────────┐  │
│  │  Policy Aggregates (3)       │  │
│  │  - Policy                    │  │
│  │  - PolicySet                 │  │
│  │  - PolicyExemption           │  │
│  │  - Pure Functions            │  │
│  │  - Event Application         │  │
│  │  - Business Logic            │  │
│  └──────────────────────────────┘  │
│              ▼                      │
│  ┌──────────────────────────────┐  │
│  │  Ports (Interfaces)          │  │
│  │  - EventPublisher            │  │
│  │  - EventStore                │  │
│  └──────────────────────────────┘  │
└─────────────────────────────────────┘
                ▼
┌─────────────────────────────────────┐
│  Adapters (Infrastructure)          │
│  - NatsEventPublisher               │
│  - NatsEventStore                   │
│  - PolicyRepository                 │
│  - PolicySetRepository              │
│  - ExemptionRepository              │
└─────────────────────────────────────┘
```

### Event Sourcing Flow

```
Command → Service → Aggregate → Event → EventStore → JetStream
                        ▲                     │
                        └─────────────────────┘
                          Reconstruction
```

## Configuration

### Service Options

| Option | Default | Description |
|--------|---------|-------------|
| `natsUrl` | `nats://localhost:4222` | NATS server URL |
| `streamName` | `POLICY_EVENTS` | JetStream stream name |
| `logLevel` | `info` | Log level (trace/debug/info/warn/error) |
| `snapshotFrequency` | `100` | Events between snapshots |

### NATS Stream Configuration

Automatically created with:
- **Subjects**: `events.policy.>` (all policy events)
- **Retention**: 1 year
- **Storage**: File-based (durable)
- **Replicas**: 1 (configurable for HA)

## Development

### Build from Source

```bash
# Clone repository
git clone https://github.com/thecowboyai/cim-domain-policy
cd cim-domain-policy

# Enter development environment
nix develop

# Build library
cargo build

# Build service binary
cargo build --bin policy-service

# Run tests
cargo test

# Build with Nix
nix build .#policy-service
```

### Run Tests

```bash
cargo test
```

Current test coverage:
- ✅ Policy aggregate tests
- ✅ PolicySet aggregate tests
- ✅ PolicyExemption aggregate tests
- ✅ Event validation
- ✅ Pure event application
- ✅ Policy lifecycle workflows
- ✅ Exemption expiration handling

## Documentation

- [CHANGELOG.md](CHANGELOG.md) - Version history and changes
- [LEAF_NODE_DEPLOYMENT.md](deployment/LEAF_NODE_DEPLOYMENT.md) - Leaf node deployment guide
- [CONVERSION_COMPLETE.md](CONVERSION_COMPLETE.md) - v0.8.0 conversion details
- [CONVERSION_ASSESSMENT.md](CONVERSION_ASSESSMENT.md) - Pre-conversion analysis

## Migration from v0.7.x

### Breaking Change (Zero Impact)

**Removed**: `apply_event(&mut self)` method from all aggregates.

**Why**: This API was never used in production. The domain was designed for pure functional v0.8.0 from the start.

**Impact**: Zero real-world impact.

### New Pure Functional Architecture

v0.8.0 uses pure functions exclusively:

```rust
// Pure functional event application (ONLY option)
let policy = /* ... */;
let new_policy = policy.apply_event_pure(&event)?;

// Event sourcing with repositories
let repository = PolicyRepository::new(event_store);
let policy = repository.load(policy_id).await?;

// NATS service deployment
$ policy-service
```

## Production Deployment

### Leaf Node Cluster

For high availability, deploy on 3+ leaf nodes:

```nix
# Each leaf node
services.policy-service = {
  enable = true;
  natsUrl = "nats://localhost:4222";  # Local NATS
  streamName = "POLICY_EVENTS";       # Shared stream
  logLevel = "info";
  snapshotFrequency = 100;
};

# Configure NATS clustering
services.nats = {
  enable = true;
  jetstream = true;
  serverConfig.cluster = {
    name = "policy-cluster";
    routes = [
      "nats://leaf-1:6222"
      "nats://leaf-2:6222"
      "nats://leaf-3:6222"
    ];
  };
};
```

### Monitoring

**NixOS:**
```bash
systemctl status policy-service
journalctl -u policy-service -f
```

**macOS:**
```bash
tail -f /var/log/policy-service.log
```

**NATS:**
```bash
nats stream info POLICY_EVENTS
nats sub "events.policy.>"
```

## Performance

### Expected Characteristics

- **Memory**: Neutral (Rust move semantics optimize cloning)
- **CPU**: Neutral (compiler optimizations)
- **Latency**: Low (NATS is fast)
- **Throughput**: High (NATS enables horizontal scaling)
- **Concurrency**: Excellent (no locks needed with pure functions)

### Tuning

**Snapshot Frequency:**
- Lower (50-100): Faster loads, more memory
- Higher (200-1000): Slower loads, less memory
- Recommended: 100 for balanced performance

## Security

### NixOS Hardening

Automatic security features:
- `ProtectSystem=strict` - Read-only system
- `ProtectHome=true` - No home directory access
- `PrivateTmp=true` - Isolated /tmp
- `NoNewPrivileges=true` - No privilege escalation
- `RestrictAddressFamilies=AF_INET AF_INET6` - Network only

### Production Checklist

- [ ] Enable TLS for NATS connections
- [ ] Configure NATS authentication (JWT)
- [ ] Restrict firewall ports
- [ ] Use private network for clusters
- [ ] Enable monitoring and alerting
- [ ] Configure backup strategy
- [ ] Document disaster recovery
- [ ] Implement policy approval workflows
- [ ] Set up exemption review processes

## Examples

### Using the Library

```rust
use cim_domain_policy::prelude::*;

// Create a security policy
let policy = Policy::new(
    PolicyId::new(),
    "Password Policy".to_string(),
    "All passwords must be at least 12 characters".to_string(),
    PolicyType::Security,
    PolicyEnforcement::Mandatory,
    PolicyScope::Organization,
)?;

// Approve the policy
let policy = policy.approve()?;

// Activate with effective dates
let policy = policy.activate(
    Utc::now(),
    Some(Utc::now() + Duration::days(365)),
)?;

// Create a policy set
let mut policy_set = PolicySet::new(
    PolicySetId::new(),
    "Security Policies".to_string(),
    "Organization-wide security policies".to_string(),
)?;

// Add policy to set
policy_set.add_policy(policy.id())?;

// Grant an exemption
let exemption = PolicyExemption::new(
    ExemptionId::new(),
    policy.id(),
    entity_id,
    "Service account - no password required".to_string(),
    "security-admin".to_string(),
    Some(Utc::now() + Duration::days(90)),
)?;
```

### Using with NATS

```bash
# Subscribe to events
nats sub "events.policy.>"

# Create a policy
nats req policy.commands.create '{
  "policy_id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Data Retention Policy",
  "description": "All customer data must be retained for 7 years",
  "policy_type": "Regulatory",
  "enforcement": "Mandatory",
  "scope": "Organization"
}'

# Approve a policy
nats req policy.commands.approve '{
  "policy_id": "550e8400-e29b-41d4-a716-446655440000",
  "approved_by": "compliance-officer",
  "approval_date": "2025-11-08T10:00:00Z"
}'

# Grant an exemption
nats req policy.commands.grant_exemption '{
  "exemption_id": "650e8400-e29b-41d4-a716-446655440001",
  "policy_id": "550e8400-e29b-41d4-a716-446655440000",
  "entity_id": "750e8400-e29b-41d4-a716-446655440002",
  "reason": "Legacy system migration",
  "granted_by": "data-officer",
  "expires_at": "2026-02-08T10:00:00Z"
}'
```

## Command Reference

### Policy Commands (7)

1. `policy.commands.create` - Create new policy
2. `policy.commands.update` - Update policy details
3. `policy.commands.approve` - Approve policy
4. `policy.commands.activate` - Activate policy
5. `policy.commands.suspend` - Suspend policy
6. `policy.commands.revoke` - Revoke policy
7. `policy.commands.archive` - Archive policy

### Policy Rule Commands (3)

8. `policy.commands.add_rule` - Add rule to policy
9. `policy.commands.update_rule` - Update policy rule
10. `policy.commands.remove_rule` - Remove policy rule

### Policy Set Commands (2)

11. `policy.commands.create_set` - Create policy set
12. `policy.commands.add_to_set` - Add policy to set

### Exemption Commands (2)

13. `policy.commands.grant_exemption` - Grant exemption
14. `policy.commands.revoke_exemption` - Revoke exemption

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Support

- **Issues**: https://github.com/thecowboyai/cim-domain-policy/issues
- **Discussions**: https://github.com/thecowboyai/cim-domain-policy/discussions
- **Documentation**: https://github.com/thecowboyai/cim-domain-policy

## See Also

- [cim-domain](https://github.com/thecowboyai/cim-domain) - Core CIM domain framework
- [cim-domain-organization](https://github.com/thecowboyai/cim-domain-organization) - Organization domain
- [cim-domain-location](https://github.com/thecowboyai/cim-domain-location) - Location domain
- [NATS Documentation](https://docs.nats.io/) - NATS messaging system
- [NixOS](https://nixos.org/) - Declarative Linux distribution
- [nix-darwin](https://github.com/LnL7/nix-darwin) - Nix for macOS

---

**Version**: 0.8.0
**Architecture**: Pure Functional CT/FRP with NATS Event Sourcing
**Deployment**: Unified Leaf Node Module for NixOS/nix-darwin
**Status**: Production Ready ✅
