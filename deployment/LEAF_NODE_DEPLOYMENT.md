# Policy Service - Leaf Node Deployment

Quick guide for deploying the Policy Service on CIM leaf nodes (NixOS or nix-darwin).

## TL;DR

Add to your leaf node's `flake.nix`:

```nix
{
  inputs.cim-domain-policy.url = "github:thecowboyai/cim-domain-policy";

  outputs = { self, nixpkgs, cim-domain-policy, ... }: {
    # For NixOS leaf nodes
    nixosConfigurations.my-leaf = nixpkgs.lib.nixosSystem {
      modules = [
        cim-domain-policy.leafModule
        {
          services.policy-service = {
            enable = true;
            natsUrl = "nats://localhost:4222";  # Your leaf's NATS
          };
        }
      ];
    };

    # For nix-darwin leaf nodes (macOS)
    darwinConfigurations.my-mac-leaf = darwin.lib.darwinSystem {
      modules = [
        cim-domain-policy.leafModule
        {
          services.policy-service = {
            enable = true;
            natsUrl = "nats://localhost:4222";  # Your leaf's NATS
          };
        }
      ];
    };
  };
}
```

Then rebuild your system.

## What is a Leaf Node?

In CIM architecture, a **leaf node** is a server (NixOS or macOS) that:
- Runs a local NATS server
- Hosts one or more NATS-enabled services (like policy-service)
- Connects to a NATS cluster (3+ leaf nodes) for high availability
- Can connect to a super-cluster for global distribution

The policy-service runs on each leaf node and processes policy commands/events.

## Prerequisites

Your leaf node must have:
- NixOS or nix-darwin configured
- Nix flakes enabled
- NATS server running locally (usually `nats://localhost:4222`)
- Network connectivity to other leaf nodes (if clustered)

## Installation Methods

### Method 1: Flake Input (Recommended)

Add `cim-domain-policy` as a flake input:

**For NixOS Leaf Nodes:**

```nix
# flake.nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    cim-domain-policy.url = "github:thecowboyai/cim-domain-policy";
  };

  outputs = { self, nixpkgs, cim-domain-policy }: {
    nixosConfigurations.leaf-node-1 = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        ./hardware-configuration.nix
        cim-domain-policy.leafModule
        {
          services.policy-service = {
            enable = true;
            natsUrl = "nats://localhost:4222";
            streamName = "POLICY_EVENTS";
            logLevel = "info";
            snapshotFrequency = 100;
          };
        }
      ];
    };
  };
}
```

Then rebuild:
```bash
sudo nixos-rebuild switch --flake .#leaf-node-1
```

**For macOS Leaf Nodes (nix-darwin):**

```nix
# flake.nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    darwin.url = "github:LnL7/nix-darwin";
    cim-domain-policy.url = "github:thecowboyai/cim-domain-policy";
  };

  outputs = { self, nixpkgs, darwin, cim-domain-policy }: {
    darwinConfigurations.mac-leaf-1 = darwin.lib.darwinSystem {
      system = "aarch64-darwin";  # or x86_64-darwin
      modules = [
        cim-domain-policy.leafModule
        {
          services.policy-service = {
            enable = true;
            natsUrl = "nats://localhost:4222";
            streamName = "POLICY_EVENTS";
            logLevel = "info";
          };
        }
      ];
    };
  };
}
```

Then rebuild:
```bash
darwin-rebuild switch --flake .#mac-leaf-1
```

### Method 2: Direct Import (No Flakes)

If not using flakes, you can import directly:

**NixOS:**
```nix
# configuration.nix
{
  imports = [
    (builtins.fetchGit {
      url = "https://github.com/thecowboyai/cim-domain-policy";
      ref = "main";
    } + "/deployment/nix/leaf.nix")
  ];

  services.policy-service = {
    enable = true;
    natsUrl = "nats://localhost:4222";
  };
}
```

**nix-darwin:**
```nix
# darwin-configuration.nix
{
  imports = [
    (builtins.fetchGit {
      url = "https://github.com/thecowboyai/cim-domain-policy";
      ref = "main";
    } + "/deployment/nix/leaf.nix")
  ];

  services.policy-service = {
    enable = true;
    natsUrl = "nats://localhost:4222";
  };
}
```

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enable` | bool | `false` | Enable the Policy Service |
| `natsUrl` | string | `"nats://localhost:4222"` | NATS server URL on this leaf |
| `streamName` | string | `"POLICY_EVENTS"` | JetStream stream name (must be consistent across cluster) |
| `logLevel` | enum | `"info"` | Log level: `trace`, `debug`, `info`, `warn`, `error` |
| `snapshotFrequency` | int | `100` | Events between snapshots (100-1000 recommended) |

### NixOS-Only Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `user` | string | `"policy-service"` | Service user account |
| `group` | string | `"policy-service"` | Service group |

## NATS Configuration for Leaf Nodes

### Single Leaf Node (Development)

For testing with a single leaf node:

```nix
services.policy-service = {
  enable = true;
  natsUrl = "nats://localhost:4222";  # Local NATS only
};
```

Your local NATS doesn't need clustering configuration.

### Clustered Leaf Nodes (Production)

For production with multiple leaf nodes:

1. **Configure NATS clustering** on each leaf:
   ```nix
   # Each leaf node's NATS configuration
   services.nats = {
     enable = true;
     jetstream = true;
     serverConfig = {
       cluster = {
         name = "policy-cluster";
         routes = [
           "nats://leaf-1.internal:6222"
           "nats://leaf-2.internal:6222"
           "nats://leaf-3.internal:6222"
         ];
       };
     };
   };
   ```

2. **Configure policy-service** to use local NATS:
   ```nix
   services.policy-service = {
     enable = true;
     natsUrl = "nats://localhost:4222";  # Still local!
     streamName = "POLICY_EVENTS";       # Same on all leafs
   };
   ```

The policy-service always connects to the local NATS server. The NATS servers handle cluster communication.

## Complete Examples

### Production NixOS Leaf Node

```nix
# flake.nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    cim-domain-policy.url = "github:thecowboyai/cim-domain-policy/v0.8.0";
  };

  outputs = { self, nixpkgs, cim-domain-policy }: {
    nixosConfigurations.prod-leaf-1 = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        ./hardware-configuration.nix
        cim-domain-policy.leafModule
        {
          # Hostname and networking
          networking.hostName = "prod-leaf-1";
          networking.firewall.allowedTCPPorts = [ 4222 6222 ];  # NATS client + cluster

          # NATS server with clustering
          services.nats = {
            enable = true;
            jetstream = true;
            serverConfig = {
              cluster = {
                name = "prod-policy-cluster";
                port = 6222;
                routes = [
                  "nats://prod-leaf-1.internal:6222"
                  "nats://prod-leaf-2.internal:6222"
                  "nats://prod-leaf-3.internal:6222"
                ];
              };
            };
          };

          # Policy service
          services.policy-service = {
            enable = true;
            natsUrl = "nats://localhost:4222";
            streamName = "POLICY_EVENTS";
            logLevel = "info";
            snapshotFrequency = 100;
          };

          # Monitoring
          services.prometheus.exporters.node.enable = true;
        }
      ];
    };
  };
}
```

### Development macOS Leaf Node

```nix
# flake.nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    darwin.url = "github:LnL7/nix-darwin";
    cim-domain-policy.url = "github:thecowboyai/cim-domain-policy";
  };

  outputs = { self, nixpkgs, darwin, cim-domain-policy }: {
    darwinConfigurations.dev-mac = darwin.lib.darwinSystem {
      system = "aarch64-darwin";
      modules = [
        cim-domain-policy.leafModule
        {
          # Local NATS server
          services.nats = {
            enable = true;
            jetstream = true;
          };

          # Policy service with debug logging
          services.policy-service = {
            enable = true;
            natsUrl = "nats://localhost:4222";
            streamName = "POLICY_EVENTS";
            logLevel = "debug";
            snapshotFrequency = 50;  # More frequent snapshots for dev
          };
        }
      ];
    };
  };
}
```

## Managing the Service

### NixOS

```bash
# Check service status
systemctl status policy-service

# View logs
journalctl -u policy-service -f

# Restart service
systemctl restart policy-service

# Stop service
systemctl stop policy-service
```

### macOS (nix-darwin)

```bash
# Check service status
launchctl list | grep policy-service

# View logs
tail -f /var/log/policy-service.log
tail -f /var/log/policy-service.error.log

# Restart service
launchctl kickstart -k system/org.nixos.policy-service

# Stop service
launchctl stop org.nixos.policy-service
```

## Testing Your Installation

### Verify Service is Running

**NixOS:**
```bash
systemctl is-active policy-service
```

**macOS:**
```bash
launchctl list | grep policy-service
```

### Test NATS Communication

Install NATS CLI:
```bash
nix-shell -p natscli
```

Subscribe to policy events:
```bash
nats sub "events.policy.>"
```

In another terminal, send a test command:
```bash
nats req policy.commands.create '{
  "policy_id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Data Retention Policy",
  "description": "All customer data must be retained for 7 years",
  "policy_type": "Retention",
  "enforcement": "Mandatory",
  "scope": "Organization"
}'
```

You should see:
1. The command request logged in the service logs
2. An event published to `events.policy.{id}.created`

### Verify JetStream Stream

```bash
nats stream info POLICY_EVENTS
nats stream subjects POLICY_EVENTS
```

## Troubleshooting

### Service Won't Start

**Check NATS is running:**
```bash
# NixOS
systemctl status nats

# macOS
launchctl list | grep nats
```

**Check connectivity:**
```bash
nats server ping
```

**Check logs:**
```bash
# NixOS
journalctl -u policy-service -n 50

# macOS
tail -n 50 /var/log/policy-service.error.log
```

### Events Not Persisting

**Check JetStream is enabled:**
```bash
nats server info
# Should show JetStream: enabled
```

**Check stream exists:**
```bash
nats stream ls
# Should show POLICY_EVENTS
```

**Check stream configuration:**
```bash
nats stream info POLICY_EVENTS
```

### High Memory Usage

Reduce snapshot frequency:
```nix
services.policy-service.snapshotFrequency = 50;  # More frequent snapshots
```

### Slow Aggregate Loads

Increase snapshot frequency:
```nix
services.policy-service.snapshotFrequency = 200;  # Less frequent snapshots
```

## Upgrading

### Update to Latest Version

```bash
# Update flake inputs
nix flake update cim-domain-policy

# Rebuild
sudo nixos-rebuild switch --flake .  # NixOS
darwin-rebuild switch --flake .      # macOS
```

### Pin to Specific Version

```nix
inputs.cim-domain-policy.url = "github:thecowboyai/cim-domain-policy/v0.8.0";
```

## Multi-Leaf Deployment

For a complete CIM cluster with 3 leaf nodes:

**Leaf 1:**
```nix
networking.hostName = "leaf-1";
services.nats.serverConfig.cluster.routes = [
  "nats://leaf-1.internal:6222"
  "nats://leaf-2.internal:6222"
  "nats://leaf-3.internal:6222"
];
services.policy-service.enable = true;
```

**Leaf 2:**
```nix
networking.hostName = "leaf-2";
services.nats.serverConfig.cluster.routes = [
  "nats://leaf-1.internal:6222"
  "nats://leaf-2.internal:6222"
  "nats://leaf-3.internal:6222"
];
services.policy-service.enable = true;
```

**Leaf 3:**
```nix
networking.hostName = "leaf-3";
services.nats.serverConfig.cluster.routes = [
  "nats://leaf-1.internal:6222"
  "nats://leaf-2.internal:6222"
  "nats://leaf-3.internal:6222"
];
services.policy-service.enable = true;
```

All three will share the same `POLICY_EVENTS` stream across the cluster.

## Security Considerations

### Production Checklist

- [ ] Enable TLS for NATS connections
- [ ] Configure NATS authentication (JWT or credentials)
- [ ] Restrict firewall ports (4222, 6222)
- [ ] Use private network for cluster routes
- [ ] Enable systemd security hardening (automatic on NixOS)
- [ ] Set up log rotation
- [ ] Configure monitoring and alerting
- [ ] Document disaster recovery procedures

### TLS Configuration

```nix
services.nats = {
  enable = true;
  jetstream = true;
  serverConfig = {
    tls = {
      cert_file = "/path/to/cert.pem";
      key_file = "/path/to/key.pem";
      ca_file = "/path/to/ca.pem";
    };
  };
};

services.policy-service = {
  enable = true;
  natsUrl = "tls://localhost:4222";  # Use TLS
};
```

## See Also

- [Container Deployment Guide](./CONTAINER_DEPLOYMENT.md) - Alternative deployment methods
- [Policy Domain README](../README.md) - Domain documentation
- [CHANGELOG](../CHANGELOG.md) - Version history
- [NATS Documentation](https://docs.nats.io/) - NATS reference
- [NixOS Manual](https://nixos.org/manual/nixos/stable/) - NixOS configuration
- [nix-darwin](https://github.com/LnL7/nix-darwin) - macOS Nix system management

## Support

- **Issues**: https://github.com/thecowboyai/cim-domain-policy/issues
- **Documentation**: https://github.com/thecowboyai/cim-domain-policy
