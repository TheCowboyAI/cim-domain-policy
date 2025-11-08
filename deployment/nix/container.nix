# NixOS Container Module for Policy Service
#
# This module provides a complete NixOS container configuration for running
# the policy-service as a systemd service with NATS integration.
#
# Usage in configuration.nix:
#
# ```nix
# {
#   imports = [ ./path/to/cim-domain-policy/deployment/nix/container.nix ];
#
#   services.policy-service = {
#     enable = true;
#     natsUrl = "nats://nats-server:4222";
#     streamName = "POLICY_EVENTS";
#     logLevel = "info";
#     snapshotFrequency = 100;
#   };
# }
# ```

{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.services.policy-service;

  # Policy service package
  policy-service = pkgs.rustPlatform.buildRustPackage rec {
    pname = "policy-service";
    version = "0.8.0";

    src = ../..;

    cargoLock = {
      lockFile = ../../Cargo.lock;
    };

    nativeBuildInputs = [ pkgs.pkg-config ];
    buildInputs = [ ];

    # Build only the service binary
    cargoBuildFlags = [ "--bin" "policy-service" ];

    meta = {
      description = "CIM Policy Domain Service with NATS event sourcing";
      homepage = "https://github.com/thecowboyai/cim-domain-policy";
      license = lib.licenses.mit;
      maintainers = [ ];
    };
  };

in {
  options.services.policy-service = {
    enable = mkEnableOption "Policy Service with NATS event sourcing";

    package = mkOption {
      type = types.package;
      default = policy-service;
      description = "The policy-service package to use";
    };

    natsUrl = mkOption {
      type = types.str;
      default = "nats://localhost:4222";
      description = "NATS server URL";
      example = "nats://nats-server.example.com:4222";
    };

    streamName = mkOption {
      type = types.str;
      default = "POLICY_EVENTS";
      description = "JetStream stream name for policy events";
    };

    logLevel = mkOption {
      type = types.enum [ "trace" "debug" "info" "warn" "error" ];
      default = "info";
      description = "Log level for the service";
    };

    snapshotFrequency = mkOption {
      type = types.int;
      default = 100;
      description = "Number of events between snapshots";
    };

    user = mkOption {
      type = types.str;
      default = "policy-service";
      description = "User account under which the service runs";
    };

    group = mkOption {
      type = types.str;
      default = "policy-service";
      description = "Group under which the service runs";
    };
  };

  config = mkIf cfg.enable {
    # Create system user and group
    users.users.${cfg.user} = {
      isSystemUser = true;
      group = cfg.group;
      description = "Policy Service user";
    };

    users.groups.${cfg.group} = {};

    # Systemd service configuration
    systemd.services.policy-service = {
      description = "CIM Policy Service with NATS event sourcing";
      after = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];

      environment = {
        NATS_URL = cfg.natsUrl;
        STREAM_NAME = cfg.streamName;
        LOG_LEVEL = cfg.logLevel;
        SNAPSHOT_FREQUENCY = toString cfg.snapshotFrequency;
      };

      serviceConfig = {
        Type = "simple";
        User = cfg.user;
        Group = cfg.group;
        ExecStart = "${cfg.package}/bin/policy-service";
        Restart = "always";
        RestartSec = "10s";

        # Security hardening
        DynamicUser = false;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        NoNewPrivileges = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        RestrictAddressFamilies = [ "AF_INET" "AF_INET6" ];
        RestrictNamespaces = true;
        LockPersonality = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        RemoveIPC = true;
        PrivateMounts = true;
      };
    };

    # Optional: Firewall configuration
    # networking.firewall.allowedTCPPorts = [ ];
  };
}
