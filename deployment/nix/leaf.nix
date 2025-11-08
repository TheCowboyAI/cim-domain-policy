# Leaf Node Module for Policy Service
#
# This module provides a unified interface for deploying the policy-service
# on CIM leaf nodes, supporting both NixOS and nix-darwin platforms.
#
# Usage in leaf node configuration:
#
# ```nix
# {
#   imports = [
#     inputs.cim-domain-policy.leafModule
#   ];
#
#   services.policy-service = {
#     enable = true;
#     natsUrl = "nats://nats-leaf.local:4222";
#     streamName = "POLICY_EVENTS";
#     logLevel = "info";
#   };
# }
# ```

{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.services.policy-service;

  # Detect platform
  isDarwin = pkgs.stdenv.isDarwin;
  isNixOS = !isDarwin;

  # Policy service package (works on both platforms)
  policy-service = pkgs.rustPlatform.buildRustPackage rec {
    pname = "policy-service";
    version = "0.8.0";

    src = ../..;

    cargoLock = {
      lockFile = ../../Cargo.lock;
    };

    nativeBuildInputs = [ pkgs.pkg-config ];
    buildInputs = with pkgs; [
      openssl
    ] ++ lib.optionals stdenv.isDarwin [
      darwin.apple_sdk.frameworks.Security
      darwin.apple_sdk.frameworks.SystemConfiguration
    ];

    # Build only the service binary
    cargoBuildFlags = [ "--bin" "policy-service" ];

    meta = {
      description = "CIM Policy Domain Service with NATS event sourcing";
      homepage = "https://github.com/thecowboyai/cim-domain-policy";
      license = lib.licenses.mit;
      platforms = lib.platforms.unix;
    };
  };

in {
  options.services.policy-service = {
    enable = mkEnableOption "Policy Service with NATS event sourcing for CIM leaf nodes";

    package = mkOption {
      type = types.package;
      default = policy-service;
      description = "The policy-service package to use";
    };

    natsUrl = mkOption {
      type = types.str;
      default = "nats://localhost:4222";
      description = ''
        NATS server URL for the leaf node.

        For leaf nodes connecting to a cluster, use the leaf node's local NATS server
        which should be configured to connect to the cluster.

        Example: nats://nats-leaf.local:4222
      '';
      example = "nats://10.0.1.10:4222";
    };

    streamName = mkOption {
      type = types.str;
      default = "POLICY_EVENTS";
      description = ''
        JetStream stream name for policy events.

        This should be consistent across all leaf nodes in a cluster.
      '';
    };

    logLevel = mkOption {
      type = types.enum [ "trace" "debug" "info" "warn" "error" ];
      default = "info";
      description = "Log level for the service";
    };

    snapshotFrequency = mkOption {
      type = types.int;
      default = 100;
      description = ''
        Number of events between snapshots.

        Lower values = faster aggregate loads, more memory
        Higher values = slower aggregate loads, less memory

        Recommended: 100-1000 depending on event volume
      '';
    };

    # NixOS-specific options
    user = mkOption {
      type = types.str;
      default = "policy-service";
      description = "User account under which the service runs (NixOS only)";
    };

    group = mkOption {
      type = types.str;
      default = "policy-service";
      description = "Group under which the service runs (NixOS only)";
    };
  };

  config = mkIf cfg.enable (mkMerge [
    # Common configuration for all platforms
    {
      assertions = [
        {
          assertion = cfg.snapshotFrequency > 0;
          message = "services.policy-service.snapshotFrequency must be greater than 0";
        }
      ];
    }

    # NixOS-specific configuration
    (mkIf isNixOS {
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
    })

    # Darwin-specific configuration
    (mkIf isDarwin {
      # Create launchd service
      launchd.daemons.policy-service = {
        serviceConfig = {
          ProgramArguments = [ "${cfg.package}/bin/policy-service" ];

          EnvironmentVariables = {
            NATS_URL = cfg.natsUrl;
            STREAM_NAME = cfg.streamName;
            LOG_LEVEL = cfg.logLevel;
            SNAPSHOT_FREQUENCY = toString cfg.snapshotFrequency;
          };

          # Keep service running
          KeepAlive = true;
          RunAtLoad = true;

          # Restart on failure
          SuccessfulExit = false;

          # Logging
          StandardOutPath = "/var/log/policy-service.log";
          StandardErrorPath = "/var/log/policy-service.error.log";

          # Working directory
          WorkingDirectory = "/var/lib/policy-service";
        };
      };

      # Ensure log directory exists
      system.activationScripts.preActivation.text = ''
        mkdir -p /var/log
        mkdir -p /var/lib/policy-service
      '';
    })
  ]);
}
