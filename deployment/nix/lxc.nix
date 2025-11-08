# Proxmox LXC Configuration for Policy Service
#
# This configuration creates a minimal NixOS LXC container suitable for
# deployment on Proxmox VE with the policy-service pre-configured.
#
# Build with:
#   nix build .#policy-lxc
#
# The output will be a tarball at:
#   result/tarball/nixos-system-x86_64-linux.tar.xz
#
# Import to Proxmox:
#   pct create 100 result/tarball/nixos-system-x86_64-linux.tar.xz \
#     --hostname policy-service \
#     --memory 512 \
#     --net0 name=eth0,bridge=vmbr0,ip=dhcp \
#     --storage local-lvm

{ config, pkgs, lib, modulesPath, ... }:

{
  imports = [
    "${modulesPath}/virtualisation/proxmox-lxc.nix"
    ./container.nix
  ];

  # Container metadata
  system.stateVersion = "24.05";

  # Networking
  networking = {
    hostName = "policy-service";
    useDHCP = lib.mkDefault true;
    firewall = {
      enable = true;
      allowedTCPPorts = [ 22 ];  # SSH only
    };
  };

  # Enable SSH for management
  services.openssh = {
    enable = true;
    settings = {
      PermitRootLogin = "prohibit-password";
      PasswordAuthentication = false;
    };
  };

  # Policy service configuration
  services.policy-service = {
    enable = true;
    natsUrl = "nats://nats-server:4222";  # Configure for your environment
    streamName = "POLICY_EVENTS";
    logLevel = "info";
    snapshotFrequency = 100;
  };

  # Minimal system packages
  environment.systemPackages = with pkgs; [
    vim
    htop
    curl
    jq
  ];

  # Automatic updates (optional)
  system.autoUpgrade = {
    enable = false;  # Enable in production if desired
    allowReboot = false;
  };

  # Journal configuration
  services.journald.extraConfig = ''
    SystemMaxUse=100M
    MaxRetentionSec=7day
  '';
}
