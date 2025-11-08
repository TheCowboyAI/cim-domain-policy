{
  description = "CIM Module - Policy domain with NATS event sourcing";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    let
      # Unified leaf node module (works on both NixOS and nix-darwin)
      leafModule = import ./deployment/nix/leaf.nix;

      # NixOS modules (system-independent)
      nixosModules = {
        default = import ./deployment/nix/container.nix;
        policy-service = import ./deployment/nix/container.nix;
        container = import ./deployment/nix/container.nix;
      };

      # Darwin modules (system-independent)
      darwinModules = {
        default = import ./deployment/nix/darwin.nix;
        policy-service = import ./deployment/nix/darwin.nix;
      };

      # NixOS configurations (system-independent)
      nixosConfigurations = {
        policy-container = nixpkgs.lib.nixosSystem {
          system = "x86_64-linux";
          modules = [
            ./deployment/nix/container.nix
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

        policy-lxc = nixpkgs.lib.nixosSystem {
          system = "x86_64-linux";
          modules = [
            ./deployment/nix/lxc.nix
          ];
        };
      };
    in
    {
      # Expose modules and configurations
      inherit leafModule nixosModules darwinModules nixosConfigurations;
    } //
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        rustVersion = pkgs.rust-bin.nightly.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" ];
        };

        buildInputs = with pkgs; [
          openssl
          pkg-config
          protobuf
        ] ++ lib.optionals stdenv.isDarwin [
          darwin.apple_sdk.frameworks.Security
          darwin.apple_sdk.frameworks.SystemConfiguration
        ];

        nativeBuildInputs = with pkgs; [
          rustVersion
          cargo-edit
          cargo-watch
        ];

        # Policy service binary package
        policy-service = pkgs.rustPlatform.buildRustPackage {
          pname = "policy-service";
          version = "0.8.0";
          src = ./.;

          cargoLock = {
            lockFile = ./Cargo.lock;
          };

          inherit buildInputs;
          nativeBuildInputs = [ pkgs.pkg-config ];

          cargoBuildFlags = [ "--bin" "policy-service" ];

          meta = with pkgs.lib; {
            description = "CIM Policy Domain Service with NATS event sourcing";
            homepage = "https://github.com/thecowboyai/cim-domain-policy";
            license = licenses.mit;
            maintainers = [ ];
          };
        };
      in
      {
        packages = {
          default = pkgs.rustPlatform.buildRustPackage {
            pname = "cim-domain-policy";
            version = "0.8.0";
            src = ./.;

            cargoLock = {
              lockFile = ./Cargo.lock;
            };

            inherit buildInputs nativeBuildInputs;

            checkType = "debug";
            doCheck = false;
          };

          policy-service = policy-service;

          # LXC container tarball for Proxmox
          policy-lxc = nixosConfigurations.policy-lxc.config.system.build.tarball;
        };

        devShells.default = pkgs.mkShell {
          inherit buildInputs nativeBuildInputs;

          shellHook = ''
            echo "CIM Policy Domain development environment"
            echo "Rust version: $(rustc --version)"
            echo ""
            echo "Available commands:"
            echo "  cargo build --bin policy-service  # Build NATS service"
            echo "  nix build .#policy-service         # Build service with Nix"
            echo "  nix build .#policy-lxc             # Build LXC container"
            echo ""
            echo "Leaf node deployment:"
            echo "  Use 'leafModule' output in your leaf node configuration"
            echo "  See deployment/LEAF_NODE_DEPLOYMENT.md for details"
          '';
        };
      });
}
