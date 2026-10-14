{
  description = "microvm-policy: egress and filesystem containment for agent microVMs";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    go-overlay = {
      url = "github:purpleclay/go-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, go-overlay }:
    let
      lib = nixpkgs.lib;
      linuxSystems = [ "x86_64-linux" "aarch64-linux" ];
      forSystems = f: lib.genAttrs linuxSystems (system: f nixpkgs.legacyPackages.${system});

      # renovate: datasource=golang-version depName=go
      goVersion = "1.27.2";
      goToolchain = system: (import nixpkgs {
        inherit system;
        overlays = [ go-overlay.overlays.default ];
      }).go-bin.versions.${goVersion};

      mkEgressProxy = pkgs: (pkgs.buildGoModule.override {
        go = goToolchain pkgs.stdenv.hostPlatform.system;
      }) {
        pname = "egress-proxy";
        version = "0.1.0";
        src = ./proxy;
        vendorHash = null;
        meta = {
          description = "Egress proxy: CONNECT allowlist, credential-injecting LLM reverse proxy, JSONL audit log";
          mainProgram = "egress-proxy";
        };
      };

      mkEgressReport = pkgs: pkgs.writeShellApplication {
        name = "egress-report";
        runtimeInputs = [ pkgs.tshark pkgs.gawk pkgs.coreutils ];
        text = builtins.readFile ./egress-report.sh;
      };
    in
    {
      # The whole reusable layer. A consumer imports nixosModules.default and
      # uses packages.{egress-proxy,egress-report} in its launcher glue; it
      # sets the microvmPolicy.* options (modules/policy.nix) to its own
      # layout, and computes its allowlist from ./allowlists/common.txt plus
      # whatever agent-specific hosts it knows.
      nixosModules = {
        policy = ./modules/policy.nix;
        egress = ./modules/egress.nix;
        workspace = ./modules/workspace.nix;
        default = { imports = [ ./modules/egress.nix ./modules/workspace.nix ]; };
      };

      packages = forSystems (pkgs: {
        egress-proxy = mkEgressProxy pkgs;
        egress-report = mkEgressReport pkgs;
        default = mkEgressProxy pkgs;
      });

      devShells = forSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [ (goToolchain pkgs.stdenv.hostPlatform.system) pkgs.go-tools ];
        };
      });

      checks = forSystems (pkgs: {
        # buildGoModule runs `go test ./...` in its check phase.
        egress-proxy = self.packages.${pkgs.stdenv.hostPlatform.system}.egress-proxy;
        egress-report = import ./tests/egress-report.nix {
          inherit pkgs lib;
          egressReport = self.packages.${pkgs.stdenv.hostPlatform.system}.egress-report;
        };
        egress-integration = import ./tests/egress-integration.nix {
          inherit pkgs lib;
          egressProxy = self.packages.${pkgs.stdenv.hostPlatform.system}.egress-proxy;
        };
      });
    };
}
