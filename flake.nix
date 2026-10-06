{
  description = "Development environment for axon-gateway";

  # In the yggdrasil monorepo this is a subflake of the root flake, which makes
  # `nixpkgs`, `fenix` and `flake-parts` follow its own, so the toolchain below
  # is the monorepo's one stable Rust (rust/toolchain.nix there). This file
  # exists for the standalone GitHub export.
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-parts = {
      url = "github:hercules-ci/flake-parts";
      inputs.nixpkgs-lib.follows = "nixpkgs";
    };
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = inputs @ {flake-parts, ...}:
    flake-parts.lib.mkFlake {inherit inputs;} {
      systems = ["x86_64-linux" "aarch64-linux" "aarch64-darwin"];

      perSystem = {
        pkgs,
        system,
        ...
      }: let
        # Latest stable, pinned by flake.lock rather than a version literal.
        # Keep the component list equal to `dev` in yggdrasil's
        # rust/toolchain.nix.
        toolchain = inputs.fenix.packages.${system}.stable.withComponents [
          "cargo"
          "clippy"
          "llvm-tools-preview"
          "rust-analyzer"
          "rust-src"
          "rustc"
          "rustfmt"
        ];
      in {
        packages.toolchain = toolchain;

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            # keep-sorted start
            act
            bacon
            cargo-audit
            cargo-deny
            cargo-edit
            cargo-workspaces
            cocogitto
            keep-sorted
            podman-compose
            tailwindcss_4
            toolchain
            trivy
            # keep-sorted end
          ];
        };
      };
    };
}
