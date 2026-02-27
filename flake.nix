{
  description = "Development environment for axon-gateway";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
    rust-overlay,
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      pkgs = import nixpkgs {
        inherit system;
        config.allowUnfree = true;
        overlays = [rust-overlay.overlays.default];
      };
      rust = pkgs.rust-bin.nightly."2026-02-15".default.override {
        extensions = ["rustfmt" "clippy" "rust-src"];
      };
    in {
      # to use other shells, run:
      # nix develop . --command fish
      devShells.default = pkgs.mkShell {
        buildInputs = with pkgs; [
          rust
          lazydocker
          bacon
          cargo-deny
          lefthook
          cocogitto
          just
          cargo-workspaces
          opentofu
          dbeaver-bin
          postgresql_16
          tailwindcss_4
          docker
          docker-buildx
          docker-compose
          sqlx-cli
          opencode
          typos
        ];
        shellHook = ''
          lefthook install
          cog install-hook
          export COMPOSE_BAKE=true
        '';
      };
    });
}
