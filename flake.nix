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
          # keep-sorted start
          bacon
          cargo-deny
          cargo-workspaces
          cocogitto
          dbeaver-bin
          docker
          docker-buildx
          docker-compose
          just
          keep-sorted
          lazydocker
          lefthook
          opencode
          opentofu
          postgresql_16
          rust
          sqlx-cli
          tailwindcss_4
          # keep-sorted end
        ];
        shellHook = ''
          lefthook install
          cog install-hook
          export COMPOSE_BAKE=true
        '';
      };
    });
}
