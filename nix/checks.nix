# What `just axon-ci` compiles (fmt, clippy, tests) as crane checks, called
# from the yggdrasil root flake; `cargo deny` and `cargo audit` stay plain
# recipes (they fetch the advisory database, and a build has no network):
#
#   import ./rust/axon-gateway/nix/checks.nix {inherit pkgs crane toolchain;}
#
# As Nix builds they are cached by their inputs: a push that does not change
# the source finds them already in the store, and the rust-ci pre-push gate
# (the root's legacyPackages.rust-ci.axon-gateway) costs an evaluation instead
# of a compile. The standalone flake does not use this file.
#
# Returns `checks` and `cargoArtifacts`.
{
  pkgs,
  crane,
  toolchain,
}: let
  inherit (pkgs) lib;

  craneLib = (crane.mkLib pkgs).overrideToolchain toolchain;

  # The Cargo sources plus what the tests read: they start the built binary
  # from the crate root, which serves styles/ and static/ relative to it.
  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      (craneLib.fileset.commonCargoSources ../.)
      ../clippy.toml
      ../config.example.toml
      ../static
      ../styles
      ../tests
    ];
  };

  commonArgs = {
    inherit src;
    pname = "axon-gateway";
    version = (lib.importTOML ../Cargo.toml).package.version;
    strictDeps = true;
    # The dev profile `cargo test` uses, so the tests keep debug assertions and
    # overflow checks (crane defaults to release).
    CARGO_PROFILE = "dev";
  };

  cargoArtifacts = craneLib.buildDepsOnly commonArgs;
in {
  inherit cargoArtifacts;

  checks = {
    fmt = craneLib.cargoFmt {
      inherit src;
      pname = "axon-gateway-fmt";
    };

    clippy = craneLib.cargoClippy (commonArgs
      // {
        inherit cargoArtifacts;
        pname = "axon-gateway-clippy";
        # Kept equal to `just axon-clippy` (crane adds --locked).
        cargoClippyExtraArgs = "--all-targets -- -D warnings";
      });

    test = craneLib.cargoTest (commonArgs
      // {
        inherit cargoArtifacts;
        pname = "axon-gateway-test";
        # reqwest's rustls verifier loads the system roots, and the sandbox
        # has none.
        SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
      });
  };
}
