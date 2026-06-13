# https://just.systems

set unstable
set dotenv-load

# OCI image label values (populate the ARGs the Dockerfile declares).
version := `grep '^version' Cargo.toml | head -1 | cut -d'"' -f2`
revision := `git rev-parse HEAD 2>/dev/null || echo unknown`
created := `date -u +%Y-%m-%dT%H:%M:%SZ`

default:
    just --choose

clear:
    clear

oci-build: clear
    podman build \
        --build-arg VERSION={{version}} \
        --build-arg REVISION={{revision}} \
        --build-arg CREATED={{created}} \
        -t axon-gateway:latest .

trivy: oci-build
    trivy image axon-gateway:latest

up: clear
    podman compose -f example/compose.local.yml up --build --force-recreate

down:
    podman compose -f example/compose.local.yml down -v

fmt: clear
    cargo fmt --all --check

clippy: clear
    cargo clippy --all-targets --locked -- -D warnings -D clippy::pedantic

test: clear
    cargo test --locked

cov: clear
    cargo llvm-cov --locked --summary-only

audit: clear
    cargo audit

deny: clear
    cargo deny check

# Run the full CI gate locally (matches .github/workflows/ci.yml)
ci: fmt clippy test deny audit
