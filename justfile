# https://just.systems

set unstable
set dotenv-load

default:
    just --choose

clear:
    clear

oci-build: clear
    podman build -t axon-gateway:latest .

trivy: clear
    podman build -t axon-gateway:latest .
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
