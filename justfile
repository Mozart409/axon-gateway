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

clippy: clear
    cargo clippy -- -D clippy::pedantic

audit: clear
    cargo audit

deny: clear
    cargo deny check
