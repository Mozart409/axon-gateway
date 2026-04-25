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
