# Stage 1: Build (optimized for compile speed)
FROM rust:1.94-bookworm AS builder

WORKDIR /build

# Compile speed optimizations
ENV CARGO_INCREMENTAL=1
ENV CARGO_PROFILE_RELEASE_LTO=thin
ENV CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release --locked

# Stage 2: Runtime (minimal Wolfi image)
FROM cgr.dev/chainguard/wolfi-base:latest

COPY --from=builder /build/target/release/axon-gateway /usr/local/bin/axon-gateway
COPY LICENSE licenses.html /usr/share/licenses/axon-gateway/
COPY static /app/static
COPY styles/output.css /app/styles/output.css

WORKDIR /app

EXPOSE 8080 

ENTRYPOINT ["/usr/local/bin/axon-gateway"]
