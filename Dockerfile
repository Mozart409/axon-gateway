# Stage 1: Build (optimized for compile speed)
FROM rust:1.96.1-bookworm AS builder

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

ARG VERSION
ARG REVISION
ARG CREATED

LABEL org.opencontainers.image.title="axon-gateway" \
      org.opencontainers.image.description="A high-performance MCP gateway that aggregates multiple Model Context Protocol servers behind a single endpoint" \
      org.opencontainers.image.url="https://github.com/Mozart409/axon-gateway" \
      org.opencontainers.image.source="https://github.com/Mozart409/axon-gateway" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.vendor="Mozart409" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}"

# `wget` is not part of wolfi-base (and busybox here has no wget applet), but the
# compose healthchecks probe /health with it. Add the tiny Wolfi package so the
# documented healthcheck actually passes instead of hanging on "unhealthy".
RUN apk add --no-cache wget

COPY --from=builder /build/target/release/axon-gateway /usr/local/bin/axon-gateway
COPY static /app/static
COPY styles/output.css /app/styles/output.css

WORKDIR /app

EXPOSE 8080 

ENTRYPOINT ["/usr/local/bin/axon-gateway"]
