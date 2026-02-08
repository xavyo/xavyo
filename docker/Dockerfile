# =============================================================================
# xavyo-idp — Production Docker Image
# =============================================================================
# Multi-stage build: planner → builder → runtime
# Uses cargo-chef for dependency caching and Debian bookworm for glibc compat.
#
# Build:  docker build -f docker/Dockerfile -t xavyo-idp .
# Run:    docker run -p 8080:8080 -v ./docker/keys:/app/keys:ro xavyo-idp

# ---------------------------------------------------------------------------
# Stage 1: Plan dependencies (cargo-chef)
# ---------------------------------------------------------------------------
FROM rust:1.88-slim-bookworm AS planner
RUN cargo install cargo-chef --locked
WORKDIR /app
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ---------------------------------------------------------------------------
# Stage 2: Build release binary
# ---------------------------------------------------------------------------
FROM rust:1.88-slim-bookworm AS builder
RUN cargo install cargo-chef --locked
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl-dev pkg-config curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app

# Cook dependencies first (cached unless Cargo.toml/lock changes)
COPY --from=planner /app/recipe.json recipe.json
ENV SQLX_OFFLINE=true
RUN cargo chef cook --release --recipe-path recipe.json -p idp-api

# Copy source and build
COPY . .
RUN cargo build --release -p idp-api && strip target/release/idp-api

# ---------------------------------------------------------------------------
# Stage 3: Minimal runtime image
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 1000 -m xavyo

WORKDIR /app
COPY --from=builder /app/target/release/idp-api /app/idp-api
RUN mkdir -p /app/keys && chown -R xavyo:xavyo /app

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=5s --retries=5 --start-period=30s \
    CMD curl -f http://localhost:8080/readyz || exit 1

USER xavyo
ENTRYPOINT ["/app/idp-api"]
