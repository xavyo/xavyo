# =============================================================================
# xavyo-ext-authz — Production Docker Image
# =============================================================================
# Multi-stage build: planner → builder → runtime
# gRPC authorization sidecar for AgentGateway integration.
#
# Build:  docker build -f deploy/ext-authz/Dockerfile -t xavyo-ext-authz .
# Run:    docker run -p 50051:50051 -e DATABASE_URL=... xavyo-ext-authz

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
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl-dev pkg-config protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app

# Cook dependencies first (cached unless Cargo.toml/lock changes)
COPY --from=planner /app/recipe.json recipe.json
ENV SQLX_OFFLINE=true
RUN cargo chef cook --release --recipe-path recipe.json -p ext-authz

# Copy source and build
COPY . .
RUN cargo build --release -p ext-authz && strip target/release/ext-authz

# ---------------------------------------------------------------------------
# Stage 3: Minimal runtime image
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

LABEL org.opencontainers.image.source="https://github.com/xavyo/xavyo"
LABEL org.opencontainers.image.title="xavyo-ext-authz"
LABEL org.opencontainers.image.description="Xavyo ext-authz gRPC sidecar for AgentGateway"

ENV DEBIAN_FRONTEND=noninteractive \
    APP_ENV=production \
    RUST_BACKTRACE=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 ca-certificates tini \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 1000 -m xavyo \
    && find / -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true

WORKDIR /app
COPY --from=builder /app/target/release/ext-authz /app/ext-authz
RUN chown -R xavyo:xavyo /app

EXPOSE 50051

USER xavyo
ENTRYPOINT ["tini", "--"]
CMD ["/app/ext-authz"]
