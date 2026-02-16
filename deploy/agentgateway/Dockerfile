# =============================================================================
# AgentGateway — Production Image (Xavyo IDP integration)
# =============================================================================
# Thin wrapper around the upstream pre-built image.
# Bakes in the production config; all secrets via env vars at runtime.
#
# Build:  docker build -f deploy/agentgateway/Dockerfile -t xavyo-agentgateway deploy/agentgateway/
# Run:    docker run -p 4000:4000 xavyo-agentgateway

FROM ghcr.io/agentgateway/agentgateway:latest

LABEL org.opencontainers.image.source="https://github.com/xavyo/xavyo"
LABEL org.opencontainers.image.title="xavyo-agentgateway"
LABEL org.opencontainers.image.description="AgentGateway configured for Xavyo Identity Platform"

COPY production.yaml /config/production.yaml

EXPOSE 4000

ENTRYPOINT ["/app/agentgateway"]
CMD ["-f", "/config/production.yaml"]
