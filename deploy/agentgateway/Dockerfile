# =============================================================================
# AgentGateway — Production Image (Xavyo IDP integration)
# =============================================================================
# Based on upstream pre-built binary, with Node.js for MCP stdio servers
# (e.g., context7, server-everything).
#
# Build:  docker build -f deploy/agentgateway/Dockerfile -t xavyo-agentgateway deploy/agentgateway/
# Run:    docker run -p 4000:4000 -p 15000:15000 xavyo-agentgateway

FROM ghcr.io/agentgateway/agentgateway:latest AS upstream

FROM node:22-slim

LABEL org.opencontainers.image.source="https://github.com/xavyo/xavyo"
LABEL org.opencontainers.image.title="xavyo-agentgateway"
LABEL org.opencontainers.image.description="AgentGateway configured for Xavyo Identity Platform"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates tini \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 1000 -m agentgateway \
    && find / -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true

COPY --from=upstream /app/agentgateway /app/agentgateway
COPY production.yaml /config/production.yaml

EXPOSE 4000 15000

USER agentgateway
ENTRYPOINT ["tini", "--"]
CMD ["/app/agentgateway", "-f", "/config/production.yaml"]
