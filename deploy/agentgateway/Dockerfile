# =============================================================================
# AgentGateway — Production Image (Xavyo IDP integration)
# =============================================================================
# Upstream binary + Node.js for MCP stdio servers (context7, etc.)
#
# Build:  docker build -f deploy/agentgateway/Dockerfile -t xavyo-agentgateway deploy/agentgateway/
# Run:    docker run -p 4000:4000 -p 15000:15000 xavyo-agentgateway

FROM ghcr.io/agentgateway/agentgateway:latest AS upstream

FROM debian:bookworm-slim

LABEL org.opencontainers.image.source="https://github.com/xavyo/xavyo"
LABEL org.opencontainers.image.title="xavyo-agentgateway"
LABEL org.opencontainers.image.description="AgentGateway configured for Xavyo Identity Platform"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl tini \
    && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 1000 -m agentgateway

WORKDIR /app
COPY --from=upstream /app/agentgateway /app/agentgateway
COPY production.yaml /config/production.yaml
RUN chmod +x /app/agentgateway && chown -R agentgateway:agentgateway /app

EXPOSE 4000 15000

USER agentgateway
ENTRYPOINT ["tini", "--"]
CMD ["/app/agentgateway", "-f", "/config/production.yaml"]
