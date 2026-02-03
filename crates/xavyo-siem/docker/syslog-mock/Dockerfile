# Syslog Mock Server
# Lightweight mock for syslog TCP/UDP testing

FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY server.py .

# Environment defaults
ENV TCP_PORT=514
ENV UDP_PORT=514
ENV API_PORT=8089
ENV MAX_MESSAGES=10000

# Health check via HTTP API
HEALTHCHECK --interval=5s --timeout=3s --start-period=10s --retries=5 \
    CMD curl -f http://localhost:8089/health || exit 1

# Install curl for health check
RUN apt-get update && apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

# Expose ports
EXPOSE 514/tcp
EXPOSE 514/udp
EXPOSE 8089

# Run directly with Python (threading handles concurrency)
CMD ["python", "server.py"]
