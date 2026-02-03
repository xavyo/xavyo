# Splunk HEC Mock Server
# Lightweight mock for Splunk HTTP Event Collector testing

FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY server.py .

# Environment defaults
ENV HEC_TOKEN=test-token-12345
ENV PORT=8088
ENV MAX_EVENTS=10000

# Health check
HEALTHCHECK --interval=5s --timeout=3s --start-period=10s --retries=5 \
    CMD curl -f http://localhost:8088/health || exit 1

# Install curl for health check
RUN apt-get update && apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

EXPOSE 8088

# Run with gunicorn for production-like behavior
CMD ["gunicorn", "--bind", "0.0.0.0:8088", "--workers", "2", "--threads", "4", "server:app"]
