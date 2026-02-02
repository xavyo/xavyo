#!/usr/bin/env bash

# =============================================================================
# Xavyo Suite - Service Health Check Script
# =============================================================================
# Waits for all required services to be healthy before proceeding.
# Useful for CI/CD pipelines and automated testing.
#
# Usage: ./scripts/wait-for-services.sh [options]
#
# Options:
#   --timeout <seconds>  Maximum wait time (default: 60)
#   --postgres-only      Only wait for PostgreSQL
#   --quiet              Suppress output except errors

set -e

# =============================================================================
# Configuration
# =============================================================================
TIMEOUT=${TIMEOUT:-60}
POSTGRES_HOST=${POSTGRES_HOST:-localhost}
POSTGRES_PORT=${POSTGRES_PORT:-5432}
POSTGRES_USER=${POSTGRES_USER:-xavyo}
POSTGRES_DB=${POSTGRES_DB:-xavyo_test}
API_HOST=${API_HOST:-localhost}
API_PORT=${API_PORT:-8080}
QUIET=false
POSTGRES_ONLY=false

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# =============================================================================
# Parse Arguments
# =============================================================================
while [[ $# -gt 0 ]]; do
    case $1 in
        --timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        --postgres-only)
            POSTGRES_ONLY=true
            shift
            ;;
        --quiet)
            QUIET=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# =============================================================================
# Helper Functions
# =============================================================================

log() {
    if [ "$QUIET" = false ]; then
        echo -e "$1"
    fi
}

log_info() {
    log "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    log "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# =============================================================================
# Wait Functions
# =============================================================================

wait_for_postgres() {
    log_info "Waiting for PostgreSQL at $POSTGRES_HOST:$POSTGRES_PORT..."

    local start_time=$(date +%s)
    local end_time=$((start_time + TIMEOUT))

    while true; do
        local current_time=$(date +%s)

        if [ $current_time -ge $end_time ]; then
            log_error "PostgreSQL did not become ready within ${TIMEOUT}s"
            return 1
        fi

        # Try to connect using pg_isready or nc
        if command -v pg_isready &> /dev/null; then
            if pg_isready -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$POSTGRES_DB" &> /dev/null; then
                log_info "PostgreSQL is ready!"
                return 0
            fi
        elif command -v nc &> /dev/null; then
            if nc -z "$POSTGRES_HOST" "$POSTGRES_PORT" &> /dev/null; then
                # Port is open, try a simple query via Docker if available
                if docker exec xavyo-postgres pg_isready -U xavyo -d xavyo_test &> /dev/null 2>&1; then
                    log_info "PostgreSQL is ready!"
                    return 0
                fi
            fi
        else
            # Fallback to Docker exec if available
            if docker exec xavyo-postgres pg_isready -U xavyo -d xavyo_test &> /dev/null 2>&1; then
                log_info "PostgreSQL is ready!"
                return 0
            fi
        fi

        local elapsed=$((current_time - start_time))
        log "Waiting for PostgreSQL... (${elapsed}s/${TIMEOUT}s)"
        sleep 2
    done
}

wait_for_api() {
    log_info "Waiting for API at $API_HOST:$API_PORT..."

    local start_time=$(date +%s)
    local end_time=$((start_time + TIMEOUT))

    while true; do
        local current_time=$(date +%s)

        if [ $current_time -ge $end_time ]; then
            log_error "API did not become ready within ${TIMEOUT}s"
            return 1
        fi

        # Try health check endpoint
        if curl -s "http://$API_HOST:$API_PORT/health" > /dev/null 2>&1; then
            log_info "API is ready!"
            return 0
        fi

        local elapsed=$((current_time - start_time))
        log "Waiting for API... (${elapsed}s/${TIMEOUT}s)"
        sleep 2
    done
}

# =============================================================================
# Main
# =============================================================================

log_info "Starting service health checks (timeout: ${TIMEOUT}s)"

# Always wait for PostgreSQL
if ! wait_for_postgres; then
    exit 1
fi

# Optionally wait for API
if [ "$POSTGRES_ONLY" = false ]; then
    # Only wait for API if it's expected to be running
    if curl -s "http://$API_HOST:$API_PORT/health" > /dev/null 2>&1 || \
       nc -z "$API_HOST" "$API_PORT" 2>&1; then
        if ! wait_for_api; then
            log_warn "API not available (this may be expected)"
        fi
    else
        log_info "API not detected, skipping API health check"
    fi
fi

log_info "All required services are ready!"
exit 0
