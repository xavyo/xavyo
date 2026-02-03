#!/usr/bin/env bash
# Start SIEM test infrastructure
# Usage: ./start-test-infra.sh [--wait]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$SCRIPT_DIR/../docker"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check Docker availability
check_docker() {
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed or not in PATH"
        exit 1
    fi

    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running"
        exit 1
    fi

    if ! command -v docker &> /dev/null || ! docker compose version &> /dev/null; then
        log_error "Docker Compose is not available"
        exit 1
    fi
}

# Wait for a service to be healthy
wait_for_health() {
    local url="$1"
    local service="$2"
    local timeout="${3:-60}"
    local elapsed=0

    log_info "Waiting for $service to be healthy..."

    while [ $elapsed -lt $timeout ]; do
        if curl -sf "$url" > /dev/null 2>&1; then
            log_info "$service is healthy!"
            return 0
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done

    log_error "$service failed to become healthy within ${timeout}s"
    return 1
}

# Main
main() {
    local wait_for_healthy=false

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --wait|-w)
                wait_for_healthy=true
                shift
                ;;
            --help|-h)
                echo "Usage: $0 [--wait]"
                echo ""
                echo "Options:"
                echo "  --wait, -w    Wait for services to be healthy before exiting"
                echo "  --help, -h    Show this help message"
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done

    check_docker

    log_info "Starting SIEM test infrastructure..."
    cd "$DOCKER_DIR"

    # Build and start containers
    docker compose up -d --build

    if [ "$wait_for_healthy" = true ]; then
        # Get configured ports from environment or defaults
        HEC_PORT="${HEC_PORT:-8088}"
        SYSLOG_API_PORT="${SYSLOG_API_PORT:-8089}"

        # Wait for health checks
        wait_for_health "http://localhost:$HEC_PORT/health" "Splunk HEC Mock" 60
        wait_for_health "http://localhost:$SYSLOG_API_PORT/health" "Syslog Mock" 60

        log_info "All services are ready!"
    else
        log_info "Containers started. Use 'docker compose ps' to check status."
        log_info "Or run with --wait to wait for health checks."
    fi

    # Show container status
    docker compose ps
}

main "$@"
