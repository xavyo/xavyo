#!/usr/bin/env bash
# Stop SIEM test infrastructure
# Usage: ./stop-test-infra.sh [--clean]

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
        log_warn "Docker daemon is not running - nothing to stop"
        exit 0
    fi
}

# Main
main() {
    local clean_images=false
    local clean_volumes=false

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --clean|-c)
                clean_images=true
                clean_volumes=true
                shift
                ;;
            --clean-images)
                clean_images=true
                shift
                ;;
            --clean-volumes)
                clean_volumes=true
                shift
                ;;
            --help|-h)
                echo "Usage: $0 [--clean] [--clean-images] [--clean-volumes]"
                echo ""
                echo "Options:"
                echo "  --clean, -c       Remove images and volumes"
                echo "  --clean-images    Remove only images"
                echo "  --clean-volumes   Remove only volumes"
                echo "  --help, -h        Show this help message"
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done

    check_docker

    log_info "Stopping SIEM test infrastructure..."
    cd "$DOCKER_DIR"

    # Build docker compose down command
    local down_args=""
    if [ "$clean_volumes" = true ]; then
        down_args="$down_args --volumes"
    fi
    if [ "$clean_images" = true ]; then
        down_args="$down_args --rmi local"
    fi

    # Stop and remove containers
    # shellcheck disable=SC2086
    docker compose down $down_args

    log_info "SIEM test infrastructure stopped."

    # Remove network if it exists and is orphaned
    if docker network inspect siem-test-network &> /dev/null; then
        log_info "Removing orphaned network..."
        docker network rm siem-test-network 2>/dev/null || true
    fi
}

main "$@"
