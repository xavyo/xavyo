#!/usr/bin/env bash

# =============================================================================
# Xavyo Suite - Development Environment Manager
# =============================================================================
# Usage: ./scripts/dev-env.sh <command> [options]
#
# Commands:
#   start    Start all development services
#   stop     Stop all services (preserves data)
#   reset    Reset database to clean seed state
#   status   Show status of all services
#   logs     View service logs
#   help     Show this help message
#
# Options:
#   --clean  For 'stop': Also remove volumes (destroys data)
#   --force  For 'reset': Skip confirmation prompt
#   -f       Same as --force

set -e

# =============================================================================
# Configuration
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DOCKER_DIR="$PROJECT_ROOT/docker"
COMPOSE_FILE="$DOCKER_DIR/docker-compose.yml"
ENV_FILE="$PROJECT_ROOT/.env.test"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# =============================================================================
# Helper Functions
# =============================================================================

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_docker() {
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed or not in PATH"
        exit 1
    fi

    if ! docker info &> /dev/null; then
        print_error "Docker daemon is not running"
        print_info "Please start Docker Desktop and try again"
        exit 1
    fi
}

check_port() {
    local port=$1
    if lsof -i ":$port" &> /dev/null; then
        print_error "Port $port is already in use"
        print_info "Check what's using it: lsof -i :$port"
        return 1
    fi
    return 0
}

wait_for_postgres() {
    print_info "Waiting for PostgreSQL to be ready..."
    local retries=30
    local wait_time=2

    for ((i=1; i<=retries; i++)); do
        if docker exec xavyo-postgres pg_isready -U xavyo -d xavyo_test &> /dev/null; then
            print_success "PostgreSQL is ready!"
            return 0
        fi
        echo -n "."
        sleep $wait_time
    done

    echo ""
    print_error "PostgreSQL failed to start within timeout"
    return 1
}

# =============================================================================
# Commands
# =============================================================================

cmd_start() {
    print_info "Starting Xavyo development environment..."

    check_docker

    # Check for port conflicts (use POSTGRES_PORT env var or default to 5434)
    local pg_port="${POSTGRES_PORT:-5434}"
    if ! check_port "$pg_port"; then
        print_warning "PostgreSQL port $pg_port is in use"
        print_info "You may need to stop another PostgreSQL instance or set POSTGRES_PORT"
        exit 1
    fi

    # Change to docker directory
    cd "$DOCKER_DIR"

    # Start services
    print_info "Starting Docker Compose services..."
    docker compose up -d

    # Wait for services to be healthy
    if wait_for_postgres; then
        echo ""
        print_success "Development environment is ready!"
        echo ""
        echo -e "  ${GREEN}PostgreSQL:${NC} localhost:$pg_port"
        echo -e "  ${GREEN}Database:${NC}   xavyo_test"
        echo -e "  ${GREEN}User:${NC}       xavyo"
        echo -e "  ${GREEN}Password:${NC}   xavyo_test_password"
        echo ""
        echo -e "  ${BLUE}Test Credentials:${NC}"
        echo -e "    Admin: admin@test.xavyo.com / Test123!"
        echo -e "    User:  user@test.xavyo.com / Test123!"
        echo ""
        echo -e "  ${BLUE}Connection String:${NC}"
        echo -e "    postgres://xavyo:xavyo_test_password@localhost:$pg_port/xavyo_test"
        echo ""
    else
        print_error "Failed to start environment"
        cmd_logs
        exit 1
    fi
}

cmd_stop() {
    local clean=false

    # Parse options
    for arg in "$@"; do
        case $arg in
            --clean)
                clean=true
                ;;
        esac
    done

    print_info "Stopping Xavyo development environment..."

    check_docker

    cd "$DOCKER_DIR"

    if [ "$clean" = true ]; then
        print_warning "Removing volumes (all data will be lost)"
        docker compose down -v --remove-orphans
    else
        docker compose down --remove-orphans
    fi

    print_success "Environment stopped"

    # Check for orphan processes
    if pgrep -f "xavyo" > /dev/null 2>&1; then
        print_warning "Some xavyo processes may still be running"
        print_info "Check with: pgrep -f xavyo"
    fi
}

cmd_reset() {
    local force=false

    # Parse options
    for arg in "$@"; do
        case $arg in
            --force|-f)
                force=true
                ;;
        esac
    done

    if [ "$force" = false ]; then
        print_warning "This will reset the database and delete all data!"
        read -p "Are you sure? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_info "Reset cancelled"
            exit 0
        fi
    fi

    print_info "Resetting database to clean state..."

    check_docker

    cd "$DOCKER_DIR"

    # Check if container is running
    if ! docker ps --format '{{.Names}}' | grep -q "xavyo-postgres"; then
        print_error "PostgreSQL container is not running"
        print_info "Start it first with: ./scripts/dev-env.sh start"
        exit 1
    fi

    # Drop and recreate database
    print_info "Dropping existing database..."
    docker exec xavyo-postgres psql -U xavyo -c "DROP DATABASE IF EXISTS xavyo_test;" postgres

    print_info "Creating fresh database..."
    docker exec xavyo-postgres psql -U xavyo -c "CREATE DATABASE xavyo_test;" postgres

    # Run init and seed scripts
    print_info "Running initialization scripts..."
    docker exec -i xavyo-postgres psql -U xavyo -d xavyo_test < "$DOCKER_DIR/postgres/init.sql"

    print_info "Loading seed data..."
    docker exec -i xavyo-postgres psql -U xavyo -d xavyo_test < "$DOCKER_DIR/postgres/seed.sql"

    print_success "Database reset complete!"
}

cmd_status() {
    print_info "Checking service status..."

    check_docker

    cd "$DOCKER_DIR"

    echo ""
    docker compose ps

    echo ""

    # Check PostgreSQL health
    if docker exec xavyo-postgres pg_isready -U xavyo -d xavyo_test &> /dev/null; then
        print_success "PostgreSQL is healthy"
    else
        print_error "PostgreSQL is not responding"
    fi
}

cmd_logs() {
    local follow=false
    local lines=100

    # Parse options
    for arg in "$@"; do
        case $arg in
            -f|--follow)
                follow=true
                ;;
        esac
    done

    check_docker

    cd "$DOCKER_DIR"

    if [ "$follow" = true ]; then
        docker compose logs -f --tail=$lines
    else
        docker compose logs --tail=$lines
    fi
}

cmd_help() {
    echo "Xavyo Suite - Development Environment Manager"
    echo ""
    echo "Usage: ./scripts/dev-env.sh <command> [options]"
    echo ""
    echo "Commands:"
    echo "  start    Start all development services"
    echo "  stop     Stop all services (preserves data)"
    echo "  reset    Reset database to clean seed state"
    echo "  status   Show status of all services"
    echo "  logs     View service logs"
    echo "  help     Show this help message"
    echo ""
    echo "Options:"
    echo "  --clean  For 'stop': Also remove volumes (destroys data)"
    echo "  --force  For 'reset': Skip confirmation prompt"
    echo "  -f       Same as --force"
    echo "  --follow For 'logs': Follow log output"
    echo ""
    echo "Examples:"
    echo "  ./scripts/dev-env.sh start         # Start environment"
    echo "  ./scripts/dev-env.sh stop          # Stop (keep data)"
    echo "  ./scripts/dev-env.sh stop --clean  # Stop and delete data"
    echo "  ./scripts/dev-env.sh reset         # Reset database"
    echo "  ./scripts/dev-env.sh reset -f      # Reset without confirmation"
    echo "  ./scripts/dev-env.sh logs -f       # Follow logs"
    echo ""
    echo "Test Credentials:"
    echo "  Admin: admin@test.xavyo.com / Test123!"
    echo "  User:  user@test.xavyo.com / Test123!"
    echo ""
}

# =============================================================================
# Main
# =============================================================================

if [ $# -eq 0 ]; then
    cmd_help
    exit 0
fi

command=$1
shift

case $command in
    start)
        cmd_start "$@"
        ;;
    stop)
        cmd_stop "$@"
        ;;
    reset)
        cmd_reset "$@"
        ;;
    status)
        cmd_status "$@"
        ;;
    logs)
        cmd_logs "$@"
        ;;
    help|--help|-h)
        cmd_help
        ;;
    *)
        print_error "Unknown command: $command"
        echo ""
        cmd_help
        exit 1
        ;;
esac
