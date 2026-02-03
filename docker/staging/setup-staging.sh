#!/bin/bash
# ==============================================================================
# uni-evm Staging Environment Setup Script
# ==============================================================================
#
# This script sets up a staging environment with:
#   - 4 BFT Core root nodes (consensus coordination)
#   - 1 Go Aggregator node (commitment aggregation partition)
#   - 1 uni-evm node (EVM execution with light client validation)
#
# Usage:
#   ./setup-staging.sh           # Full setup and start
#   ./setup-staging.sh --build   # Force rebuild all images
#   ./setup-staging.sh --clean   # Clean all data and restart fresh
#   ./setup-staging.sh --down    # Stop all services
#   ./setup-staging.sh --logs    # Follow logs
#   ./setup-staging.sh --status  # Show service status
#
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# ==============================================================================
# Helper Functions
# ==============================================================================

check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed. Please install Docker first."
        exit 1
    fi

    # Check Docker Compose
    if ! docker compose version &> /dev/null; then
        log_error "Docker Compose is not available. Please install Docker Compose v2."
        exit 1
    fi

    # Check if Docker daemon is running
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running. Please start Docker."
        exit 1
    fi

    # Check required directories
    if [ ! -d "$PROJECT_ROOT/bft-core" ]; then
        log_error "bft-core directory not found at $PROJECT_ROOT/bft-core"
        exit 1
    fi

    if [ ! -d "$PROJECT_ROOT/aggregator-go" ]; then
        log_error "aggregator-go directory not found at $PROJECT_ROOT/aggregator-go"
        exit 1
    fi

    log_success "All prerequisites satisfied"
}

build_images() {
    log_info "Building Docker images..."
    cd "$SCRIPT_DIR"

    # Build BFT Core image
    log_info "Building BFT Core image..."
    docker compose build bft-genesis

    # Build Aggregator image
    log_info "Building Aggregator image..."
    docker compose build aggregator

    # Build uni-evm image
    log_info "Building uni-evm image..."
    docker compose build uni-evm

    log_success "All images built successfully"
}

start_services() {
    log_info "Starting staging environment..."
    cd "$SCRIPT_DIR"

    # Start genesis services first (they run and exit)
    log_info "Running genesis initialization..."
    docker compose up bft-genesis
    docker compose up evm-genesis aggregator-genesis

    # Start BFT root nodes
    log_info "Starting BFT root node 1 (leader)..."
    docker compose up -d bft-root-1

    # Wait for root-1 to be healthy
    log_info "Waiting for root node 1 to be healthy..."
    for i in $(seq 1 30); do
        if docker compose ps bft-root-1 | grep -q "healthy"; then
            log_success "Root node 1 is healthy"
            break
        fi
        echo -n "."
        sleep 2
    done

    log_info "Starting BFT root nodes 2, 3, 4..."
    docker compose up -d bft-root-2 bft-root-3 bft-root-4

    # Wait for all root nodes
    log_info "Waiting for all root nodes to be healthy..."
    for i in $(seq 1 30); do
        HEALTHY=$(docker compose ps | grep "bft-root" | grep -c "healthy" || true)
        if [ "$HEALTHY" -eq 4 ]; then
            log_success "All 4 root nodes are healthy"
            break
        fi
        echo -n "."
        sleep 2
    done

    # Upload configurations
    log_info "Uploading partition configurations..."
    docker compose up upload-configs

    # Start dependencies
    log_info "Starting Redis and MongoDB..."
    docker compose up -d redis mongodb

    # Wait for dependencies
    log_info "Waiting for Redis and MongoDB..."
    for i in $(seq 1 20); do
        HEALTHY=$(docker compose ps | grep -E "redis|mongodb" | grep -c "healthy" || true)
        if [ "$HEALTHY" -eq 2 ]; then
            log_success "Redis and MongoDB are healthy"
            break
        fi
        echo -n "."
        sleep 2
    done

    # Start aggregator
    log_info "Starting Go Aggregator..."
    docker compose up -d aggregator
    sleep 5

    # Start uni-evm
    log_info "Starting uni-evm (Light Client Mode)..."
    docker compose up -d uni-evm

    log_success "Staging environment started successfully!"
}

show_status() {
    log_info "Service Status:"
    cd "$SCRIPT_DIR"
    docker compose ps

    echo ""
    log_info "Endpoints:"
    echo "  BFT Root 1 RPC:    http://localhost:25866"
    echo "  BFT Root 2 RPC:    http://localhost:25867"
    echo "  BFT Root 3 RPC:    http://localhost:25868"
    echo "  BFT Root 4 RPC:    http://localhost:25869"
    echo "  Aggregator API:    http://localhost:3000"
    echo "  Aggregator Docs:   http://localhost:3000/docs"
    echo "  uni-evm JSON-RPC:  http://localhost:8545"

    echo ""
    log_info "Useful commands:"
    echo "  # View logs"
    echo "  docker compose -f $SCRIPT_DIR/docker-compose.yml logs -f"
    echo ""
    echo "  # View specific service logs"
    echo "  docker compose -f $SCRIPT_DIR/docker-compose.yml logs -f uni-evm"
    echo "  docker compose -f $SCRIPT_DIR/docker-compose.yml logs -f bft-root-1"
    echo ""
    echo "  # Stop all services"
    echo "  $0 --down"
    echo ""
    echo "  # Test uni-evm RPC"
    echo "  curl -X POST http://localhost:8545 \\"
    echo "    -H 'Content-Type: application/json' \\"
    echo "    -d '{\"jsonrpc\":\"2.0\",\"method\":\"eth_chainId\",\"params\":[],\"id\":1}'"
}

stop_services() {
    log_info "Stopping staging environment..."
    cd "$SCRIPT_DIR"
    docker compose down

    log_success "All services stopped"
}

clean_all() {
    log_warn "This will delete all staging data including blockchain state!"
    read -p "Are you sure? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Aborted"
        exit 0
    fi

    log_info "Cleaning all staging data..."
    cd "$SCRIPT_DIR"

    # Stop services
    docker compose down -v --remove-orphans 2>/dev/null || true

    # Remove volumes
    docker volume rm staging_genesis staging_root1 staging_root2 staging_root3 staging_root4 \
        staging_aggregator staging_redis-data staging_mongodb-data staging_evm staging_evm-data \
        2>/dev/null || true

    log_success "All staging data cleaned"
}

follow_logs() {
    cd "$SCRIPT_DIR"
    docker compose logs -f "$@"
}

# ==============================================================================
# Main
# ==============================================================================

main() {
    cd "$SCRIPT_DIR"

    case "${1:-}" in
        --build)
            check_prerequisites
            build_images
            ;;
        --clean)
            clean_all
            ;;
        --down)
            stop_services
            ;;
        --logs)
            shift
            follow_logs "$@"
            ;;
        --status)
            show_status
            ;;
        --help|-h)
            echo "Usage: $0 [OPTION]"
            echo ""
            echo "Options:"
            echo "  (no args)    Full setup and start"
            echo "  --build      Force rebuild all Docker images"
            echo "  --clean      Clean all data and volumes"
            echo "  --down       Stop all services"
            echo "  --logs       Follow service logs (optionally specify service name)"
            echo "  --status     Show service status and endpoints"
            echo "  --help       Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                    # Start everything"
            echo "  $0 --logs uni-evm     # Follow uni-evm logs"
            echo "  $0 --clean && $0      # Fresh restart"
            ;;
        *)
            check_prerequisites
            build_images
            start_services
            echo ""
            show_status
            ;;
    esac
}

main "$@"
