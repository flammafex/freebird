#!/usr/bin/env bash
# Freebird admin launch script — first-time setup and deployment helper.
set -euo pipefail

COMPOSE_FILE="$(cd "$(dirname "$0")" && pwd)/docker-compose.yaml"
ENV_FILE="$(cd "$(dirname "$0")" && pwd)/.env"
ENV_EXAMPLE="$(cd "$(dirname "$0")" && pwd)/.env.example"

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'
info()  { printf "${GREEN}[freebird]${NC} %s\n" "$*"; }
warn()  { printf "${YELLOW}[warn]${NC}    %s\n" "$*"; }
error() { printf "${RED}[error]${NC}   %s\n" "$*" >&2; exit 1; }
prompt(){ printf "${YELLOW}>>>${NC} %s " "$*"; }

# ── Prerequisites ──────────────────────────────────────────────────────────────

check_prereqs() {
    local missing=0
    command -v docker >/dev/null 2>&1 || { warn "docker not found"; missing=1; }
    if docker compose version >/dev/null 2>&1; then
        COMPOSE_CMD="docker compose"
    elif command -v docker-compose >/dev/null 2>&1; then
        COMPOSE_CMD="docker-compose"
    else
        warn "docker compose (plugin or standalone) not found"; missing=1
    fi
    [[ $missing -eq 0 ]] || error "Install missing prerequisites and retry."
    docker info >/dev/null 2>&1 || error "Docker daemon is not running. Start it and retry."
    info "Prerequisites OK (${COMPOSE_CMD})"
}

# ── .env setup ─────────────────────────────────────────────────────────────────

setup_env() {
    if [[ ! -f "$ENV_FILE" ]]; then
        info "Creating .env from .env.example ..."
        cp "$ENV_EXAMPLE" "$ENV_FILE"
        warn ".env created — review it before going to production."
    fi

    # Check ADMIN_API_KEY is not the example default
    local key
    key=$(grep -E '^ADMIN_API_KEY=' "$ENV_FILE" | cut -d= -f2- | tr -d '"' || true)
    if [[ "$key" == "dev-admin-key-must-be-at-least-32-characters-long" || -z "$key" ]]; then
        warn "ADMIN_API_KEY is still the example default — this is insecure in production."
        printf "\nGenerate a secure key now? [Y/n] "
        read -r answer
        if [[ "${answer,,}" != "n" ]]; then
            local new_key
            new_key=$(LC_ALL=C tr -dc 'A-Za-z0-9_-' </dev/urandom | head -c 48)
            # Replace in .env (handles both quoted and unquoted values)
            sed -i.bak "s|^ADMIN_API_KEY=.*|ADMIN_API_KEY=${new_key}|" "$ENV_FILE" && rm -f "${ENV_FILE}.bak"
            info "New ADMIN_API_KEY written to .env."
            info "  Key: ${new_key}"
            warn "Save this key — it cannot be recovered."
        fi
    fi
}

# ── Image selection ────────────────────────────────────────────────────────────

choose_images() {
    echo ""
    echo "How would you like to get the Freebird images?"
    echo "  1) Pull pre-built images from GHCR  (fast, requires internet)"
    echo "  2) Build from source                (slow ~15 min, requires Rust in Docker)"
    echo ""
    prompt "Choice [1]:"
    read -r choice
    choice="${choice:-1}"

    case "$choice" in
        1)
            info "Pulling images from GHCR ..."
            $COMPOSE_CMD -f "$COMPOSE_FILE" pull issuer verifier redis || {
                warn "Pull failed — falling back to building from source."
                BUILD_FLAG="--build"
            }
            BUILD_FLAG=""
            ;;
        2)
            info "Will build from source (this takes ~15 minutes on first run)."
            BUILD_FLAG="--build"
            ;;
        *)
            warn "Invalid choice; defaulting to pull."
            $COMPOSE_CMD -f "$COMPOSE_FILE" pull issuer verifier redis || BUILD_FLAG="--build"
            BUILD_FLAG=""
            ;;
    esac
}

# ── Launch ─────────────────────────────────────────────────────────────────────

launch() {
    info "Starting Freebird ..."
    # shellcheck disable=SC2086
    $COMPOSE_CMD -f "$COMPOSE_FILE" --env-file "$ENV_FILE" up -d ${BUILD_FLAG:-}

    echo ""
    info "Waiting for services to become healthy (up to 60s) ..."
    local deadline=$(( $(date +%s) + 60 ))
    while true; do
        local issuer_health verifier_health
        issuer_health=$(docker inspect --format='{{.State.Health.Status}}' freebird-issuer 2>/dev/null || echo "starting")
        verifier_health=$(docker inspect --format='{{.State.Health.Status}}' freebird-verifier 2>/dev/null || echo "starting")
        if [[ "$issuer_health" == "healthy" && "$verifier_health" == "healthy" ]]; then
            break
        fi
        if [[ $(date +%s) -ge $deadline ]]; then
            warn "Services not healthy after 60s — check logs with: docker compose logs"
            break
        fi
        sleep 3
    done
}

# ── Status ─────────────────────────────────────────────────────────────────────

print_status() {
    local issuer_port verifier_port
    issuer_port=$(grep -E '^ISSUER_BIND_ADDR=' "$ENV_FILE" 2>/dev/null | cut -d: -f2 || echo "8081")
    verifier_port=$(grep -E '^VERIFIER_BIND_ADDR=' "$ENV_FILE" 2>/dev/null | cut -d: -f2 || echo "8082")
    issuer_port="${issuer_port:-8081}"
    verifier_port="${verifier_port:-8082}"

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Freebird is running"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Issuer   http://127.0.0.1:${issuer_port}"
    echo "  Verifier http://127.0.0.1:${verifier_port}"
    echo ""
    echo "  Well-known: curl http://127.0.0.1:${issuer_port}/.well-known/issuer"
    echo "  Verify:     curl http://127.0.0.1:${verifier_port}/v1/check"
    echo ""
    echo "  Logs:   docker compose logs -f"
    echo "  Stop:   docker compose down"
    echo "  Backup: ./scripts/backup-restore.sh backup"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# ── Subcommands ────────────────────────────────────────────────────────────────

CMD="${1:-up}"
case "$CMD" in
    up|start|"")
        check_prereqs
        setup_env
        choose_images
        launch
        print_status
        ;;
    stop|down)
        check_prereqs
        $COMPOSE_CMD -f "$COMPOSE_FILE" down
        info "Freebird stopped."
        ;;
    logs)
        check_prereqs
        $COMPOSE_CMD -f "$COMPOSE_FILE" logs -f "${@:2}"
        ;;
    restart)
        check_prereqs
        $COMPOSE_CMD -f "$COMPOSE_FILE" restart "${@:2}"
        ;;
    status)
        check_prereqs
        $COMPOSE_CMD -f "$COMPOSE_FILE" ps
        ;;
    pull)
        check_prereqs
        $COMPOSE_CMD -f "$COMPOSE_FILE" pull
        ;;
    build)
        check_prereqs
        $COMPOSE_CMD -f "$COMPOSE_FILE" build "${@:2}"
        ;;
    *)
        echo "Usage: $0 [up|down|logs|restart|status|pull|build]"
        exit 1
        ;;
esac
