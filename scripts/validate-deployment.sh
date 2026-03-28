#!/usr/bin/env bash
#
# Freebird Pre-Deployment Validation Script
#
# This script validates:
# - System requirements (entropy, NTP sync, disk space)
# - Configuration validity
# - Network connectivity
# - Security settings
# - Docker/Kubernetes readiness
#
# Usage: ./scripts/validate-deployment.sh [--fix-entropy] [--mode docker|k8s]
#

set -u

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ENV_FILE="${PROJECT_ROOT}/.env"
MIN_ENTROPY=1000
MIN_DISK_GB=10
NTP_SYNC_THRESHOLD=500  # milliseconds
DEPLOYMENT_MODE="${1:-docker}"  # docker or k8s
FIX_ENTROPY="${2:-}"

# Counters
CHECKS_PASSED=0
CHECKS_FAILED=0
CHECKS_WARNING=0

# Helper functions
print_header() {
    echo ""
    echo -e "${BLUE}=== $1 ===${NC}"
}

check_pass() {
    echo -e "${GREEN}✓${NC} $1"
    ((CHECKS_PASSED++))
}

check_fail() {
    echo -e "${RED}✗${NC} $1"
    ((CHECKS_FAILED++))
}

check_warn() {
    echo -e "${YELLOW}⚠${NC} $1"
    ((CHECKS_WARNING++))
}

# ============================================================================
# 1. ENTROPY CHECK
# ============================================================================
check_entropy() {
    print_header "Entropy & Randomness"

    if [[ ! -f /proc/sys/kernel/random/entropy_avail ]]; then
        check_warn "Entropy file not found (not on Linux?)"
        return
    fi

    local entropy=$(cat /proc/sys/kernel/random/entropy_avail)
    if [[ $entropy -ge $MIN_ENTROPY ]]; then
        check_pass "Entropy available: $entropy bytes"
    else
        check_fail "Low entropy: $entropy bytes (need >= $MIN_ENTROPY)"
        if [[ "$FIX_ENTROPY" == "--fix-entropy" ]]; then
            echo "  Attempting to restore entropy with haveged..."
            if command -v haveged &> /dev/null; then
                sudo haveged &
                sleep 2
                local new_entropy=$(cat /proc/sys/kernel/random/entropy_avail)
                echo "  New entropy: $new_entropy bytes"
            else
                echo "  Install haveged: sudo apt-get install haveged"
            fi
        fi
    fi
}

# ============================================================================
# 2. SYSTEM RESOURCES
# ============================================================================
check_system_resources() {
    print_header "System Resources"

    # Available disk space
    local disk_available_gb=$(df "$PROJECT_ROOT" | awk 'NR==2 {printf "%.1f", $4/1024/1024}')
    if (( $(echo "$disk_available_gb >= $MIN_DISK_GB" | bc -l) )); then
        check_pass "Disk space: ${disk_available_gb}GB available"
    else
        check_fail "Insufficient disk space: ${disk_available_gb}GB (need >= ${MIN_DISK_GB}GB)"
    fi

    # Available RAM
    local ram_available_mb=$(free -m | awk 'NR==2 {print $7}')
    if [[ $ram_available_mb -ge 2048 ]]; then
        check_pass "RAM available: ${ram_available_mb}MB"
    else
        check_warn "Low RAM: ${ram_available_mb}MB (2GB+ recommended)"
    fi

    # CPU cores
    local cpu_count=$(nproc)
    if [[ $cpu_count -ge 2 ]]; then
        check_pass "CPU cores: $cpu_count"
    else
        check_warn "Only $cpu_count CPU core(s) (2+ recommended)"
    fi
}

# ============================================================================
# 3. TIME SYNCHRONIZATION
# ============================================================================
check_ntp_sync() {
    print_header "Time Synchronization"

    if command -v timedatectl &> /dev/null; then
        local ntp_status=$(timedatectl | grep -i "synchronized" | awk '{print $NF}')
        if [[ "$ntp_status" == "yes" ]]; then
            check_pass "System clock synchronized"
        else
            check_fail "System clock NOT synchronized - Configure NTP (ntpd, systemd-timesyncd)"
        fi
    else
        check_warn "timedatectl not available - Cannot verify NTP sync"
    fi

    # Check if ntpd or chrony is running
    if systemctl is-active --quiet systemd-timesyncd || \
       systemctl is-active --quiet ntpd || \
       systemctl is-active --quiet chrony; then
        check_pass "Time service is running"
    else
        check_warn "No active time service detected (ntpd, chrony, or systemd-timesyncd)"
    fi
}

# ============================================================================
# 4. CONFIGURATION VALIDATION
# ============================================================================
check_configuration() {
    print_header "Configuration Validation"

    if [[ ! -f "$ENV_FILE" ]]; then
        check_fail "Environment file not found: $ENV_FILE"
        echo "  Run: cp .env.example .env"
        return
    fi

    check_pass "Environment file exists: $ENV_FILE"

    # Source the environment file safely
    if grep -q "ADMIN_API_KEY=" "$ENV_FILE"; then
        local admin_key=$(grep "ADMIN_API_KEY=" "$ENV_FILE" | cut -d'=' -f2)
        if [[ ${#admin_key} -ge 32 ]]; then
            check_pass "ADMIN_API_KEY is present and valid (${#admin_key} chars)"
        else
            check_fail "ADMIN_API_KEY too short (${#admin_key} chars, need 32+)"
        fi
    else
        check_fail "ADMIN_API_KEY not set in .env"
    fi

    # Check ISSUER_ID
    if grep -q "ISSUER_ID=" "$ENV_FILE"; then
        check_pass "ISSUER_ID is configured"
    else
        check_warn "ISSUER_ID not set (will use default)"
    fi

    # Check REQUIRE_TLS setting
    if grep -q "REQUIRE_TLS=false" "$ENV_FILE"; then
        check_warn "REQUIRE_TLS=false (use TLS in production!)"
    else
        check_pass "TLS configuration set"
    fi

    # Verify Redis URL if REDIS_URL is set
    if grep -q "REDIS_URL=" "$ENV_FILE"; then
        check_pass "REDIS_URL is configured"
    else
        check_warn "REDIS_URL not set (using docker-compose default)"
    fi
}

# ============================================================================
# 5. DOCKER VALIDATION
# ============================================================================
check_docker() {
    print_header "Docker Environment"

    if ! command -v docker &> /dev/null; then
        check_fail "Docker not installed"
        return
    fi
    check_pass "Docker is installed"

    if docker ps &>/dev/null; then
        check_pass "Docker daemon is running"
    else
        check_fail "Docker daemon is not running or not accessible"
        return
    fi

    # Check docker-compose
    if command -v docker-compose &> /dev/null; then
        local compose_version=$(docker-compose --version)
        check_pass "docker-compose available: $compose_version"
    elif docker compose version &>/dev/null 2>&1; then
        check_pass "Docker Compose plugin available"
    else
        check_warn "docker-compose not found (required for Docker deployments)"
    fi

    # Check available disk for Docker
    local docker_disk=$(docker system df | awk 'NR==2 {print $4}')
    if [[ -n "$docker_disk" ]]; then
        check_pass "Docker disk usage: $docker_disk"
    fi
}

# ============================================================================
# 6. KUBERNETES VALIDATION
# ============================================================================
check_kubernetes() {
    print_header "Kubernetes Environment"

    if ! command -v kubectl &> /dev/null; then
        check_warn "kubectl not installed (required for Kubernetes deployments)"
        return
    fi

    check_pass "kubectl is installed"

    # Check cluster connectivity
    if kubectl cluster-info &>/dev/null; then
        check_pass "Connected to Kubernetes cluster"
    else
        check_warn "Cannot connect to Kubernetes cluster"
        return
    fi

    # Check current context
    local context=$(kubectl config current-context 2>/dev/null)
    if [[ -n "$context" ]]; then
        check_pass "Current context: $context"
    fi

    # Check available resources
    if kubectl auth can-i create deployments --all-namespaces &>/dev/null; then
        check_pass "Sufficient RBAC permissions"
    else
        check_fail "Insufficient RBAC permissions to deploy"
    fi
}

# ============================================================================
# 7. SECURITY CHECKS
# ============================================================================
check_security() {
    print_header "Security Configuration"

    # Check file permissions on .env
    if [[ -f "$ENV_FILE" ]]; then
        local perms=$(stat -f '%A' "$ENV_FILE" 2>/dev/null || stat -c '%a' "$ENV_FILE" 2>/dev/null)
        if [[ "$perms" == *"600"* ]] || [[ "$perms" == *"rw"* ]]; then
            check_pass ".env file permissions: restrictive"
        else
            check_warn ".env file should have restricted permissions (600)"
        fi
    fi

    # Check for plaintext secrets in docker-compose
    if grep -q "ADMIN_API_KEY=" "$PROJECT_ROOT/docker-compose.yaml" 2>/dev/null; then
        check_warn "Secrets may be in docker-compose.yaml (use secrets management)"
    fi

    # Check SELinux/AppArmor status
    if command -v getenforce &>/dev/null; then
        local selinux_status=$(getenforce 2>/dev/null)
        check_warn "SELinux status: $selinux_status (configure policies for Freebird)"
    fi

    if command -v aa-status &>/dev/null; then
        check_warn "AppArmor detected (configure profiles for Freebird)"
    fi
}

# ============================================================================
# 8. NETWORK VALIDATION
# ============================================================================
check_network() {
    print_header "Network Configuration"

    # Check if ports are available
    local issuer_port=$(grep "ISSUER_BIND_ADDR" "$ENV_FILE" | grep -o ':[0-9]*' | tr -d ':' || echo "8081")
    local verifier_port=$(grep "VERIFIER_BIND_ADDR" "$ENV_FILE" | grep -o ':[0-9]*' | tr -d ':' || echo "8082")
    local redis_port=${REDIS_PORT:-6379}

    # Test issuer port
    if ! nc -z 127.0.0.1 "$issuer_port" 2>/dev/null; then
        check_pass "Port $issuer_port (issuer) is available"
    else
        check_warn "Port $issuer_port (issuer) may already be in use"
    fi

    # Test verifier port
    if ! nc -z 127.0.0.1 "$verifier_port" 2>/dev/null; then
        check_pass "Port $verifier_port (verifier) is available"
    else
        check_warn "Port $verifier_port (verifier) may already be in use"
    fi

    # Test DNS resolution
    if ping -c 1 -W 1 8.8.8.8 &>/dev/null; then
        check_pass "External network connectivity confirmed"
    else
        check_warn "External network connectivity test failed"
    fi
}

# ============================================================================
# 9. BUILD ARTIFACTS
# ============================================================================
check_build_artifacts() {
    print_header "Build Artifacts"

    if [[ -f "$PROJECT_ROOT/Dockerfile" ]]; then
        check_pass "Dockerfile found"
    else
        check_fail "Dockerfile not found"
    fi

    if [[ -f "$PROJECT_ROOT/docker-compose.yaml" ]]; then
        check_pass "docker-compose.yaml found"
    else
        check_fail "docker-compose.yaml not found"
    fi

    if [[ -f "$PROJECT_ROOT/Cargo.toml" ]]; then
        check_pass "Cargo.toml found (Rust workspace)"
    else
        check_fail "Cargo.toml not found"
    fi
}

# ============================================================================
# 10. PRODUCTION CHECKLIST
# ============================================================================
check_production_readiness() {
    print_header "Production Readiness Checklist"

    # This is a summary based on docs/PRODUCTION.md

    local checks=(
        "REQUIRE_TLS is set to 'true' (not 'false')"
        "Issuer and Verifier on separate infrastructure"
        "Reverse proxy (Nginx/Caddy) configured for TLS"
        "ADMIN_API_KEY is strong (48+ characters recommended)"
        "Redis configured with persistence (AOF or RDB)"
        "Monitoring and alerting configured"
        "Log aggregation enabled"
        "Backup strategy implemented"
        "Disaster recovery plan documented"
        "Security audit completed"
    )

    echo ""
    echo "To achieve full production readiness, ensure:"
    for check in "${checks[@]}"; do
        echo "  • $check"
    done
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================
main() {
    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║          Freebird Pre-Deployment Validation               ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Mode: $DEPLOYMENT_MODE"
    echo "Project: $PROJECT_ROOT"
    echo ""

    # Run all checks
    check_entropy
    check_system_resources
    check_ntp_sync
    check_configuration
    check_docker
    if [[ "$DEPLOYMENT_MODE" == "k8s" ]]; then
        check_kubernetes
    fi
    check_security
    check_network
    check_build_artifacts
    check_production_readiness

    # Summary
    echo ""
    echo -e "${BLUE}=== Summary ===${NC}"
    echo -e "${GREEN}Passed:${NC}  $CHECKS_PASSED"
    echo -e "${YELLOW}Warnings:${NC} $CHECKS_WARNING"
    echo -e "${RED}Failed:${NC}  $CHECKS_FAILED"
    echo ""

    if [[ $CHECKS_FAILED -eq 0 ]]; then
        echo -e "${GREEN}✓ Deployment validation passed!${NC}"
        if [[ $CHECKS_WARNING -gt 0 ]]; then
            echo -e "${YELLOW}⚠ Address warnings above before production deployment${NC}"
        fi
        exit 0
    else
        echo -e "${RED}✗ Deployment validation failed. Fix errors above.${NC}"
        exit 1
    fi
}

# Run main
main
