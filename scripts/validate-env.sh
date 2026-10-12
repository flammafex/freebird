#!/bin/sh
set -eu

errors=0
error() { printf 'ERROR: %s\n' "$1" >&2; errors=$((errors + 1)); }

key=${ADMIN_API_KEY:-}
[ "${#key}" -ge 32 ] || error "ADMIN_API_KEY must be at least 32 characters"
[ "$key" != dev-admin-key-must-be-at-least-32-characters-long ] || error "ADMIN_API_KEY uses the example value"

mode=${DEPLOYMENT_MODE:-development}
if [ "${COMPOSE_DIRECT_ONLY:-false}" = true ] && [ "$mode" != development ]; then
  error "Compose is direct-development-only; trusted-proxy/production mode requires a proxy-aware deployment"
fi
case "$mode" in
  development)
    [ "${REQUIRE_TLS:-false}" = false ] || error "development mode requires REQUIRE_TLS=false"
    [ "${BEHIND_PROXY:-false}" = false ] || error "development mode requires BEHIND_PROXY=false"
    ;;
  trusted-proxy)
    [ "${REQUIRE_TLS:-false}" = true ] || error "trusted-proxy mode requires REQUIRE_TLS=true"
    [ "${BEHIND_PROXY:-false}" = true ] || error "trusted-proxy mode requires BEHIND_PROXY=true"
    [ -n "${TRUSTED_PROXY_CIDRS:-}" ] || error "trusted-proxy mode requires TRUSTED_PROXY_CIDRS"
    ;;
  *) error "DEPLOYMENT_MODE must be development or trusted-proxy" ;;
esac

[ -n "${REDIS_URL:-}" ] || [ -n "${SYBIL_REPLAY_REDIS_URL:-}" ] || error "a Redis URL is required"
[ "${SERVICE_ROLE:-}" != issuer ] || [ -n "${SYBIL_REPLAY_REDIS_URL:-}" ] || error "SYBIL_REPLAY_REDIS_URL is required for issuer"
[ "${IN_MEMORY_REPLAY_STORE:-false}" = false ] || error "IN_MEMORY_REPLAY_STORE must be false"
[ "${SYBIL_REPLAY_STORE:-redis}" = redis ] || error "SYBIL_REPLAY_STORE must be redis"

if [ "$errors" -ne 0 ]; then
  printf 'Configuration validation failed (%s error(s)).\n' "$errors" >&2
  exit 1
fi
printf 'Environment validation passed (%s mode; Redis required).\n' "$mode"
