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

# V2 graph/exchange configuration is deliberately explicit. Runtime config
# validation checks files and cryptographic material; this lightweight check
# catches missing environment wiring before the service is started.
if [ "${PUBLIC_BEARER_EXCHANGE_PROFILE_PATH+x}" = x ] ||
   [ "${PUBLIC_BEARER_EXCHANGE_RETAINED_PROFILE_PATHS+x}" = x ]; then
  error "V1 exchange profile settings are obsolete; use V2 graph paths"
fi
if [ "${PUBLIC_BEARER_GRAPH_ISSUANCE_V4_REPLAY_REDIS_URL+x}" = x ]; then
  error "PUBLIC_BEARER_GRAPH_ISSUANCE_V4_REPLAY_REDIS_URL is obsolete; use the shared authority probe"
fi

if [ "${PUBLIC_BEARER_EXCHANGE_ENABLE:-false}" = true ] ||
   [ "${PUBLIC_BEARER_EXCHANGE_ENABLE:-false}" = 1 ]; then
  [ -n "${PUBLIC_BEARER_EXCHANGE_REDIS_URL:-}" ] || error "PUBLIC_BEARER_EXCHANGE_REDIS_URL is required when exchange is enabled"
  [ -n "${PUBLIC_BEARER_EXCHANGE_ACTIVE_GRAPH_PATH:-}" ] || error "PUBLIC_BEARER_EXCHANGE_ACTIVE_GRAPH_PATH is required when exchange is enabled"
  [ -n "${PUBLIC_BEARER_EXCHANGE_ACTIVE_RECEIPT_KEY_PATH:-}" ] || error "PUBLIC_BEARER_EXCHANGE_ACTIVE_RECEIPT_KEY_PATH is required when exchange is enabled"
  [ -n "${PUBLIC_BEARER_EXCHANGE_ACTIVE_RECEIPT_METADATA_PATH:-}" ] || error "PUBLIC_BEARER_EXCHANGE_ACTIVE_RECEIPT_METADATA_PATH is required when exchange is enabled"
fi

if [ "${PUBLIC_BEARER_GRAPH_ISSUANCE_ENABLE:-false}" = true ] ||
   [ "${PUBLIC_BEARER_GRAPH_ISSUANCE_ENABLE:-false}" = 1 ]; then
  [ "${PUBLIC_BEARER_EXCHANGE_ENABLE:-false}" = true ] || error "graph issuance requires PUBLIC_BEARER_EXCHANGE_ENABLE=true"
  [ -n "${PUBLIC_BEARER_GRAPH_ISSUANCE_POLICY_PATH:-}" ] || error "PUBLIC_BEARER_GRAPH_ISSUANCE_POLICY_PATH is required when graph issuance is enabled"
  case "${PUBLIC_BEARER_GRAPH_ISSUANCE_AUTHORIZATION:-}" in
    hmac_sha256)
      [ -n "${PUBLIC_BEARER_GRAPH_ISSUANCE_HMAC_SECRET_B64:-}" ] || error "graph issuance HMAC secret is required"
      ;;
    v4_local)
      [ -n "${PUBLIC_BEARER_GRAPH_ISSUANCE_V4_KEYRING_B64:-}" ] || error "graph issuance V4 keyring is required"
      ;;
    development_mock)
      [ "${FREEBIRD_ENV:-}" = development ] || error "development graph issuance requires FREEBIRD_ENV=development"
      [ "${FREEBIRD_UNSAFE_DEVELOPMENT_MODE:-false}" = true ] || error "development graph issuance requires FREEBIRD_UNSAFE_DEVELOPMENT_MODE=true"
      ;;
    *) error "PUBLIC_BEARER_GRAPH_ISSUANCE_AUTHORIZATION must be hmac_sha256, v4_local, or development_mock" ;;
  esac
fi

if [ -n "${VERIFIER_GRAPH_ISSUANCE_ISSUER_URLS:-}" ]; then
  [ -n "${REDIS_URL:-}" ] || error "REDIS_URL is required for a graph-authority verifier"
  [ "${IN_MEMORY_REPLAY_STORE:-false}" = false ] || error "graph-authority verifiers cannot use in-memory replay"
  [ "${VERIFIER_REPLAY_AUTHORITY_PROBE_INTERVAL:-30s}" = 30s ] || error "VERIFIER_REPLAY_AUTHORITY_PROBE_INTERVAL must be 30s"
  [ "${VERIFIER_REPLAY_AUTHORITY_MAX_STALENESS:-60s}" = 60s ] || error "VERIFIER_REPLAY_AUTHORITY_MAX_STALENESS must be 60s"
fi
if [ "${SERVICE_ROLE:-}" = verifier ] &&
   { [ "${PUBLIC_BEARER_GRAPH_ISSUANCE_ENABLE:-false}" = true ] ||
     [ "${PUBLIC_BEARER_GRAPH_ISSUANCE_ENABLE:-false}" = 1 ]; }; then
  [ -n "${VERIFIER_GRAPH_ISSUANCE_ISSUER_URLS:-}" ] || error "VERIFIER_GRAPH_ISSUANCE_ISSUER_URLS is required for a graph-enabled verifier"
fi
if [ "${SERVICE_ROLE:-}" = verifier ] &&
   [ -n "${VERIFIER_GRAPH_ISSUANCE_ISSUER_URLS:-}" ] &&
   [ "${PUBLIC_BEARER_GRAPH_ISSUANCE_ENABLE:-false}" != true ] &&
   [ "${PUBLIC_BEARER_GRAPH_ISSUANCE_ENABLE:-false}" != 1 ]; then
  error "VERIFIER_GRAPH_ISSUANCE_ISSUER_URLS requires PUBLIC_BEARER_GRAPH_ISSUANCE_ENABLE=true"
fi

if [ "$errors" -ne 0 ]; then
  printf 'Configuration validation failed (%s error(s)).\n' "$errors" >&2
  exit 1
fi
printf 'Environment validation passed (%s mode; Redis required).\n' "$mode"
