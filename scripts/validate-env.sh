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

# Retired V5/V1 settings are rejected, never positively interpreted. This
# catches both inherited process variables and assignments loaded from .env.
if env | grep -Eq '^PUBLIC_BEARER_[A-Za-z0-9_]*='; then
  error "retired PUBLIC_BEARER_* configuration is not accepted; use native V7 settings"
fi

if [ "${SERVICE_ROLE:-}" = issuer ]; then
  [ "${NATIVE_BEARER_V7_ENABLE:-}" = true ] || [ "${NATIVE_BEARER_V7_ENABLE:-}" = 1 ] || \
    error "NATIVE_BEARER_V7_ENABLE=true is required; V7 native bearer issuance is mandatory"
  [ -n "${NATIVE_BEARER_V7_SK_PATH:-}" ] || error "NATIVE_BEARER_V7_SK_PATH is required"
  [ -n "${NATIVE_BEARER_V7_METADATA_PATH:-}" ] || error "NATIVE_BEARER_V7_METADATA_PATH is required"
  [ -n "${NATIVE_BEARER_V7_REGISTRY_PATH:-}" ] || error "NATIVE_BEARER_V7_REGISTRY_PATH is required"
  [ -n "${NATIVE_BEARER_V7_PROFILE_ID:-}" ] || error "NATIVE_BEARER_V7_PROFILE_ID is required"
  [ -n "${NATIVE_BEARER_V7_TOKEN_KEY_ID:-}" ] || error "NATIVE_BEARER_V7_TOKEN_KEY_ID is required"
  [ -n "${NATIVE_BEARER_V7_ASSET_ID:-}" ] || error "NATIVE_BEARER_V7_ASSET_ID is required"
  [ -n "${NATIVE_BEARER_V7_AMOUNT_MINOR:-}" ] || error "NATIVE_BEARER_V7_AMOUNT_MINOR is required"
  if [ -n "${NATIVE_BEARER_V7_DESCRIPTOR_ID:-}" ]; then
    printf '%s' "${NATIVE_BEARER_V7_DESCRIPTOR_ID}" | grep -Eq '^[0-9a-f]{64}$' || \
      error "NATIVE_BEARER_V7_DESCRIPTOR_ID must be 64 lowercase hexadecimal characters when set"
  fi
  printf '%s' "${NATIVE_BEARER_V7_TOKEN_KEY_ID:-}" | grep -Eq '^[0-9a-f]{64}$' || \
    error "NATIVE_BEARER_V7_TOKEN_KEY_ID must be 64 lowercase hexadecimal characters"
fi

if [ "${NATIVE_EXCHANGE_V7_ENABLE:-false}" = true ] ||
   [ "${NATIVE_EXCHANGE_V7_ENABLE:-false}" = 1 ]; then
  [ -n "${NATIVE_EXCHANGE_V7_REDIS_URL:-}" ] || error "NATIVE_EXCHANGE_V7_REDIS_URL is required when V7 exchange is enabled"
  [ -n "${NATIVE_EXCHANGE_V7_DISCOVERY_PATH:-}" ] || error "NATIVE_EXCHANGE_V7_DISCOVERY_PATH is required when V7 exchange is enabled"
  [ -n "${NATIVE_EXCHANGE_V7_ACTIVE_RECEIPT_KEY_PATH:-}" ] || error "NATIVE_EXCHANGE_V7_ACTIVE_RECEIPT_KEY_PATH is required when V7 exchange is enabled"
  [ -n "${NATIVE_EXCHANGE_V7_ACTIVE_RECEIPT_METADATA_PATH:-}" ] || error "NATIVE_EXCHANGE_V7_ACTIVE_RECEIPT_METADATA_PATH is required when V7 exchange is enabled"
fi

if [ "${NATIVE_GRAPH_ISSUANCE_V7_ENABLE:-false}" = true ] ||
   [ "${NATIVE_GRAPH_ISSUANCE_V7_ENABLE:-false}" = 1 ]; then
  [ "${NATIVE_EXCHANGE_V7_ENABLE:-false}" = true ] || [ "${NATIVE_EXCHANGE_V7_ENABLE:-false}" = 1 ] || \
    error "V7 graph issuance requires NATIVE_EXCHANGE_V7_ENABLE=true"
  [ -n "${NATIVE_GRAPH_ISSUANCE_V7_POLICY_PATH:-}" ] || error "NATIVE_GRAPH_ISSUANCE_V7_POLICY_PATH is required when V7 graph issuance is enabled"
  [ "${NATIVE_GRAPH_ISSUANCE_V7_AUTHORIZATION:-}" = v4_local ] || \
    error "NATIVE_GRAPH_ISSUANCE_V7_AUTHORIZATION must be v4_local for deployment"
  [ -n "${NATIVE_GRAPH_ISSUANCE_V7_V4_KEYRING_B64:-}" ] || error "NATIVE_GRAPH_ISSUANCE_V7_V4_KEYRING_B64 is required for V7 graph issuance"
fi

if [ -n "${VERIFIER_GRAPH_ISSUANCE_ISSUER_URLS:-}" ]; then
  [ -n "${REDIS_URL:-}" ] || error "REDIS_URL is required for a graph-authority verifier"
  [ "${IN_MEMORY_REPLAY_STORE:-false}" = false ] || error "graph-authority verifiers cannot use in-memory replay"
  [ "${VERIFIER_REPLAY_AUTHORITY_PROBE_INTERVAL:-30s}" = 30s ] || error "VERIFIER_REPLAY_AUTHORITY_PROBE_INTERVAL must be 30s"
  [ "${VERIFIER_REPLAY_AUTHORITY_MAX_STALENESS:-60s}" = 60s ] || error "VERIFIER_REPLAY_AUTHORITY_MAX_STALENESS must be 60s"
fi
if [ "${SERVICE_ROLE:-}" = verifier ] &&
   { [ "${NATIVE_GRAPH_ISSUANCE_V7_ENABLE:-false}" = true ] ||
     [ "${NATIVE_GRAPH_ISSUANCE_V7_ENABLE:-false}" = 1 ]; }; then
  [ -n "${VERIFIER_GRAPH_ISSUANCE_ISSUER_URLS:-}" ] || error "VERIFIER_GRAPH_ISSUANCE_ISSUER_URLS is required for a graph-enabled verifier"
fi
if [ "${SERVICE_ROLE:-}" = verifier ] &&
   [ -n "${VERIFIER_GRAPH_ISSUANCE_ISSUER_URLS:-}" ] &&
   [ "${NATIVE_GRAPH_ISSUANCE_V7_ENABLE:-false}" != true ] &&
   [ "${NATIVE_GRAPH_ISSUANCE_V7_ENABLE:-false}" != 1 ]; then
  error "VERIFIER_GRAPH_ISSUANCE_ISSUER_URLS requires NATIVE_GRAPH_ISSUANCE_V7_ENABLE=true"
fi

if [ "${SERVICE_ROLE:-}" = verifier ]; then
  case ",${VERIFIER_ACCEPTED_TOKEN_VERSIONS:-}," in
    *,v4,* ) ;; *) error "verifier must accept V4 tokens" ;; esac
  case ",${VERIFIER_ACCEPTED_TOKEN_VERSIONS:-}," in
    *,v7,* ) ;; *) error "verifier must accept V7 native bearer tokens" ;; esac
fi

if [ "$errors" -ne 0 ]; then
  printf 'Configuration validation failed (%s error(s)).\n' "$errors" >&2
  exit 1
fi
printf 'Environment validation passed (%s mode; Redis required).\n' "$mode"
