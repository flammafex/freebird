#!/usr/bin/env sh
# SPDX-License-Identifier: Apache-2.0 OR MIT
set -eu

if [ "$#" -ne 2 ]; then
  printf 'usage: %s ISSUER_ENV_FILE VERIFIER_ENV_FILE\n' "$0" >&2
  exit 2
fi

issuer_env=$1
verifier_env=$2
errors=0

error() {
  printf 'ERROR: %s\n' "$1" >&2
  errors=$((errors + 1))
}

value_from_file() {
  file=$1
  name=$2
  line=$(grep -E "^[[:space:]]*${name}=" "$file" | awk 'END { print }' || true)
  if [ -z "$line" ]; then
    return 0
  fi
  value=${line#*=}
  case "$value" in
    \"*\") value=${value#\"}; value=${value%\"} ;;
    \'*\') value=${value#\'}; value=${value%\'} ;;
  esac
  printf '%s' "$value"
}

for file in "$issuer_env" "$verifier_env"; do
  [ -f "$file" ] || error "environment file does not exist: $file"
done
if [ "$errors" -ne 0 ]; then
  exit 1
fi

issuer_graph=$(value_from_file "$issuer_env" PUBLIC_BEARER_GRAPH_ISSUANCE_ENABLE)
issuer_graph=${issuer_graph:-false}
verifier_graph=$(value_from_file "$verifier_env" PUBLIC_BEARER_GRAPH_ISSUANCE_ENABLE)
verifier_graph=${verifier_graph:-false}
verifier_urls=$(value_from_file "$verifier_env" VERIFIER_GRAPH_ISSUANCE_ISSUER_URLS)
issuer_exchange=$(value_from_file "$issuer_env" PUBLIC_BEARER_EXCHANGE_ENABLE)
issuer_exchange=${issuer_exchange:-false}

case "$issuer_graph" in
  true|1|false|0) ;;
  *) error "issuer PUBLIC_BEARER_GRAPH_ISSUANCE_ENABLE must be true or false" ;;
esac
case "$verifier_graph" in
  true|1|false|0) ;;
  *) error "verifier PUBLIC_BEARER_GRAPH_ISSUANCE_ENABLE must be true or false" ;;
esac

if [ "$issuer_graph" = true ] || [ "$issuer_graph" = 1 ]; then
  if [ "$issuer_exchange" != true ] && [ "$issuer_exchange" != 1 ]; then
    error "issuer graph issuance requires PUBLIC_BEARER_EXCHANGE_ENABLE=true"
  fi
  if [ "$verifier_graph" != true ] && [ "$verifier_graph" != 1 ]; then
    error "graph-enabled issuer requires PUBLIC_BEARER_GRAPH_ISSUANCE_ENABLE=true in every participating verifier environment"
  fi
  [ -n "$verifier_urls" ] || error "graph-enabled issuer requires VERIFIER_GRAPH_ISSUANCE_ISSUER_URLS in the verifier environment"
  case "$verifier_urls" in
    https://*) ;;
    *) error "graph authority URLs must use the trusted HTTPS boundary" ;;
  esac
  case "$verifier_urls" in
    *http://*) error "graph authority URLs must use the trusted HTTPS boundary" ;;
  esac
  verifier_probe=$(value_from_file "$verifier_env" VERIFIER_REPLAY_AUTHORITY_PROBE_INTERVAL)
  verifier_stale=$(value_from_file "$verifier_env" VERIFIER_REPLAY_AUTHORITY_MAX_STALENESS)
  [ "${verifier_probe:-30s}" = 30s ] || error "VERIFIER_REPLAY_AUTHORITY_PROBE_INTERVAL must be 30s"
  [ "${verifier_stale:-60s}" = 60s ] || error "VERIFIER_REPLAY_AUTHORITY_MAX_STALENESS must be 60s"
else
  if [ "$verifier_graph" = true ] || [ "$verifier_graph" = 1 ]; then
    error "verifier graph issuance marker is enabled while issuer graph issuance is disabled"
  fi
  [ -z "$verifier_urls" ] || error "VERIFIER_GRAPH_ISSUANCE_ISSUER_URLS must be empty when issuer graph issuance is disabled"
fi

if [ "$errors" -ne 0 ]; then
  printf 'Graph deployment coupling validation failed (%s error(s)).\n' "$errors" >&2
  exit 1
fi
printf 'Graph deployment coupling validation passed.\n'
