#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
smoke="$root/scripts/release-kind-smoke.sh"
if grep -q 'REQUIRE_TLS.*false' "$smoke"; then
  printf '%s\n' 'kind smoke must not disable REQUIRE_TLS' >&2
  exit 1
fi
if ! grep -q 'openssl rand' "$smoke" || ! grep -q 'VERIFIER_SK_B64' "$smoke" || \
   ! grep -q 'issuer-v4-key' "$smoke"; then
  printf '%s\n' 'kind smoke does not provision matching explicit V4 key material' >&2
  exit 1
fi
if grep -q -- '--insecure\|curl[^\n]* -k' "$smoke"; then
  printf '%s\n' 'kind smoke contains an insecure TLS bypass' >&2
  exit 1
fi
if ! grep -q 'issuer-ca\.crt' "$smoke" || ! grep -q 'issuer-tls-cert' "$smoke"; then
  printf '%s\n' 'kind smoke does not provision the ephemeral issuer CA and TLS Secret' >&2
  exit 1
fi
if ! grep -q 'wrong-ca' "$smoke" || ! grep -q 'wrong CA was unexpectedly accepted' "$smoke" || \
   ! grep -q 'hostAliases' "$smoke" || ! grep -q 'https://issuer.freebird.test/readyz' "$smoke"; then
  printf '%s\n' 'kind smoke lacks wrong-CA negative validation or HTTPS hostname routing' >&2
  exit 1
fi
if command -v kustomize >/dev/null 2>&1; then
  build=(kustomize build)
elif command -v kubectl >/dev/null 2>&1; then
  build=(kubectl kustomize)
else
  printf '%s\n' 'kustomize or kubectl is required' >&2
  exit 2
fi

common_checks() {
  local name=$1 output=$2
  if grep -q '10\.244\.0\.0/16\|172\.18\.0\.0/16' "$output"; then
    printf '%s\n' "$name: broad assumed network trust is forbidden" >&2
    return 1
  fi
  grep -q 'livenessProbe:' "$output" && grep -q 'tcpSocket:' "$output" || {
    printf '%s\n' "$name: process-local TCP liveness probe missing" >&2
    return 1
  }
  if grep -q 'configuration-snippet\|server-snippet' "$output"; then
    printf '%s\n' "$name: unsafe ingress snippet annotation present" >&2
    return 1
  fi
  if grep -q 'CHANGE_ME\|secrets-template' "$output"; then
    printf '%s\n' "$name: placeholder secret template is deployable" >&2
    return 1
  fi
  if grep -q 'name: verifier-lb\|type: LoadBalancer' "$output"; then
    printf '%s\n' "$name: direct public verifier LoadBalancer exposure is forbidden" >&2
    return 1
  fi
  if grep -q 'use-forwarded-headers:.*true' "$output"; then
    printf '%s\n' "$name: unconstrained forwarded-header trust is forbidden" >&2
    return 1
  fi
  grep -q 'X-Forwarded-Proto: https' "$output" || {
    printf '%s\n' "$name: proxy must emit HTTPS forwarded-proto semantics" >&2
    return 1
  }
  grep -q 'X-Forwarded-For: \$remote_addr' "$output" || {
    printf '%s\n' "$name: proxy must overwrite X-Forwarded-For" >&2
    return 1
  }
  if grep -A40 'name: verifier-ingress' "$output" | grep -q '/admin'; then
    printf '%s\n' "$name: verifier admin route is public" >&2
    return 1
  fi
  for route in /healthz /readyz /health /ready; do
    if ! grep -q "path: $route" "$output"; then
      printf '%s\n' "$name: ingress route $route is missing" >&2
      return 1
    fi
  done
}

kind_output=$(mktemp)
production_output=$(mktemp)
fixture_output=$(mktemp)
trap 'rm -f "$kind_output" "$production_output" "$fixture_output"' EXIT

"${build[@]}" "$root/k8s/overlays/kind" >"$kind_output"
common_checks kind "$kind_output"
if grep -q 'REQUIRED_' "$kind_output"; then
  printf '%s\n' 'kind overlay contains unresolved values' >&2
  exit 1
fi
if ! grep -A3 'name: freebird-proxy-headers' "$kind_output" | grep -q 'namespace: ingress-nginx'; then
  printf '%s\n' 'kind: proxy-header ConfigMap namespace is inconsistent with the provider' >&2
  exit 1
fi
printf '%s\n' 'validated kind overlay'

if ! grep -q 'ingress-nginx-controller\.ingress-nginx\.svc\.cluster\.local:80' "$kind_output"; then
  printf '%s\n' 'kind: readiness does not use the configured proxy service and port' >&2
  exit 1
fi
if ! grep -q 'issuer\.freebird\.test/readyz' "$kind_output" || \
   ! grep -q 'verifier\.freebird\.test/ready' "$kind_output"; then
  printf '%s\n' 'kind: readiness probes do not use the aligned ingress endpoints' >&2
  exit 1
fi
if ! grep -q 'ISSUER_URL: https://issuer\.freebird\.test/\.well-known/issuer' "$kind_output" || \
   ! grep -q 'secretName: issuer-tls-cert' "$kind_output" || \
   ! grep -q 'SSL_CERT_FILE' "$kind_output" || \
   ! grep -q 'secretName: issuer-ci-ca' "$kind_output" || \
   ! grep -q 'issuer.freebird.test' "$kind_output"; then
  printf '%s\n' 'kind: HTTPS issuer metadata CA/TLS wiring is incomplete' >&2
  exit 1
fi
if ! grep -q 'VERIFIER_ACCEPTED_TOKEN_VERSIONS: v4' "$kind_output"; then
  printf '%s\n' 'kind: V4 token family is not explicitly configured' >&2
  exit 1
fi
if ! grep -q 'name: allow-kind-health-to-proxy' "$kind_output" || \
   ! grep -A30 'name: allow-kind-health-to-proxy' "$kind_output" | grep -q 'port: 443'; then
  printf '%s\n' 'kind: health pod lacks explicit HTTPS ingress egress policy' >&2
  exit 1
fi
if ! grep -q 'name: allow-proxy-boundary-probes' "$kind_output" || \
   ! grep -A25 'name: allow-proxy-boundary-probes' "$kind_output" | grep -q 'port: 80'; then
  printf '%s\n' 'kind: probe egress policy is inconsistent with readiness proxy port' >&2
  exit 1
fi

"${build[@]}" "$root/k8s/overlays/production" >"$production_output"
common_checks production-template "$production_output"
if ! grep -q 'REQUIRED_' "$production_output"; then
  printf '%s\n' 'production template unexpectedly has no required-value markers' >&2
  exit 1
fi
if ! grep -A3 'name: freebird-proxy-headers' "$production_output" | grep -q 'namespace: REQUIRED_PROXY_NAMESPACE'; then
  printf '%s\n' 'production: proxy-header ConfigMap namespace is not parameterized' >&2
  exit 1
fi
printf '%s\n' 'validated production template fails closed on unresolved values'

# Validate the rendered production shape independently with representative,
# non-production fixture values. This does not alter checked-in manifests.
proxy_namespace=ingress-nginx
sed -e 's/REQUIRED_PUBLIC_ISSUER_HOST/issuer.fixture.invalid/g' \
  -e 's/REQUIRED_PUBLIC_VERIFIER_HOST/verifier.fixture.invalid/g' \
  -e 's/REQUIRED_ISSUER_ADMIN_HOST/admin.fixture.invalid/g' \
  -e 's/REQUIRED_OPERATOR_CIDR/192.0.2.10\/32/g' \
  -e 's/REQUIRED_INGRESS_SOURCE_CIDR/192.0.2.10\/32/g' \
  -e 's/REQUIRED_PROXY_SERVICE_NAME/ingress-nginx-controller/g' \
  -e "s/REQUIRED_PROXY_NAMESPACE/${proxy_namespace}/g" \
  -e 's/REQUIRED_PROXY_COMPONENT_LABEL/controller/g' \
  "$production_output" >"$fixture_output"
if grep -q 'REQUIRED_' "$fixture_output"; then
  printf '%s\n' 'production fixture contains unresolved values' >&2
  exit 1
fi
common_checks production-fixture "$fixture_output"
if ! grep -A3 'name: freebird-proxy-headers' "$fixture_output" | grep -q "namespace: $proxy_namespace"; then
  printf '%s\n' 'production fixture: proxy-header ConfigMap namespace is inconsistent' >&2
  exit 1
fi
if ! grep -q 'ingress-nginx-controller\.ingress-nginx\.svc\.cluster\.local:443' "$fixture_output" || \
   ! grep -A25 'name: allow-proxy-boundary-probes' "$fixture_output" | grep -q 'port: 443'; then
  printf '%s\n' 'production: probe service wiring is inconsistent with fixed HTTPS port' >&2
  exit 1
fi
if ! grep -q 'issuer\.fixture\.invalid/readyz' "$fixture_output" || \
   ! grep -q 'verifier\.fixture\.invalid/ready' "$fixture_output"; then
  printf '%s\n' 'production: readiness probes do not use the aligned ingress endpoints' >&2
  exit 1
fi
printf '%s\n' 'validated rendered production fixture'
