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
if ! grep -q 'kind load docker-image "$KIND_ISSUER_IMAGE" "$KIND_VERIFIER_IMAGE"' "$smoke" || \
   ! grep -q 'issuer="\$KIND_ISSUER_IMAGE"' "$smoke" || \
   ! grep -q 'verifier="\$KIND_VERIFIER_IMAGE"' "$smoke" || \
   grep -q 'issuer="\$ISSUER_IMAGE"\|verifier="\$VERIFIER_IMAGE"' "$smoke"; then
  printf '%s\n' 'kind smoke workload images must match the explicitly loaded local image aliases' >&2
  exit 1
fi
if ! grep -q 'wrong-ca' "$smoke" || ! grep -q 'wrong CA was unexpectedly accepted' "$smoke" || \
   ! grep -q 'hostAliases' "$smoke" || ! grep -q 'https://issuer.freebird.test/readyz' "$smoke"; then
  printf '%s\n' 'kind smoke lacks wrong-CA negative validation or HTTPS hostname routing' >&2
  exit 1
fi
if grep -q 'proxy-headers\.yaml\|freebird-proxy-headers' "$smoke" || \
   ! grep -q 'proxy-set-headers":"","use-forwarded-headers":"false","compute-full-forwarded-for":"false"' "$smoke" || \
   ! grep -q 'PROXY_SET_HEADERS' "$smoke" || ! grep -q 'COMPUTE_FULL_FORWARDED_FOR' "$smoke"; then
  printf '%s\n' 'kind smoke must use exact built-in ingress forwarding settings without custom headers' >&2
  exit 1
fi
if ! grep -q 'subjectAltName=DNS:issuer\.freebird\.test,DNS:verifier\.freebird\.test' "$smoke" || \
   ! grep -q 'https://verifier\.freebird\.test/ready' "$smoke" || \
   grep -q 'http://verifier\.freebird\.test' "$smoke"; then
  printf '%s\n' 'kind smoke must use the exact two-host SAN and verified HTTPS verifier readiness' >&2
  exit 1
fi
for old_proxy_headers in \
  "$root/k8s/overlays/kind/proxy-headers.yaml" \
  "$root/k8s/overlays/production/proxy-headers.yaml"; do
  if [ -e "$old_proxy_headers" ]; then
    printf '%s\n' "custom proxy header ConfigMap must not be restored: $old_proxy_headers" >&2
    exit 1
  fi
done
if command -v kustomize >/dev/null 2>&1; then
  build=(kustomize build)
elif command -v kubectl >/dev/null 2>&1; then
  build=(kubectl kustomize)
else
  printf '%s\n' 'kustomize or kubectl is required' >&2
  exit 2
fi

for manifest in \
  "$root/k8s/base/issuer-deployment.yaml" \
  "$root/k8s/base/verifier-deployment.yaml"; do
  if grep -Eq 'ghcr\.io/flammafex/freebird-(issuer|verifier):0\.7\.0' "$manifest"; then
    printf '%s\n' "$manifest: historical 0.7.0 image must not be used for graph-capable deployment" >&2
    exit 1
  fi
done
if ! grep -q 'ghcr.io/flammafex/freebird-issuer@sha256:REQUIRED_ISSUER_IMAGE_DIGEST' \
    "$root/k8s/base/issuer-deployment.yaml" || \
   ! grep -q 'ghcr.io/flammafex/freebird-verifier@sha256:REQUIRED_VERIFIER_IMAGE_DIGEST' \
    "$root/k8s/base/verifier-deployment.yaml"; then
  printf '%s\n' 'base manifests must require operator-provided immutable image digests' >&2
  exit 1
fi

for duplicate in \
  namespace.yaml \
  rbac.yaml \
  redis-deployment.yaml \
  issuer-deployment.yaml \
  verifier-deployment.yaml \
  network-policy.yaml \
  ingress.yaml; do
  if [ -e "$root/k8s/$duplicate" ]; then
    printf '%s\n' "root kustomization must not restore deleted duplicate: k8s/$duplicate" >&2
    exit 1
  fi
done

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
  if grep -q 'freebird-proxy-headers\|X-Forwarded-Proto:\|X-Forwarded-For:\|X-Forwarded-Host:\|X-Forwarded-Port:' "$output"; then
    printf '%s\n' "$name: custom standard forwarded-header ConfigMap is forbidden" >&2
    return 1
  fi
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
  if grep -q 'PUBLIC_BEARER_EXCHANGE_PROFILE_PATH\|PUBLIC_BEARER_EXCHANGE_RETAINED_PROFILE_PATHS\|PUBLIC_BEARER_EXCHANGE_RECEIPT_KEY_PATH\|PUBLIC_BEARER_GRAPH_ISSUANCE_V4_REPLAY_REDIS_URL' "$output"; then
    printf '%s\n' "$name: obsolete V1 graph/exchange configuration is present" >&2
    return 1
  fi
  if ! grep -q '/v1/public/graph/replay-authority/probe' "$output"; then
    printf '%s\n' "$name: V2 replay-authority probe route is not exposed" >&2
    return 1
  fi
  if ! grep -q 'VERIFIER_REPLAY_AUTHORITY_PROBE_INTERVAL: 30s' "$output" || \
     ! grep -q 'VERIFIER_REPLAY_AUTHORITY_MAX_STALENESS: 60s' "$output"; then
    printf '%s\n' "$name: frozen 30s/60s replay-authority health settings are missing" >&2
    return 1
  fi
}

config_value() {
  local output=$1 config_name=$2 key=$3
  awk -v config_name="$config_name" -v key="$key" '
    /^kind: ConfigMap$/ { in_cm=1; selected=0 }
    in_cm && $0 == "  name: " config_name { selected=1; next }
    selected && $0 ~ ("^  " key ":") {
      sub("^  " key ": ?", "")
      gsub(/^"|"$/, "")
      print
      exit
    }
    selected && /^---$/ { exit }
  ' "$output"
}

check_graph_coupling() {
  local name=$1 output=$2
  # The production template intentionally carries unresolved operator choices.
  # Validate the rendered fixtures instead of guessing those choices here.
  if grep -q 'REQUIRED_GRAPH_ISSUANCE_' "$output"; then
    return 0
  fi
  local issuer_graph verifier_graph issuer_exchange verifier_urls
  issuer_graph=$(config_value "$output" issuer-config PUBLIC_BEARER_GRAPH_ISSUANCE_ENABLE)
  verifier_graph=$(config_value "$output" verifier-config PUBLIC_BEARER_GRAPH_ISSUANCE_ENABLE)
  issuer_exchange=$(config_value "$output" issuer-config PUBLIC_BEARER_EXCHANGE_ENABLE)
  verifier_urls=$(config_value "$output" verifier-config VERIFIER_GRAPH_ISSUANCE_ISSUER_URLS)
  if [ "$issuer_graph" = true ] || [ "$issuer_graph" = "1" ]; then
    [ "$issuer_exchange" = true ] || [ "$issuer_exchange" = "1" ] || {
      printf '%s\n' "$name: graph issuance requires exchange enabled" >&2
      return 1
    }
    [ "$verifier_graph" = true ] || [ "$verifier_graph" = "1" ] || {
      printf '%s\n' "$name: graph-enabled issuer is not coupled to the verifier marker" >&2
      return 1
    }
    [ -n "$verifier_urls" ] || {
      printf '%s\n' "$name: graph-enabled issuer has no verifier authority URL" >&2
      return 1
    }
    case "$verifier_urls" in
      https://*) ;;
      *)
        printf '%s\n' "$name: graph authority URL must use HTTPS" >&2
        return 1
        ;;
    esac
  else
    [ "$verifier_graph" = false ] || [ -z "$verifier_graph" ] || {
      printf '%s\n' "$name: verifier graph marker is enabled while issuer graph issuance is disabled" >&2
      return 1
    }
    [ -z "$verifier_urls" ] || {
      printf '%s\n' "$name: verifier graph authority URL is set while graph issuance is disabled" >&2
      return 1
    }
  fi
}

check_service_contract() {
  local name=$1 output=$2 service=$3 component=$4 port=$5 probe=$6
  if ! awk -v wanted="$service" -v expected_component="$component" \
    -v expected_port="$port" -v probe="$probe" '
    function reset() {
      kind_service=0
      selected=0
      publish_fields=0
      publish_true=0
      type_count=0
      app_count=0
      component_count=0
      port_count=0
      port_name_count=0
      target_count=0
    }
    function finish() {
      if (!selected) {
        reset()
        return
      }
      matched++
      if (probe) {
        if (publish_fields != 1 || publish_true != 1 || type_count != 1 ||
            app_count != 1 || component_count != 1 || port_count != 1 ||
            port_name_count != 1 || target_count != 1) {
          invalid++
        }
      } else if (publish_fields != 0) {
        invalid++
      }
      reset()
    }
    BEGIN { reset() }
    /^---$/ { finish(); next }
    /^kind: Service$/ { kind_service=1; next }
    kind_service && /^  name: / {
      if ($0 == "  name: " wanted) selected=1
      next
    }
    selected && /^  publishNotReadyAddresses:/ {
      publish_fields++
      if ($0 == "  publishNotReadyAddresses: true") publish_true++
      next
    }
    selected && /^  type: ClusterIP$/ { type_count++; next }
    selected && /^    app: freebird$/ { app_count++; next }
    selected && $0 == "    component: " expected_component { component_count++; next }
    selected && $0 ~ /^    port: / {
      if ($0 == "    port: " expected_port) port_count++
      next
    }
    selected && /^  - name: http$/ { port_name_count++; next }
    selected && /^    targetPort: http$/ { target_count++; next }
    END {
      finish()
      exit !(matched == 1 && invalid == 0)
    }
  ' "$output"; then
    printf '%s\n' "$name: service $service has an invalid probe/publishNotReadyAddresses contract" >&2
    return 1
  fi
}

route_backend_status() {
  local output=$1 wanted=$2 expected=$3
  awk -v wanted="$wanted" -v expected="$expected" '
    BEGIN { in_route=0; matches=0; correct=0 }
    /^      - backend:$/ { in_route=1; service=""; next }
    in_route && /^            name: / { service=$2; next }
    in_route && /^        path: / {
      if ($2 == wanted) {
        matches++
        if (service == expected) correct++
      }
      in_route=0
      next
    }
    END {
      if (matches == 1 && correct == 1) exit 0
      if (matches == 0) exit 2
      exit 1
    }
  ' "$output"
}

check_route_backend() {
  local name=$1 output=$2 route=$3 service=$4 required=$5 status
  if route_backend_status "$output" "$route" "$service"; then
    return 0
  else
    status=$?
  fi
  if [ "$required" = optional ] && [ "$status" -eq 2 ]; then
    return 0
  fi
  printf '%s\n' "$name: route $route does not target the expected $service service" >&2
  return 1
}

check_probe_contract() {
  local name=$1 output=$2
  check_service_contract "$name" "$output" issuer issuer 8081 0
  check_service_contract "$name" "$output" verifier verifier 8082 0
  check_service_contract "$name" "$output" issuer-probe issuer 8081 1
  check_service_contract "$name" "$output" verifier-probe verifier 8082 1

  check_route_backend "$name" "$output" /healthz issuer-probe required
  check_route_backend "$name" "$output" /readyz issuer-probe required
  check_route_backend "$name" "$output" /health verifier-probe required
  check_route_backend "$name" "$output" /ready verifier-probe required

  for route in \
    /.well-known/issuer \
    /.well-known/keys \
    /v1/oprf \
    /v1/public \
    /v1/public/graph/replay-authority/probe \
    /webauthn \
    /admin; do
    check_route_backend "$name" "$output" "$route" issuer optional
  done
  for route in /.well-known/verifier /v1/verify /v1/verify/batch /v1/check; do
    check_route_backend "$name" "$output" "$route" verifier optional
  done
  printf '%s\n' "validated $name probe services and ingress backends"
}

root_output=$(mktemp)
base_output=$(mktemp)
kind_output=$(mktemp)
production_output=$(mktemp)
fixture_output=$(mktemp)
graph_fixture_output=$(mktemp)
trap 'rm -f "$root_output" "$base_output" "$kind_output" "$production_output" "$fixture_output" "$graph_fixture_output"' EXIT

"${build[@]}" "$root/k8s" >"$root_output"
"${build[@]}" "$root/k8s/base" >"$base_output"
if ! cmp -s "$base_output" "$root_output"; then
  printf '%s\n' 'root and base renders differ' >&2
  diff -u "$base_output" "$root_output" >&2 || true
  exit 1
fi
printf '%s\n' 'validated root and base renders are byte-identical'
check_probe_contract root "$root_output"
check_probe_contract base "$base_output"

"${build[@]}" "$root/k8s/overlays/kind" >"$kind_output"
common_checks kind "$kind_output"
check_graph_coupling kind "$kind_output"
check_probe_contract kind "$kind_output"
if grep -q 'REQUIRED_' "$kind_output"; then
  printf '%s\n' 'kind overlay contains unresolved values' >&2
  exit 1
fi
if ! grep -q 'image: freebird-issuer:kind-smoke' "$kind_output" || \
   ! grep -q 'image: freebird-verifier:kind-smoke' "$kind_output"; then
  printf '%s\n' 'kind overlay does not use explicit local smoke image overrides' >&2
  exit 1
fi
printf '%s\n' 'validated kind overlay'

if ! grep -q 'ingress-nginx-controller\.ingress-nginx\.svc\.cluster\.local:443' "$kind_output"; then
  printf '%s\n' 'kind: readiness does not use the configured HTTPS proxy service and port' >&2
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
if ! grep -q -- '--appendfsync' "$kind_output" || \
   ! grep -q -- 'always' "$kind_output" || \
   ! grep -q -- 'noeviction' "$kind_output"; then
  printf '%s\n' 'kind: Redis authority durability settings are incomplete' >&2
  exit 1
fi
if ! grep -q 'name: allow-kind-health-to-proxy' "$kind_output" || \
   ! grep -A20 'name: allow-kind-health-to-proxy' "$kind_output" | grep -q 'port: 443' || \
   grep -A20 'name: allow-kind-health-to-proxy' "$kind_output" | grep -q 'port: 80'; then
  printf '%s\n' 'kind: health pod lacks explicit HTTPS ingress egress policy' >&2
  exit 1
fi
if ! grep -q 'name: allow-proxy-boundary-probes' "$kind_output" || \
   ! grep -A20 'name: allow-proxy-boundary-probes' "$kind_output" | grep -q 'port: 443' || \
   grep -A20 'name: allow-proxy-boundary-probes' "$kind_output" | grep -q 'port: 80'; then
  printf '%s\n' 'kind: probe egress policy must use HTTPS port 443 only' >&2
  exit 1
fi
verifier_ingress=$(awk '
  /^kind: Ingress$/ { in_block=1; block=$0 ORS; next }
  in_block {
    block=block $0 ORS
    if (/^---$/) {
      if (block ~ /name: verifier-ingress/) {
        printf "%s", block
        exit
      }
      in_block=0
      block=""
    }
  }
' "$kind_output")
if ! grep -q 'nginx.ingress.kubernetes.io/ssl-redirect: "true"' <<<"$verifier_ingress" || \
   ! grep -q 'secretName: issuer-tls-cert' <<<"$verifier_ingress" || \
   ! grep -q 'verifier.freebird.test' <<<"$verifier_ingress"; then
  printf '%s\n' 'kind: verifier ingress must use the temporary HTTPS TLS Secret and redirect' >&2
  exit 1
fi
if grep -q 'http://verifier\.freebird\.test\|verifier\.freebird\.test:80' "$kind_output"; then
  printf '%s\n' 'kind: verifier readiness must not use HTTP port 80' >&2
  exit 1
fi

"${build[@]}" "$root/k8s/overlays/production" >"$production_output"
common_checks production-template "$production_output"
if ! grep -q 'REQUIRED_' "$production_output"; then
  printf '%s\n' 'production template unexpectedly has no required-value markers' >&2
  exit 1
fi
if ! grep -q 'freebird-issuer@sha256:REQUIRED_ISSUER_IMAGE_DIGEST' "$production_output" || \
   ! grep -q 'freebird-verifier@sha256:REQUIRED_VERIFIER_IMAGE_DIGEST' "$production_output"; then
  printf '%s\n' 'production template does not require operator-provided immutable GHCR image digests' >&2
  exit 1
fi
check_probe_contract production-template "$production_output"
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
  -e 's/REQUIRED_ISSUER_IMAGE_DIGEST/fixture-not-a-registry-digest/g' \
  -e 's/REQUIRED_VERIFIER_IMAGE_DIGEST/fixture-not-a-registry-digest/g' \
  -e 's/REQUIRED_GRAPH_ISSUANCE_ENABLED/false/g' \
  -e 's/REQUIRED_GRAPH_ISSUANCE_EXCHANGE_ENABLED/false/g' \
  -e 's/REQUIRED_GRAPH_ISSUANCE_ISSUER_URLS//g' \
  "$production_output" >"$fixture_output"
if grep -q 'REQUIRED_' "$fixture_output"; then
  printf '%s\n' 'production fixture contains unresolved values' >&2
  exit 1
fi
common_checks production-fixture "$fixture_output"
check_graph_coupling production-fixture "$fixture_output"
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

# Also exercise the enabled relationship without claiming a real registry
# digest. These are representative manifest values only.
sed -e 's/REQUIRED_PUBLIC_ISSUER_HOST/issuer.fixture.invalid/g' \
  -e 's/REQUIRED_PUBLIC_VERIFIER_HOST/verifier.fixture.invalid/g' \
  -e 's/REQUIRED_ISSUER_ADMIN_HOST/admin.fixture.invalid/g' \
  -e 's/REQUIRED_OPERATOR_CIDR/192.0.2.10\/32/g' \
  -e 's/REQUIRED_INGRESS_SOURCE_CIDR/192.0.2.10\/32/g' \
  -e 's/REQUIRED_PROXY_SERVICE_NAME/ingress-nginx-controller/g' \
  -e "s/REQUIRED_PROXY_NAMESPACE/${proxy_namespace}/g" \
  -e 's/REQUIRED_PROXY_COMPONENT_LABEL/controller/g' \
  -e 's/REQUIRED_ISSUER_IMAGE_DIGEST/fixture-not-a-registry-digest/g' \
  -e 's/REQUIRED_VERIFIER_IMAGE_DIGEST/fixture-not-a-registry-digest/g' \
  -e 's/REQUIRED_GRAPH_ISSUANCE_ENABLED/true/g' \
  -e 's/REQUIRED_GRAPH_ISSUANCE_EXCHANGE_ENABLED/true/g' \
  -e 's#REQUIRED_GRAPH_ISSUANCE_ISSUER_URLS#https://issuer.fixture.invalid#g' \
  "$production_output" >"$graph_fixture_output"
if grep -q 'REQUIRED_' "$graph_fixture_output"; then
  printf '%s\n' 'graph production fixture contains unresolved values' >&2
  exit 1
fi
common_checks graph-production-fixture "$graph_fixture_output"
check_graph_coupling graph-production-fixture "$graph_fixture_output"
printf '%s\n' 'validated graph-enabled production coupling fixture'
