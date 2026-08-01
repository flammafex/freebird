#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
set -euo pipefail

: "${ISSUER_IMAGE:?set ISSUER_IMAGE to an immutable local image tag}"
: "${VERIFIER_IMAGE:?set VERIFIER_IMAGE to an immutable local image tag}"
KIND_VERSION="v0.23.0"
# ingress-nginx v1.15.1, pinned to the immutable reviewed commit below.
INGRESS_VERSION="v1.15.1"
INGRESS_COMMIT="0a5901f3c64f11e92e487799b8da3f00cca37515"
INGRESS_READY_TIMEOUT="${INGRESS_READY_TIMEOUT:-600s}"
CLUSTER="freebird-release-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}"
CLUSTER_OWNED=false
TMP="$(mktemp -d)"
cleanup() {
  if [[ "$CLUSTER_OWNED" == true ]]; then
    kubectl --context "kind-$CLUSTER" --request-timeout=15s get pods -A -o wide || true
    kubectl --context "kind-$CLUSTER" --request-timeout=15s describe deployment issuer verifier -n freebird || true
    kubectl --context "kind-$CLUSTER" --request-timeout=15s logs -n freebird -l app=freebird,component=issuer --all-containers=true --prefix=true --tail=100 || true
    kubectl --context "kind-$CLUSTER" --request-timeout=15s logs -n freebird -l app=freebird,component=verifier --all-containers=true --prefix=true --tail=100 || true
    kubectl --context "kind-$CLUSTER" --request-timeout=15s logs issuer-metadata -n freebird --all-containers=true --tail=100 || true
    kubectl --context "kind-$CLUSTER" --request-timeout=15s logs health -n freebird --tail=100 || true
    kubectl --context "kind-$CLUSTER" --request-timeout=15s get events -A --sort-by=.lastTimestamp || true
    python3 - "$CLUSTER" <<'PY' || true
import os
import signal
import subprocess
import sys


cluster = sys.argv[1]
process = subprocess.Popen(
    ["kind", "delete", "cluster", "--name", cluster],
    start_new_session=True,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
try:
    process.wait(timeout=30)
except subprocess.TimeoutExpired:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)
PY
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT

case "$(uname -s)" in
  Linux) KIND_OS=linux ;;
  Darwin) KIND_OS=darwin ;;
  *) printf 'ERROR: unsupported kind host OS: %s\n' "$(uname -s)" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) KIND_ARCH=amd64 ;;
  arm64|aarch64) KIND_ARCH=arm64 ;;
  *) printf 'ERROR: unsupported kind host architecture: %s\n' "$(uname -m)" >&2; exit 1 ;;
esac
KIND_ARTIFACT="kind-${KIND_OS}-${KIND_ARCH}"
curl -fsSL "https://kind.sigs.k8s.io/dl/${KIND_VERSION}/${KIND_ARTIFACT}" -o "$TMP/kind"
chmod 755 "$TMP/kind"
export PATH="$TMP:$PATH"
kind create cluster --name "$CLUSTER" --wait 90s
CLUSTER_OWNED=true

# Pin the official kind provider to the reviewed ingress-nginx commit. Extract
# the digest-pinned image references from that exact manifest and preload them
# into every kind node through its CRI before applying the workload. This avoids
# Docker Desktop's separate host/containerd image stores and pod-admission pulls.
INGRESS_MANIFEST="$TMP/ingress-nginx.yaml"
INGRESS_APPLY_MANIFEST="$TMP/ingress-nginx-apply.yaml"
INGRESS_MANIFEST_URL="https://raw.githubusercontent.com/kubernetes/ingress-nginx/${INGRESS_COMMIT}/deploy/static/provider/kind/deploy.yaml"
curl -fsSL "$INGRESS_MANIFEST_URL" -o "$INGRESS_MANIFEST"
INGRESS_CONTROLLER_IMAGE="$(awk '/image: registry.k8s.io\/ingress-nginx\/controller:/ {print $2; exit}' "$INGRESS_MANIFEST")"
INGRESS_CERTGEN_IMAGE="$(awk '/image: registry.k8s.io\/ingress-nginx\/kube-webhook-certgen:/ {print $2; exit}' "$INGRESS_MANIFEST")"
[[ $INGRESS_CONTROLLER_IMAGE == *@sha256:* && $INGRESS_CERTGEN_IMAGE == *@sha256:* ]] || { printf 'ERROR: reviewed ingress manifest did not contain digest-pinned images\n' >&2; exit 1; }
KIND_NODES="$(kind get nodes --name "$CLUSTER")"
: "${KIND_NODES:?could not determine Kind nodes}"
while IFS= read -r node; do
  [[ -n "$node" ]] || continue
  docker exec "$node" crictl pull "$INGRESS_CONTROLLER_IMAGE"
  docker exec "$node" crictl inspecti "$INGRESS_CONTROLLER_IMAGE" >/dev/null
  docker exec "$node" crictl pull "$INGRESS_CERTGEN_IMAGE"
  docker exec "$node" crictl inspecti "$INGRESS_CERTGEN_IMAGE" >/dev/null
done <<< "$KIND_NODES"

python3 - "$INGRESS_MANIFEST" "$INGRESS_APPLY_MANIFEST" \
  "$INGRESS_CONTROLLER_IMAGE" "$INGRESS_CERTGEN_IMAGE" <<'PY'
from pathlib import Path
import re
import sys


source_path = Path(sys.argv[1])
output_path = Path(sys.argv[2])
controller_image = sys.argv[3].encode("utf-8")
certgen_image = sys.argv[4].encode("utf-8")
source = source_path.read_bytes()
policy = re.compile(rb"(?m)^[ \t]*imagePullPolicy: IfNotPresent[ \t]*$")

input_policy_count = len(policy.findall(source))
if input_policy_count != 3:
    raise SystemExit(f"expected exactly 3 IfNotPresent entries, found {input_policy_count}")

transformed = policy.sub(
    lambda match: match.group(0).replace(b"IfNotPresent", b"Never"), source
)
output_policy = re.compile(rb"(?m)^[ \t]*imagePullPolicy: Never[ \t]*$")
output_policy_count = len(output_policy.findall(transformed))
if output_policy_count != 3:
    raise SystemExit(f"expected exactly 3 Never entries, found {output_policy_count}")
if b"imagePullPolicy: IfNotPresent" in transformed or b"imagePullPolicy: Always" in transformed:
    raise SystemExit("transformed ingress manifest contains a forbidden image pull policy")


def image_lines(document: bytes, image: bytes) -> list[bytes]:
    expected = b"image: " + image
    return [line for line in document.splitlines(keepends=True) if line.strip() == expected]


for label, image in (("controller", controller_image), ("certgen", certgen_image)):
    if b"@sha256:" not in image:
        raise SystemExit(f"{label} image is not digest-pinned")
    source_image_lines = image_lines(source, image)
    output_image_lines = image_lines(transformed, image)
    if not source_image_lines or output_image_lines != source_image_lines:
        raise SystemExit(f"{label} image lines changed during policy transformation")

output_path.write_bytes(transformed)
PY
kubectl apply -f "$INGRESS_APPLY_MANIFEST"
kubectl -n ingress-nginx wait --for=condition=ready pod \
  -l app.kubernetes.io/component=controller --timeout="$INGRESS_READY_TIMEOUT"
kubectl -n ingress-nginx patch configmap ingress-nginx-controller --type merge \
  -p '{"data":{"proxy-set-headers":"","use-forwarded-headers":"false","compute-full-forwarded-for":"false"}}'
PROXY_SET_HEADERS="$(kubectl -n ingress-nginx get configmap ingress-nginx-controller -o jsonpath='{.data.proxy-set-headers}')"
USE_FORWARDED_HEADERS="$(kubectl -n ingress-nginx get configmap ingress-nginx-controller -o jsonpath='{.data.use-forwarded-headers}')"
COMPUTE_FULL_FORWARDED_FOR="$(kubectl -n ingress-nginx get configmap ingress-nginx-controller -o jsonpath='{.data.compute-full-forwarded-for}')"
[[ -z "$PROXY_SET_HEADERS" && "$USE_FORWARDED_HEADERS" == "false" && \
   "$COMPUTE_FULL_FORWARDED_FOR" == "false" ]] || {
  printf 'ERROR: ingress controller forwarding settings are not exact\n' >&2
  exit 1
}
kubectl -n ingress-nginx rollout restart deployment ingress-nginx-controller
kubectl -n ingress-nginx rollout status deployment/ingress-nginx-controller --timeout="$INGRESS_READY_TIMEOUT"

# Discover the source address after the controller and its networking exist.
# A /32 avoids assuming the kind node or pod network in application config.
PROXY_IP="$(kubectl -n ingress-nginx get pod -l app.kubernetes.io/component=controller \
  -o jsonpath='{.items[0].status.podIP}')"
: "${PROXY_IP:?could not determine ingress controller pod IP}"
TRUSTED_PROXY_CIDR="${PROXY_IP}/32"

# The kind overlay intentionally contains non-release local placeholders rather
# than an historical GHCR tag. Retag the operator-provided immutable test
# images to those placeholders before applying the workload.
KIND_ISSUER_IMAGE="freebird-issuer:kind-smoke"
KIND_VERIFIER_IMAGE="freebird-verifier:kind-smoke"
if [[ "$ISSUER_IMAGE" != "$KIND_ISSUER_IMAGE" ]]; then
  docker tag "$ISSUER_IMAGE" "$KIND_ISSUER_IMAGE"
fi
if [[ "$VERIFIER_IMAGE" != "$KIND_VERIFIER_IMAGE" ]]; then
  docker tag "$VERIFIER_IMAGE" "$KIND_VERIFIER_IMAGE"
fi
kind load docker-image "$KIND_ISSUER_IMAGE" "$KIND_VERIFIER_IMAGE" --name "$CLUSTER"
kubectl apply -f k8s/base/namespace.yaml -f k8s/base/rbac.yaml
kubectl create secret generic admin-credentials --namespace freebird \
  --from-literal=admin-api-key=release-smoke-admin-key-01234567890123456789
kubectl create secret generic redis-credentials --namespace freebird \
  --from-literal=password=release-smoke-redis-password
openssl genrsa -out "$TMP/issuer-ca.key" 2048
openssl req -x509 -new -nodes -key "$TMP/issuer-ca.key" \
  -sha256 -days 1 -out "$TMP/issuer-ca.crt" \
  -subj "/CN=freebird-kind-ci-ca"
openssl req -new -newkey rsa:2048 -nodes \
  -keyout "$TMP/issuer-tls.key" -out "$TMP/issuer-tls.csr" \
  -subj "/CN=issuer.freebird.test"
cat >"$TMP/issuer-san.ext" <<'EOF'
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
subjectAltName=DNS:issuer.freebird.test,DNS:verifier.freebird.test
EOF
openssl x509 -req -in "$TMP/issuer-tls.csr" \
  -CA "$TMP/issuer-ca.crt" -CAkey "$TMP/issuer-ca.key" -CAcreateserial \
  -out "$TMP/issuer-tls.crt" -days 1 -sha256 -extfile "$TMP/issuer-san.ext"
kubectl create secret tls issuer-tls-cert -n freebird \
  --cert="$TMP/issuer-tls.crt" --key="$TMP/issuer-tls.key"
kubectl create secret generic issuer-ci-ca -n freebird \
  --from-file=ca.crt="$TMP/issuer-ca.crt"
openssl genrsa -out "$TMP/wrong-ca.key" 2048
openssl req -x509 -new -nodes -key "$TMP/wrong-ca.key" \
  -sha256 -days 1 -out "$TMP/wrong-ca.crt" \
  -subj "/CN=wrong-freebird-kind-ca"
kubectl create secret generic issuer-wrong-ca -n freebird \
  --from-file=ca.crt="$TMP/wrong-ca.crt"
openssl rand -out "$TMP/issuer_sk.bin" 32
VERIFIER_SK_B64="$(base64 < "$TMP/issuer_sk.bin" | tr -d '\n=' | tr '+/' '-_')"
kubectl create secret generic verifier-keys --namespace freebird \
  --from-literal=verifier-sk-b64="$VERIFIER_SK_B64" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl create secret generic issuer-v4-key --namespace freebird \
  --from-file=issuer_sk.bin="$TMP/issuer_sk.bin"
kubectl apply -f - <<'YAML'
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: issuer-data
  namespace: freebird
spec:
  accessModes: [ReadWriteOnce]
  resources:
    requests:
      storage: 20Gi
YAML
kubectl apply -f - <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: issuer-key-seed
  namespace: freebird
spec:
  restartPolicy: Never
  securityContext:
    runAsUser: 1000
    runAsGroup: 1000
    fsGroup: 1000
  containers:
    - name: seed
      image: alpine:3.20
      command: ["sh", "-c", "mkdir -p /data/keys /data/state && cp /key/issuer_sk.bin /data/keys/issuer_sk.bin && chmod 600 /data/keys/issuer_sk.bin"]
      volumeMounts:
        - name: data
          mountPath: /data
        - name: key
          mountPath: /key
          readOnly: true
  volumes:
    - name: data
      persistentVolumeClaim:
        claimName: issuer-data
    - name: key
      secret:
        secretName: issuer-v4-key
YAML
kubectl wait --for=jsonpath='{.status.phase}'=Succeeded pod/issuer-key-seed -n freebird --timeout=120s
kubectl delete pod issuer-key-seed -n freebird --wait=true
kubectl delete secret issuer-v4-key -n freebird --wait=true
kubectl apply --dry-run=server -k k8s/overlays/kind >/dev/null
kubectl apply -k k8s/overlays/kind
kubectl -n freebird scale deployment/verifier --replicas=0
kubectl -n freebird rollout status deployment/verifier --timeout=180s
kubectl -n freebird wait --for=delete pod -l app=freebird,component=verifier --timeout=180s
PROXY_SERVICE_IP="$(kubectl -n ingress-nginx get service ingress-nginx-controller \
  -o jsonpath='{.spec.clusterIP}')"
: "${PROXY_SERVICE_IP:?could not determine ingress controller Service IP}"
kubectl -n freebird patch deployment verifier --type=strategic \
  -p "{\"spec\":{\"template\":{\"spec\":{\"hostAliases\":[{\"ip\":\"${PROXY_SERVICE_IP}\",\"hostnames\":[\"issuer.freebird.test\"]}]}}}}"
kubectl -n freebird patch configmap issuer-config --type merge \
  -p "{\"data\":{\"TRUSTED_PROXY_CIDRS\":\"${TRUSTED_PROXY_CIDR}\"}}"
kubectl -n freebird patch configmap verifier-config --type merge \
  -p "{\"data\":{\"TRUSTED_PROXY_CIDRS\":\"${TRUSTED_PROXY_CIDR}\"}}"
# Keep the workload references aligned with the exact aliases loaded above.
# The operator-provided source references are only used to create those local
# tags; they are not present in the kind node's image store after retagging.
kubectl set image deployment/issuer -n freebird issuer="$KIND_ISSUER_IMAGE"
kubectl set image deployment/verifier -n freebird verifier="$KIND_VERIFIER_IMAGE"
kubectl rollout restart deployment/issuer -n freebird
kubectl wait --for=condition=available deployment/issuer -n freebird --timeout=180s
kubectl rollout status deployment/issuer -n freebird --timeout=180s
ISSUER_PRIMARY_ENDPOINTS="$(kubectl get endpoints issuer -n freebird -o jsonpath='{.subsets[*].addresses[*].ip}')"
[[ -n "$ISSUER_PRIMARY_ENDPOINTS" ]] || {
  printf 'ERROR: primary issuer endpoints did not populate after readiness\n' >&2
  exit 1
}

kubectl apply -f - <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: issuer-metadata
  namespace: freebird
  labels:
    app: freebird-smoke
    component: health
spec:
  restartPolicy: Never
  serviceAccountName: default
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 1000
  containers:
    - name: metadata
      image: curlimages/curl:8.10.1
      env:
        - name: SSL_CERT_FILE
          value: /etc/freebird/ca/ca.crt
      command:
        - sh
        - -c
        - >-
          curl --fail --silent --show-error
          --cacert /etc/freebird/ca/ca.crt
          https://issuer.freebird.test/.well-known/issuer
          >/dev/null
      volumeMounts:
        - name: ca
          mountPath: /etc/freebird/ca
          readOnly: true
  hostAliases:
    - ip: "${PROXY_SERVICE_IP}"
      hostnames:
        - issuer.freebird.test
  volumes:
    - name: ca
      secret:
        secretName: issuer-ci-ca
YAML
kubectl wait --for=jsonpath='{.status.phase}'=Succeeded pod/issuer-metadata -n freebird --timeout=120s
kubectl logs issuer-metadata -n freebird
kubectl delete pod issuer-metadata -n freebird --wait=true

kubectl -n freebird scale deployment/verifier --replicas=3
kubectl rollout status deployment/verifier -n freebird --timeout=180s
VERIFIER_CONVERGENCE_TIMEOUT="${VERIFIER_CONVERGENCE_TIMEOUT:-180}"
VERIFIER_CONVERGENCE_DEADLINE="$(( $(date +%s) + VERIFIER_CONVERGENCE_TIMEOUT ))"
VERIFIER_PODS=""
VERIFIER_CONVERGENCE_LAST=""
while :; do
  kubectl get pods -n freebird -l app=freebird,component=verifier -o json >"$TMP/verifier-pods.json"
  kubectl get rs -n freebird -l app=freebird,component=verifier -o json >"$TMP/verifier-rs.json"
  kubectl get endpoints verifier -n freebird -o json >"$TMP/verifier-endpoints.json"
  if VERIFIER_CONVERGENCE_LAST="$(python3 - "$TMP/verifier-pods.json" "$TMP/verifier-rs.json" "$TMP/verifier-endpoints.json" <<'PY'
import json
from pathlib import Path
import sys


pods = json.loads(Path(sys.argv[1]).read_text())
replicasets = json.loads(Path(sys.argv[2]).read_text())
endpoints = json.loads(Path(sys.argv[3]).read_text())
current_sets = []
for replica_set in replicasets.get("items", []):
    metadata = replica_set.get("metadata", {})
    owners = metadata.get("ownerReferences", [])
    annotations = metadata.get("annotations", {})
    spec = replica_set.get("spec", {})
    if (
        metadata.get("deletionTimestamp") is None
        and spec.get("replicas") == 3
        and any(owner.get("kind") == "Deployment" and owner.get("name") == "verifier" for owner in owners)
    ):
        revision = int(annotations.get("deployment.kubernetes.io/revision", "0"))
        current_sets.append((revision, metadata.get("creationTimestamp", ""), metadata.get("labels", {}).get("pod-template-hash", "")))

if not current_sets:
    print("no non-terminating three-replica verifier ReplicaSet", file=sys.stderr)
    raise SystemExit(1)

_, _, current_hash = max(current_sets)
ready_pods = []
for pod in pods.get("items", []):
    metadata = pod.get("metadata", {})
    if metadata.get("deletionTimestamp") is not None:
        continue
    if metadata.get("labels", {}).get("pod-template-hash") != current_hash:
        continue
    conditions = pod.get("status", {}).get("conditions", [])
    if any(condition.get("type") == "Ready" and condition.get("status") == "True" for condition in conditions):
        ready_pods.append(metadata.get("name", ""))

endpoint_count = sum(len(subset.get("addresses", [])) for subset in endpoints.get("subsets", []))
if len(ready_pods) == 3 and endpoint_count == 3:
    print("\n".join(sorted(ready_pods)))
    raise SystemExit(0)

print(f"current_hash={current_hash} ready_pods={len(ready_pods)} primary_endpoints={endpoint_count}", file=sys.stderr)
raise SystemExit(1)
PY
)"; then
    break
  fi
  if [ "$(date +%s)" -ge "$VERIFIER_CONVERGENCE_DEADLINE" ]; then
    printf 'ERROR: verifier readiness/endpoints did not converge before timeout: %s\n' "$VERIFIER_CONVERGENCE_LAST" >&2
    kubectl get deployment verifier -n freebird -o wide || true
    kubectl get rs -n freebird -l app=freebird,component=verifier -o wide || true
    kubectl get pods -n freebird -l app=freebird,component=verifier -o wide || true
    kubectl get endpoints verifier -n freebird -o yaml || true
    exit 1
  fi
  sleep 2
done
VERIFIER_PRIMARY_ENDPOINTS="$(kubectl get endpoints verifier -n freebird -o jsonpath='{.subsets[*].addresses[*].ip}')"
VERIFIER_PRIMARY_ENDPOINT_COUNT="$(printf '%s\n' "$VERIFIER_PRIMARY_ENDPOINTS" | wc -w | tr -d ' ')"
[[ "$VERIFIER_PRIMARY_ENDPOINT_COUNT" == 3 ]] || {
  printf 'ERROR: expected exactly three primary verifier endpoints after convergence, found %s\n' "$VERIFIER_PRIMARY_ENDPOINT_COUNT" >&2
  exit 1
}
VERIFIER_PODS="$VERIFIER_CONVERGENCE_LAST"
VERIFIER_METADATA_DEADLINE="$(( $(date +%s) + VERIFIER_CONVERGENCE_TIMEOUT ))"
VERIFIER_METADATA_MISSING=""
while :; do
  VERIFIER_METADATA_MISSING=""
  while IFS= read -r verifier_pod; do
    [[ -n "$verifier_pod" ]] || continue
    if ! kubectl logs "$verifier_pod" -n freebird --all-containers=true | grep -q 'updated issuer metadata'; then
      VERIFIER_METADATA_MISSING+=" ${verifier_pod}"
    fi
  done <<< "$VERIFIER_PODS"
  if [[ -z "$VERIFIER_METADATA_MISSING" ]]; then
    break
  fi
  if [ "$(date +%s)" -ge "$VERIFIER_METADATA_DEADLINE" ]; then
    printf 'ERROR: verifier pods lack updated issuer metadata evidence before timeout:%s\n' "$VERIFIER_METADATA_MISSING" >&2
    for verifier_pod in $VERIFIER_METADATA_MISSING; do
      kubectl logs "$verifier_pod" -n freebird --all-containers=true --tail=100 || true
    done
    exit 1
  fi
  sleep 2
done

CONTROLLER_POD="$(kubectl -n ingress-nginx get pod -l app.kubernetes.io/component=controller -o jsonpath='{.items[0].metadata.name}')"
kubectl -n ingress-nginx exec "$CONTROLLER_POD" -- nginx -T >"$TMP/nginx-config.txt" 2>&1
python3 - "$TMP/nginx-config.txt" <<'PY'
from pathlib import Path
import re
import sys


text = Path(sys.argv[1]).read_text(encoding="utf-8")
for route in ("/healthz", "/readyz", "/health", "/ready"):
    matches = list(
        re.finditer(rf'(?m)^\s*location\s*=\s*"{re.escape(route)}"\s*\{{', text)
    )
    if len(matches) != 1:
        raise SystemExit(
            f"{route}: expected exactly one quoted exact nginx status location, found {len(matches)}"
        )

    match = matches[0]
    start = match.end()
    depth = 1
    index = start
    while depth and index < len(text):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
        index += 1
    if depth:
        raise SystemExit(f"{route}: unbalanced nginx status location block")
    block = text[start:index]
    for header, expected_value in (
        ("X-Forwarded-For", "$remote_addr"),
        ("X-Forwarded-Proto", "$pass_access_scheme"),
    ):
        values = re.findall(
            rf"^\s*proxy_set_header\s+{re.escape(header)}\s+([^;\n]+)\s*;\s*$",
            block,
            re.MULTILINE,
        )
        if values != [expected_value]:
            raise SystemExit(
                f"{route}: expected exactly one {header} directive with {expected_value}, "
                f"found {values}"
            )
PY

# All application checks traverse ingress; direct ClusterIP health checks are
# intentionally absent so the smoke test cannot accept a bypassed service.
kubectl apply -f - <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: health
  namespace: freebird
  labels:
    app: freebird-smoke
    component: health
spec:
  restartPolicy: Never
  serviceAccountName: default
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 1000
  containers:
    - name: health
      image: curlimages/curl:8.10.1
      env:
        - name: SSL_CERT_FILE
          value: /etc/freebird/ca/ca.crt
      command:
        - sh
        - -c
        - >-
          if curl --fail --silent --show-error
          --cacert /etc/freebird/wrong-ca/ca.crt
          https://issuer.freebird.test/readyz >/dev/null; then
          echo 'wrong CA was unexpectedly accepted for issuer' >&2; exit 1; fi;
          if curl --fail --silent --show-error
          --cacert /etc/freebird/wrong-ca/ca.crt
          https://verifier.freebird.test/ready >/dev/null; then
          echo 'wrong CA was unexpectedly accepted for verifier' >&2; exit 1; fi;
          curl --fail --silent --show-error
          --cacert /etc/freebird/ca/ca.crt
          -H 'X-Forwarded-For: 198.51.100.1'
          -H 'X-Forwarded-For: 203.0.113.2'
          -H 'X-Forwarded-Proto: http'
          -H 'X-Forwarded-Proto: http'
          https://issuer.freebird.test/readyz >/dev/null &&
          curl --fail --silent --show-error
          --cacert /etc/freebird/ca/ca.crt
          -H 'X-Forwarded-For: 198.51.100.1'
          -H 'X-Forwarded-For: 203.0.113.2'
          -H 'X-Forwarded-Proto: http'
          -H 'X-Forwarded-Proto: http'
          https://verifier.freebird.test/ready
          >/dev/null
      volumeMounts:
        - name: ca
          mountPath: /etc/freebird/ca
          readOnly: true
        - name: wrong-ca
          mountPath: /etc/freebird/wrong-ca
          readOnly: true
  hostAliases:
    - ip: "${PROXY_SERVICE_IP}"
      hostnames:
        - issuer.freebird.test
        - verifier.freebird.test
  volumes:
    - name: ca
      secret:
        secretName: issuer-ci-ca
    - name: wrong-ca
      secret:
        secretName: issuer-wrong-ca
YAML
kubectl wait --for=jsonpath='{.status.phase}'=Succeeded pod/health -n freebird --timeout=120s
kubectl logs health -n freebird
kubectl delete pod health -n freebird --wait=true
