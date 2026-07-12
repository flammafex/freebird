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
TMP="$(mktemp -d)"
cleanup() {
  kubectl get pods -A -o wide || true
  kubectl describe deployment issuer verifier -n freebird || true
  kubectl logs health -n freebird --tail=100 || true
  kubectl get events -A --sort-by=.lastTimestamp || true
  kubectl delete secret issuer-tls-cert issuer-ci-ca issuer-wrong-ca -n freebird --ignore-not-found || true
  kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
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

# Pin the official kind provider to the reviewed ingress-nginx commit. Extract
# the digest-pinned image references from that exact manifest and load them
# into kind before applying it, avoiding a second pull during pod admission.
INGRESS_MANIFEST="$TMP/ingress-nginx.yaml"
INGRESS_MANIFEST_URL="https://raw.githubusercontent.com/kubernetes/ingress-nginx/${INGRESS_COMMIT}/deploy/static/provider/kind/deploy.yaml"
curl -fsSL "$INGRESS_MANIFEST_URL" -o "$INGRESS_MANIFEST"
INGRESS_CONTROLLER_IMAGE="$(awk '/image: registry.k8s.io\/ingress-nginx\/controller:/ {print $2; exit}' "$INGRESS_MANIFEST")"
INGRESS_CERTGEN_IMAGE="$(awk '/image: registry.k8s.io\/ingress-nginx\/kube-webhook-certgen:/ {print $2; exit}' "$INGRESS_MANIFEST")"
[[ $INGRESS_CONTROLLER_IMAGE == *@sha256:* && $INGRESS_CERTGEN_IMAGE == *@sha256:* ]] || { printf 'ERROR: reviewed ingress manifest did not contain digest-pinned images\n' >&2; exit 1; }
docker pull "$INGRESS_CONTROLLER_IMAGE"
docker pull "$INGRESS_CERTGEN_IMAGE"
kind load docker-image "$INGRESS_CONTROLLER_IMAGE" "$INGRESS_CERTGEN_IMAGE" --name "$CLUSTER"
kubectl apply -f "$INGRESS_MANIFEST"
kubectl -n ingress-nginx wait --for=condition=ready pod \
  -l app.kubernetes.io/component=controller --timeout="$INGRESS_READY_TIMEOUT"
kubectl apply -f k8s/overlays/kind/proxy-headers.yaml
kubectl -n ingress-nginx patch configmap ingress-nginx-controller --type merge \
  -p '{"data":{"proxy-set-headers":"ingress-nginx/freebird-proxy-headers"}}'
kubectl -n ingress-nginx rollout restart deployment ingress-nginx-controller
kubectl -n ingress-nginx rollout status deployment/ingress-nginx-controller --timeout="$INGRESS_READY_TIMEOUT"

# Discover the source address after the controller and its networking exist.
# A /32 avoids assuming the kind node or pod network in application config.
PROXY_IP="$(kubectl -n ingress-nginx get pod -l app.kubernetes.io/component=controller \
  -o jsonpath='{.items[0].status.podIP}')"
: "${PROXY_IP:?could not determine ingress controller pod IP}"
TRUSTED_PROXY_CIDR="${PROXY_IP}/32"

kind load docker-image "$ISSUER_IMAGE" "$VERIFIER_IMAGE" --name "$CLUSTER"
kubectl apply -f k8s/namespace.yaml -f k8s/rbac.yaml
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
subjectAltName=DNS:issuer.freebird.test
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
kubectl apply -k k8s/overlays/kind
PROXY_SERVICE_IP="$(kubectl -n ingress-nginx get service ingress-nginx-controller \
  -o jsonpath='{.spec.clusterIP}')"
: "${PROXY_SERVICE_IP:?could not determine ingress controller Service IP}"
kubectl -n freebird patch deployment verifier --type=strategic \
  -p "{\"spec\":{\"template\":{\"spec\":{\"hostAliases\":[{\"ip\":\"${PROXY_SERVICE_IP}\",\"hostnames\":[\"issuer.freebird.test\"]}]}}}}"
kubectl -n freebird patch configmap issuer-config --type merge \
  -p "{\"data\":{\"TRUSTED_PROXY_CIDRS\":\"${TRUSTED_PROXY_CIDR}\"}}"
kubectl -n freebird patch configmap verifier-config --type merge \
  -p "{\"data\":{\"TRUSTED_PROXY_CIDRS\":\"${TRUSTED_PROXY_CIDR}\"}}"
kubectl set image deployment/issuer -n freebird issuer="$ISSUER_IMAGE"
kubectl set image deployment/verifier -n freebird verifier="$VERIFIER_IMAGE"
kubectl rollout restart deployment/issuer deployment/verifier -n freebird
kubectl rollout status deployment/issuer -n freebird --timeout=180s
kubectl rollout status deployment/verifier -n freebird --timeout=180s

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
          echo 'wrong CA was unexpectedly accepted' >&2; exit 1; fi;
          curl --fail --silent --show-error
          --cacert /etc/freebird/ca/ca.crt
          https://issuer.freebird.test/readyz >/dev/null &&
          curl --fail --silent --show-error
          http://verifier.freebird.test/ready
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
