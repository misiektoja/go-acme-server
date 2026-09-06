#!/usr/bin/env bash
# Issues and renews a certificate through cert-manager in a throwaway kind cluster against
# go-acme-server. Run from the repository root with Docker, kind, kubectl and openssl installed.
# openssl also handles base64 because the base64 command differs between platforms.
# ACME_TEST_SCRATCH selects where logs, credentials and the summary are kept.
set -euo pipefail

CERT_MANAGER_VERSION=v1.21.1
CERT_MANAGER_SHA256=5f6a499b8c1857d57f560f536e0dcc830914b45c420899fe7ad0692c8624e408
KIND_NODE_IMAGE=kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5
CLUSTER=${ACME_KIND_CLUSTER:-acme-cert-manager}
NAMESPACE=acme-test
DOMAIN=cert-manager.issuance.test
# The solver service in manifests.yaml holds this address.
SOLVER_IP=10.96.0.100
SERVER_NAME=acme.acme-test.svc.cluster.local
IMAGE=go-acme-server-interop:local
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
SCRATCH=${ACME_TEST_SCRATCH:-$ROOT/.cache/acme-tests}
WORK=$SCRATCH/cert-manager
STATE=$WORK/state
SUMMARY=$SCRATCH/cert-manager-summary.json
START=$(date +%s)

# Prints a timestamped progress line.
log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*"; }

# Saves cluster diagnostics without secret contents, then removes the cluster.
cleanup() {
	status=$?
	if kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
		if [ "$status" -ne 0 ]; then
			log "collecting diagnostics into $WORK"
			kubectl get certificate,certificaterequest,order,challenge -A -o wide >"$WORK/resources.txt" 2>&1 || true
			kubectl describe challenge -A >"$WORK/challenges.txt" 2>&1 || true
			kubectl get events -A --sort-by=.lastTimestamp >"$WORK/events.txt" 2>&1 || true
			kubectl -n cert-manager logs deploy/cert-manager --tail=500 >"$WORK/cert-manager.log" 2>&1 || true
			kubectl -n "$NAMESPACE" logs deploy/acme --tail=500 >"$WORK/acme-server.log" 2>&1 || true
		fi
		if [ "${ACME_KEEP_CLUSTER:-}" != "1" ]; then
			kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
		fi
	fi
	printf '{"certManager":"%s","kindNodeImage":"%s","outcome":"%s","elapsedSeconds":%d}\n' \
		"$CERT_MANAGER_VERSION" "$KIND_NODE_IMAGE" "$([ "$status" -eq 0 ] && echo pass || echo fail)" "$(($(date +%s) - START))" >"$SUMMARY"
	exit "$status"
}
trap cleanup EXIT

# Retries a command until it succeeds or the attempt budget runs out.
retry() {
	local attempts=$1
	shift
	local n=1
	until "$@"; do
		if [ "$n" -ge "$attempts" ]; then
			return 1
		fi
		n=$((n + 1))
		sleep 2
	done
}

# Prints the serial number of the certificate in the test secret, or nothing before issuance.
serial() {
	kubectl -n "$NAMESPACE" get secret cert-manager-test-tls -o jsonpath='{.data.tls\.crt}' 2>/dev/null |
		openssl base64 -d -A 2>/dev/null | openssl x509 -noout -serial 2>/dev/null || true
}

# Checks that the secret holds a chain to the test root for the test domain.
verify_secret() {
	kubectl -n "$NAMESPACE" get secret cert-manager-test-tls -o jsonpath='{.data.tls\.crt}' | openssl base64 -d -A >"$WORK/issued.pem"
	openssl verify -CAfile "$STATE/root.pem" "$WORK/issued.pem" >/dev/null
	openssl x509 -in "$WORK/issued.pem" -noout -ext subjectAltName | grep -q "DNS:$DOMAIN"
	kubectl -n "$NAMESPACE" get certificate cert-manager-test -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' | grep -qx True
}

mkdir -p "$WORK"
: >"$SUMMARY"
log "building the test server for $(docker version -f '{{.Server.Os}}/{{.Server.Arch}}')"
(cd "$ROOT/test/interop" && CGO_ENABLED=0 GOOS=linux GOARCH="$(docker version -f '{{.Server.Arch}}')" go build -o "$WORK/acme-server" ./cmd/server)
(cd "$ROOT/test/interop" && go run ./cmd/server -init -state "$STATE" -names "$SERVER_NAME")
cp "$ROOT/test/interop/cert-manager/Dockerfile" "$WORK/Dockerfile"
docker build -q -t "$IMAGE" "$WORK" >/dev/null

if [ ! -f "$WORK/cert-manager-$CERT_MANAGER_VERSION.yaml" ]; then
	curl -fsSL -o "$WORK/cert-manager-$CERT_MANAGER_VERSION.yaml" "https://github.com/cert-manager/cert-manager/releases/download/$CERT_MANAGER_VERSION/cert-manager.yaml"
fi
echo "$CERT_MANAGER_SHA256  $WORK/cert-manager-$CERT_MANAGER_VERSION.yaml" | shasum -a 256 -c - >/dev/null

log "creating kind cluster $CLUSTER"
kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
kind create cluster --name "$CLUSTER" --image "$KIND_NODE_IMAGE" --wait 120s >"$WORK/kind.log" 2>&1
kind load docker-image "$IMAGE" --name "$CLUSTER" >>"$WORK/kind.log" 2>&1

log "installing cert-manager $CERT_MANAGER_VERSION"
kubectl apply -f "$WORK/cert-manager-$CERT_MANAGER_VERSION.yaml" >/dev/null
kubectl -n cert-manager wait --for=condition=Available deployment --all --timeout=180s >/dev/null

# cert-manager's self-check resolves the domain inside the cluster, so CoreDNS answers it with
# the solver service address.
log "pointing $DOMAIN at $SOLVER_IP in CoreDNS"
kubectl -n kube-system get configmap coredns -o jsonpath='{.data.Corefile}' >"$WORK/Corefile"
if ! grep -q "$DOMAIN" "$WORK/Corefile"; then
	awk -v ip="$SOLVER_IP" -v domain="$DOMAIN" '/^ *kubernetes / { printf "    hosts {\n        %s %s\n        fallthrough\n    }\n", ip, domain } { print }' "$WORK/Corefile" >"$WORK/Corefile.new"
	kubectl -n kube-system create configmap coredns --from-file=Corefile="$WORK/Corefile.new" --dry-run=client -o yaml | kubectl replace -f - >/dev/null
	kubectl -n kube-system rollout restart deployment/coredns >/dev/null
	kubectl -n kube-system rollout status deployment/coredns --timeout=120s >/dev/null
fi

log "deploying the ACME server"
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n "$NAMESPACE" create secret generic acme-credentials --from-file=root.pem="$STATE/root.pem" --from-file=root-key.pem="$STATE/root-key.pem" --from-file=tls.crt="$STATE/tls.crt" --from-file=tls.key="$STATE/tls.key" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl apply -f "$ROOT/test/interop/cert-manager/manifests.yaml" >/dev/null
kubectl -n "$NAMESPACE" rollout status deployment/acme --timeout=120s >/dev/null

log "creating the ClusterIssuer"
CA_BUNDLE=$(openssl base64 -A -in "$STATE/root.pem")
cat >"$WORK/issuer.yaml" <<ISSUER
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: acme-test
spec:
  acme:
    server: https://$SERVER_NAME:8443/acme/directory
    caBundle: $CA_BUNDLE
    privateKeySecretRef:
      name: acme-test-account
    solvers:
      - http01:
          ingress: {}
ISSUER
# The webhook may still refuse connections shortly after its deployment reports available.
retry 30 kubectl apply -f "$WORK/issuer.yaml" >/dev/null
kubectl wait --for=condition=Ready clusterissuer/acme-test --timeout=120s >/dev/null

log "waiting for the first issuance"
kubectl apply -f "$ROOT/test/interop/cert-manager/certificate.yaml" >/dev/null
kubectl -n "$NAMESPACE" wait --for=condition=Ready certificate/cert-manager-test --timeout=300s >/dev/null
verify_secret
FIRST=$(serial)
log "issued $FIRST"

log "triggering renewal"
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
GENERATION=$(kubectl -n "$NAMESPACE" get certificate cert-manager-test -o jsonpath='{.metadata.generation}')
kubectl -n "$NAMESPACE" patch certificate cert-manager-test --subresource=status --type=merge -p "{\"status\":{\"conditions\":[{\"type\":\"Issuing\",\"status\":\"True\",\"reason\":\"ManuallyTriggered\",\"message\":\"renewal requested by the test\",\"lastTransitionTime\":\"$NOW\",\"observedGeneration\":$GENERATION}]}}" >/dev/null
for _ in $(seq 1 150); do
	SECOND=$(serial)
	if [ -n "$SECOND" ] && [ "$SECOND" != "$FIRST" ]; then
		break
	fi
	sleep 2
done
[ "$SECOND" != "$FIRST" ] || { log "renewal did not replace $FIRST"; exit 1; }
kubectl -n "$NAMESPACE" wait --for=condition=Ready certificate/cert-manager-test --timeout=120s >/dev/null
verify_secret
log "renewed as $SECOND"
# cert-manager prunes the request history, so the revision counts the issuances instead.
REVISION=$(kubectl -n "$NAMESPACE" get certificate cert-manager-test -o jsonpath='{.status.revision}')
[ "$REVISION" = 2 ] || { log "expected revision 2, found $REVISION"; exit 1; }
log "cert-manager $CERT_MANAGER_VERSION issued and renewed through HTTP-01 with its self-check"
