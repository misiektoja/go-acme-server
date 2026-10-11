// Package certmanager_test checks cluster ownership without invoking real infrastructure tools.
package certmanager_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/misiektoja/go-acme-server/test/interop/testutil"
)

// Exercises the actual runner with inert tools and checks cleanup on every ownership boundary.
func TestClusterOwnership(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mode    string
		cluster string
		keep    bool
		created bool
		code    int
	}{
		{name: "existing default", mode: "existing", cluster: "acme-cert-manager", code: 1},
		{name: "existing kept", mode: "existing", cluster: "custom-cluster", keep: true, code: 1},
		{name: "listing failed", mode: "list-fail", cluster: "custom-cluster", code: 22},
		{name: "build failed", mode: "build-fail", cluster: "custom-cluster", code: 23},
		{name: "creation failed", mode: "create-fail", cluster: "custom-cluster", code: 24},
		{name: "owned failure", mode: "load-fail", cluster: "custom-cluster", created: true, code: 25},
		{name: "kept failure", mode: "load-fail", cluster: "custom-cluster", keep: true, created: true, code: 25},
		{name: "success", mode: "success", cluster: "custom-cluster", created: true},
		{name: "kept success", mode: "success", cluster: "custom-cluster", keep: true, created: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := testutil.Scratch(t)
			bin := filepath.Join(dir, "bin")
			if err := os.Mkdir(bin, 0700); err != nil {
				t.Fatal(err)
			}
			for _, tool := range []string{"kind", "kubectl", "docker", "go", "curl", "shasum", "openssl"} {
				if err := os.WriteFile(filepath.Join(bin, tool), []byte(clusterToolStub), 0700); err != nil {
					t.Fatal(err)
				}
			}
			original := filepath.Join(dir, "user-kubeconfig")
			if err := os.WriteFile(original, []byte("existing user configuration\n"), 0600); err != nil {
				t.Fatal(err)
			}
			keep := "0"
			if tc.keep {
				keep = "1"
			}
			cluster := tc.cluster
			if tc.name == "existing default" {
				cluster = ""
			}
			cmd := exec.CommandContext(t.Context(), "bash", "run.sh")
			cmd.WaitDelay = time.Second
			cmd.Env = append(os.Environ(), "PATH="+bin+":/usr/bin:/bin", "ACME_TEST_SCRATCH="+dir,
				"ACME_KIND_CLUSTER="+cluster, "ACME_KEEP_CLUSTER="+keep, "KUBECONFIG="+original,
				"STUB_MODE="+tc.mode, "STUB_CLUSTER="+tc.cluster, "STUB_DIR="+dir)
			output, err := cmd.CombinedOutput()
			if cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != tc.code {
				t.Fatalf("exit=%v error=%v want=%d output=%s", cmd.ProcessState, err, tc.code, output)
			}
			calls := readRunnerFile(t, filepath.Join(dir, "calls"))
			deleted := strings.Count(calls, "kind delete cluster --name "+tc.cluster+"\n")
			wantDeleted := 0
			if tc.created && !tc.keep {
				wantDeleted = 1
			}
			if deleted != wantDeleted || strings.Contains(calls, "kubectl ") != tc.created {
				t.Fatalf("ownership violation: deletes=%d want=%d calls=\n%s", deleted, wantDeleted, calls)
			}
			if (tc.mode == "existing" || tc.mode == "list-fail") && strings.Contains(calls, "go ") {
				t.Fatalf("build started before the cluster preflight passed:\n%s", calls)
			}
			if got := readRunnerFile(t, original); got != "existing user configuration\n" {
				t.Fatalf("user kubeconfig changed: %q", got)
			}
			var summary struct {
				Outcome string `json:"outcome"`
			}
			if err := json.Unmarshal([]byte(readRunnerFile(t, filepath.Join(dir, "cert-manager-summary.json"))), &summary); err != nil {
				t.Fatal(err)
			}
			want := "fail"
			if tc.code == 0 {
				want = "pass"
			}
			if summary.Outcome != want {
				t.Fatalf("summary outcome=%q want=%q", summary.Outcome, want)
			}
		})
	}
}

// Reads retained runner evidence for assertions.
func readRunnerFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// Simulates issuance and renewal while refusing kubectl calls outside the owned context.
const clusterToolStub = `#!/bin/bash
set -euo pipefail
tool=${0##*/}
printf '%s %s\n' "$tool" "$*" >>"$STUB_DIR/calls"
case "$tool" in
kind)
  case "$1 $2" in
  'get clusters')
    [ "$STUB_MODE" != list-fail ] || exit 22
    if [ "$STUB_MODE" = existing ]; then printf '%s\n' "$STUB_CLUSTER"; fi
    ;;
  'create cluster')
    [ "$STUB_MODE" != create-fail ] || exit 24
    case "$KUBECONFIG" in "$STUB_DIR"/cert-manager/kubeconfig.*) ;; *) exit 80;; esac
    [[ " $* " == *" --kubeconfig $KUBECONFIG "* ]] || exit 81
    printf 'owned cluster\n' >"$KUBECONFIG"
    ;;
  'load docker-image') [ "$STUB_MODE" != load-fail ] || exit 25;;
  esac
  ;;
kubectl)
  [ "$1" = --context ] && [ "$2" = "kind-$STUB_CLUSTER" ] || exit 82
  case "$KUBECONFIG" in "$STUB_DIR"/cert-manager/kubeconfig.*) ;; *) exit 83;; esac
  [ "$(cat "$KUBECONFIG")" = 'owned cluster' ] || exit 84
  case "$*" in
  *data.Corefile*) printf '    kubernetes cluster.local\n';;
  *metadata.generation*) printf '1';;
  *status.revision*) printf '2';;
  *status.conditions*) printf 'True\n';;
  *data.tls*) printf 'certificate\n';;
  esac
  ;;
docker) [ "$1" != version ] || printf 'amd64\n';;
go) [ "$STUB_MODE" != build-fail ] || exit 23;;
curl) printf 'manifest\n' >"$3";;
shasum) cat >/dev/null;;
openssl)
  case "$*" in
  *-serial*)
    value=1
    if [ -f "$STUB_DIR/serial" ]; then value=2; fi
    printf '%s\n' "$value" >"$STUB_DIR/serial"
    cat >/dev/null
    printf 'serial=%s\n' "$value"
    ;;
  *subjectAltName*) printf 'DNS:cert-manager.issuance.test\n';;
  'base64 -d -A') cat;;
  'base64 -A'*) printf 'CA\n';;
  esac
  ;;
esac
exit 0
`
