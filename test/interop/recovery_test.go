package interop

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/mholt/acmez/v3/acme"

	acmeserver "github.com/misiektoja/go-acme-server"
	"github.com/misiektoja/go-acme-server/test/interop/sqlitestore"
)

// Pauses after the CA committed issuance but before the ACME store sees the result.
type stoppedPublication struct{ acmeserver.Store }

// Signals the parent at the crash boundary and waits for process termination.
func (s stoppedPublication) CompleteIssuance(ctx context.Context, task *acmeserver.Task, order *acmeserver.Order, cert *acmeserver.Certificate) error {
	if cert != nil {
		fmt.Println("CA result persisted before ACME publication")
		select {}
	}
	return s.Store.CompleteIssuance(ctx, task, order, cert)
}

// Starts a separately killable worker against the HTTP process's durable database.
func (h *harness) workerProcess(t *testing.T, stop bool) (*exec.Cmd, *bufio.Scanner) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(t.Context(), executable, "-test.run=^TestWorkerProcess$")
	command.Env = append(os.Environ(), "ACME_WORKER_DIR="+h.directory, "ACME_WORKER_BASE="+h.https.URL+"/acme/",
		"ACME_WORKER_PORT="+strconv.Itoa(h.options.httpPort), "ACME_STOP_PUBLICATION="+strconv.FormatBool(stop))
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if command.ProcessState == nil {
			command.Process.Kill()
			command.Wait()
		}
	})
	return command, bufio.NewScanner(output)
}

// Restarts a killed worker and recovers the exact CA result without a second signing operation.
func TestCrashAfterIssuance(t *testing.T) {
	s, port := newSolver(t, false)
	h := newHarness(t, harnessOptions{httpPort: port, external: true})
	client, account := h.acmez(t, httpSolver(s))
	key := newKey(t)
	first, output := h.workerProcess(t, true)
	type outcome struct {
		certificates []acme.Certificate
		err          error
	}
	completed := make(chan outcome, 1)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	go func() {
		certificates, err := client.ObtainCertificateForSANs(ctx, account, key, []string{testHost})
		completed <- outcome{certificates, err}
	}()
	signal := make(chan string, 1)
	go func() {
		if output.Scan() {
			signal <- output.Text()
		} else {
			signal <- "worker exited before crash boundary"
		}
	}()
	select {
	case message := <-signal:
		if message != "CA result persisted before ACME publication" {
			t.Fatal(message)
		}
	case <-ctx.Done():
		t.Fatal("worker never reached crash boundary")
	}
	if err := first.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	var exit *exec.ExitError
	if err := first.Wait(); !errors.As(err, &exit) {
		t.Fatalf("worker was not killed: %v", err)
	}
	ids, err := h.store.OrderIDs(t.Context(), accountID(account), "", 10)
	if err != nil || len(ids) != 1 {
		t.Fatalf("orders = %v, %v", ids, err)
	}
	before, err := h.store.Order(t.Context(), ids[0])
	if err != nil || before.Status != acmeserver.OrderProcessing || before.Issuance == nil || before.CertificateID != "" {
		t.Fatalf("crash state = %+v, %v", before, err)
	}
	var issuedDER []byte
	if err := h.ca.db.QueryRowContext(t.Context(), "SELECT der FROM issuance WHERE operation = ?", before.Issuance.OperationID).Scan(&issuedDER); err != nil {
		t.Fatal(err)
	}
	h.workerProcess(t, false)
	select {
	case result := <-completed:
		if result.err != nil || len(result.certificates) != 1 {
			t.Fatalf("recovery = %d, %v", len(result.certificates), result.err)
		}
		after := h.verify(t, result.certificates[0].ChainPEM, &key.PublicKey, []string{testHost}, acmeserver.ChallengeHTTP01)
		cert, err := h.store.Certificate(t.Context(), after.CertificateID)
		if err != nil || !bytes.Equal(cert.Chain[0], issuedDER) || after.Issuance.OperationID != before.Issuance.OperationID {
			t.Fatal("recovery changed the issued result or operation")
		}
	case <-ctx.Done():
		t.Fatal("replacement worker did not recover issuance")
	}
	var count, calls int
	if err := h.ca.db.QueryRowContext(t.Context(), "SELECT count(*), sum(calls) FROM issuance").Scan(&count, &calls); err != nil || count != 1 || calls != 2 {
		t.Fatalf("issued=%d calls=%d error=%v", count, calls, err)
	}
	t.Log("worker killed after CA commit, new worker recovered identical DER, one issuance across two CA calls")
}

// Runs only when the parent supplies a database and explicitly requests a worker subprocess.
func TestWorkerProcess(t *testing.T) {
	directory := os.Getenv("ACME_WORKER_DIR")
	if directory == "" {
		return
	}
	ca := openCA(t, directory)
	store, err := sqlitestore.Open(t.Context(), filepath.Join(directory, "acme.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	port, err := strconv.Atoi(os.Getenv("ACME_WORKER_PORT"))
	if err != nil {
		t.Fatal(err)
	}
	var persistence acmeserver.Store = store
	if os.Getenv("ACME_STOP_PUBLICATION") == "true" {
		persistence = stoppedPublication{Store: store}
	}
	server := configuredServer(t, os.Getenv("ACME_WORKER_BASE"), harnessOptions{httpPort: port, external: true}, persistence, ca)
	if err := server.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
}
