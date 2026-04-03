package sqlitestore_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	acmeserver "github.com/misiektoja/go-acme-server"
	"github.com/misiektoja/go-acme-server/storetest"
	"github.com/misiektoja/go-acme-server/test/interop/sqlitestore"
	"github.com/misiektoja/go-acme-server/test/interop/testutil"
)

// Opens a durable test store and retains its database as local evidence.
func openStore(t *testing.T, path string) *sqlitestore.Store {
	t.Helper()
	store, err := sqlitestore.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	return store
}

// Runs the same public storage contract suite as the memory adapter.
func TestStoreContract(t *testing.T) {
	storetest.Run(t, func(t *testing.T) acmeserver.Store {
		return openStore(t, filepath.Join(testutil.Scratch(t), "store.sqlite"))
	})
}

// Confirms the durability settings on the connection used by the adapter.
func TestDurabilitySettings(t *testing.T) {
	store := openStore(t, filepath.Join(testutil.Scratch(t), "store.sqlite"))
	settings, err := store.Settings(t.Context())
	if err != nil || settings != "journal=wal synchronous=2 foreign_keys=1 busy_timeout=5000" {
		t.Fatalf("settings = %q, %v", settings, err)
	}
	t.Log(settings)
}

// Seeds one pending issuance operation for the cross-process fencing test.
func seedIssue(t *testing.T, store acmeserver.Store) {
	t.Helper()
	account := storetest.NewAccount(t, "account")
	if err := store.CreateAccount(t.Context(), account); err != nil {
		t.Fatal(err)
	}
	order, authzs, challenges := storetest.NewOrder(t, account.ID, "order", "a.test")
	if err := store.CreateOrder(t.Context(), order, authzs, challenges); err != nil {
		t.Fatal(err)
	}
	order.Status = acmeserver.OrderProcessing
	now := time.Date(2026, 4, 4, 12, 13, 17, 0, time.UTC)
	task := &acmeserver.Task{ID: "issue", Kind: acmeserver.TaskIssue, TargetID: order.ID, AccountID: account.ID, RunAt: now, CreatedAt: now}
	if err := store.FinalizeOrder(t.Context(), order, task); err != nil {
		t.Fatal(err)
	}
}

// Proves that a second process cannot claim an active lease and fences the first after lease recovery.
func TestTwoProcessLeaseAndFence(t *testing.T) {
	path := filepath.Join(testutil.Scratch(t), "lease.sqlite")
	store := openStore(t, path)
	seedIssue(t, store)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-test.run=^TestLeaseChild$")
	command.Env = append(os.Environ(), "ACME_LEASE_DB="+path)
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	input, err := command.StdinPipe()
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
	scanner := bufio.NewScanner(output)
	if !scanner.Scan() || scanner.Text() != "claimed fence 1" {
		t.Fatalf("child did not claim: %q", scanner.Text())
	}
	now := time.Date(2026, 4, 4, 12, 13, 17, 0, time.UTC)
	if _, err := store.ClaimTask(t.Context(), now, now.Add(time.Second)); !errors.Is(err, acmeserver.ErrNotFound) {
		t.Fatalf("active lease claimed: %v", err)
	}
	task, err := store.ClaimTask(t.Context(), now.Add(2*time.Second), now.Add(3*time.Second))
	if err != nil || task.Fence != 2 {
		t.Fatalf("reclaim = %+v, %v", task, err)
	}
	fmt.Fprintln(input, "finish")
	input.Close()
	var transcript strings.Builder
	for scanner.Scan() {
		transcript.WriteString(scanner.Text())
		transcript.WriteByte('\n')
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("child: %v\n%s", err, transcript.String())
	}
	if !strings.Contains(transcript.String(), "stale fence rejected") {
		t.Fatal(transcript.String())
	}
	order, err := store.Order(t.Context(), "order")
	if err != nil || order.Status != acmeserver.OrderProcessing {
		t.Fatalf("stale worker changed order: %+v, %v", order, err)
	}
	order.Status = acmeserver.OrderInvalid
	if err := store.CompleteIssuance(t.Context(), task, order, nil); err != nil {
		t.Fatal(err)
	}
	t.Log("active lease refused, reclaimed fence 2, stale fence 1 rejected, current fence committed")
}

// Runs in a separate test process to retain a stale fence across another process's claim.
func TestLeaseChild(t *testing.T) {
	path := os.Getenv("ACME_LEASE_DB")
	if path == "" {
		return
	}
	store := openStore(t, path)
	now := time.Date(2026, 4, 4, 12, 13, 17, 0, time.UTC)
	task, err := store.ClaimTask(t.Context(), now, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("claimed fence %d\n", task.Fence)
	if !bufio.NewScanner(os.Stdin).Scan() {
		t.Fatal("parent closed control input")
	}
	order, err := store.Order(t.Context(), "order")
	if err != nil {
		t.Fatal(err)
	}
	order.Status = acmeserver.OrderInvalid
	if err := store.CompleteIssuance(t.Context(), task, order, nil); !errors.Is(err, acmeserver.ErrRevisionMismatch) {
		t.Fatalf("stale completion = %v", err)
	}
	fmt.Println("stale fence rejected")
}
