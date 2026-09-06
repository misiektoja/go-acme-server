package storetest

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	acmeserver "github.com/misiektoja/go-acme-server"
)

// The renewal identifier the contract tests attach to the first issued certificate.
const renewalID = "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE"

// Finalizes the order, claims its issuance task and returns the certificate to complete it with.
func issueCertificate(t *testing.T, store acmeserver.Store, order *acmeserver.Order, certID, renewalID string) (*acmeserver.Certificate, *acmeserver.Task) {
	t.Helper()
	ctx := context.Background()
	order.Status = acmeserver.OrderProcessing
	order.CSR = []byte{0x30, 0x03, 0x02, 0x01, 0x01}
	task := newTask("issue-"+order.ID, acmeserver.TaskIssue, order.ID, testNow)
	if err := store.FinalizeOrder(ctx, order, task); err != nil {
		t.Fatalf("FinalizeOrder: %v", err)
	}
	claimed, err := store.ClaimTask(ctx, testNow, testNow.Add(time.Minute))
	if err != nil || claimed.TargetID != order.ID {
		t.Fatalf("ClaimTask = %+v, %v", claimed, err)
	}
	cert := &acmeserver.Certificate{
		ID: certID, AccountID: order.AccountID, OrderID: order.ID, Chain: [][]byte{{0x30, 0x00}},
		NotBefore: testNow, NotAfter: testNow.Add(90 * 24 * time.Hour), RenewalID: renewalID,
		Validations: []acmeserver.Validation{
			{Identifier: order.Identifiers[0], Type: acmeserver.ChallengeHTTP01, Validated: testNow}},
		CreatedAt: testNow,
	}
	order.Status, order.CertificateID = acmeserver.OrderValid, cert.ID
	return cert, claimed
}

// Creates an order of the seeded account that replaces the certificate with the renewal identifier.
func replacingOrder(t *testing.T, store acmeserver.Store, orderID, replaces string, createdAt time.Time) error {
	t.Helper()
	order, authzs, challenges := NewOrder(t, "acct-1", orderID, "a.example")
	order.Replaces, order.CreatedAt, order.Expires = replaces, createdAt, createdAt.Add(7*24*time.Hour)
	return store.CreateOrder(context.Background(), order, authzs, challenges)
}

// Checks the renewal identifier lookup and its uniqueness.
func testRenewalLookup(t *testing.T, store acmeserver.Store) {
	ctx := context.Background()
	order, _, _ := seedOrder(t, store)
	cert, task := issueCertificate(t, store, order, "cert-1", renewalID)
	if err := store.CompleteIssuance(ctx, task, order, cert); err != nil {
		t.Fatalf("CompleteIssuance: %v", err)
	}
	found, err := store.CertificateByRenewalID(ctx, renewalID)
	if err != nil || found.ID != cert.ID || found.RenewalID != renewalID || found.Revision != 1 {
		t.Fatalf("CertificateByRenewalID = %+v, %v", found, err)
	}
	for _, id := range []string{"", "missing.serial"} {
		if _, err := store.CertificateByRenewalID(ctx, id); !errors.Is(err, acmeserver.ErrNotFound) {
			t.Fatalf("CertificateByRenewalID(%q) error = %v, want ErrNotFound", id, err)
		}
	}
	second, authzs, challenges := NewOrder(t, order.AccountID, "order-2", "c.example")
	if err := store.CreateOrder(ctx, second, authzs, challenges); err != nil {
		t.Fatalf("CreateOrder: %v", err)
	}
	duplicate, task := issueCertificate(t, store, second, "cert-2", renewalID)
	if err := store.CompleteIssuance(ctx, task, second, duplicate); !errors.Is(err, acmeserver.ErrConflict) {
		t.Fatalf("CompleteIssuance with a used RenewalID error = %v, want ErrConflict", err)
	}
	if _, err := store.Certificate(ctx, "cert-2"); !errors.Is(err, acmeserver.ErrNotFound) {
		t.Fatalf("conflicting certificate was stored: %v", err)
	}
}

// Stores one issued certificate carrying the renewal identifier.
func seedCertificate(t *testing.T, store acmeserver.Store) *acmeserver.Certificate {
	t.Helper()
	ctx := context.Background()
	order, _, _ := seedOrder(t, store)
	cert, task := issueCertificate(t, store, order, "cert-1", renewalID)
	if err := store.CompleteIssuance(ctx, task, order, cert); err != nil {
		t.Fatalf("CompleteIssuance: %v", err)
	}
	return cert
}

// Checks that one live order at a time may replace a certificate.
func testReplacementClaim(t *testing.T, store acmeserver.Store) {
	ctx := context.Background()
	cert := seedCertificate(t, store)
	if err := replacingOrder(t, store, "order-2", renewalID, testNow); err != nil {
		t.Fatalf("first replacement: %v", err)
	}
	stored, err := store.Certificate(ctx, cert.ID)
	if err != nil || stored.ReplacedByOrderID != "order-2" || stored.Revision != 2 {
		t.Fatalf("certificate after claim = %+v, %v", stored, err)
	}
	if err := replacingOrder(t, store, "order-3", renewalID, testNow); !errors.Is(err, acmeserver.ErrAlreadyReplaced) {
		t.Fatalf("second replacement error = %v, want ErrAlreadyReplaced", err)
	}
	if _, err := store.Order(ctx, "order-3"); !errors.Is(err, acmeserver.ErrNotFound) {
		t.Fatalf("refused order was stored: %v", err)
	}
	if err := replacingOrder(t, store, "order-4", "missing.serial", testNow); !errors.Is(err, acmeserver.ErrNotFound) {
		t.Fatalf("unknown predecessor error = %v, want ErrNotFound", err)
	}
	// The first replacing order expires unfinished, so the certificate may be replaced again.
	later := testNow.Add(8 * 24 * time.Hour)
	if err := replacingOrder(t, store, "order-5", renewalID, later); err != nil {
		t.Fatalf("replacement after expiry: %v", err)
	}
	stored, err = store.Certificate(ctx, cert.ID)
	if err != nil || stored.ReplacedByOrderID != "order-5" || stored.Revision != 3 {
		t.Fatalf("certificate after second claim = %+v, %v", stored, err)
	}
	order, err := store.Order(ctx, "order-5")
	if err != nil || order.Replaces != renewalID {
		t.Fatalf("stored order = %+v, %v", order, err)
	}
}

// Checks that racing replacement orders leave exactly one claim.
func testConcurrentReplacement(t *testing.T, store acmeserver.Store) {
	seedCertificate(t, store)
	const racers = 8
	errs := make([]error, racers)
	var wg sync.WaitGroup
	for i := range racers {
		wg.Go(func() {
			errs[i] = replacingOrder(t, store, fmt.Sprintf("racer-%d", i), renewalID, testNow)
		})
	}
	wg.Wait()
	created := 0
	for i, err := range errs {
		switch {
		case err == nil:
			created++
		case errors.Is(err, acmeserver.ErrAlreadyReplaced):
		default:
			t.Fatalf("racer %d: unexpected error %v", i, err)
		}
	}
	if created != 1 {
		t.Fatalf("%d racing replacements succeeded, want exactly 1", created)
	}
}
