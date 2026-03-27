// Package storetest checks an acmeserver.Store against the persistence contract.
package storetest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"testing"

	acmeserver "github.com/misiektoja/go-acme-server"
	"github.com/misiektoja/go-acme-server/internal/jws"
)

// Runs the contract suite. The open function returns a fresh empty store for each subtest.
func Run(t *testing.T, open func(t *testing.T) acmeserver.Store) {
	t.Run("CreateAndReadAccount", func(t *testing.T) { testCreateAndRead(t, open(t)) })
	t.Run("AccountNotFound", func(t *testing.T) { testNotFound(t, open(t)) })
	t.Run("CreateAccountConflicts", func(t *testing.T) { testCreateConflicts(t, open(t)) })
	t.Run("UpdateAccount", func(t *testing.T) { testUpdate(t, open(t)) })
	t.Run("UpdateAccountStaleRevision", func(t *testing.T) { testUpdateStale(t, open(t)) })
	t.Run("UpdateAccountMissing", func(t *testing.T) { testUpdateMissing(t, open(t)) })
	t.Run("UpdateAccountKey", func(t *testing.T) { testUpdateKey(t, open(t)) })
	t.Run("ReturnsCopies", func(t *testing.T) { testCopies(t, open(t)) })
	t.Run("ConcurrentCreateSameKey", func(t *testing.T) { testConcurrentCreate(t, open(t)) })
	t.Run("CanceledContext", func(t *testing.T) { testCanceledContext(t, open(t)) })
	t.Run("CreateOrder", func(t *testing.T) { testCreateOrder(t, open(t)) })
	t.Run("CreateOrderConflicts", func(t *testing.T) { testCreateOrderConflicts(t, open(t)) })
	t.Run("OrderIDs", func(t *testing.T) { testOrderIDs(t, open(t)) })
	t.Run("UpdateAuthorization", func(t *testing.T) { testUpdateAuthorization(t, open(t)) })
	t.Run("AcceptChallenge", func(t *testing.T) { testAcceptChallenge(t, open(t)) })
	t.Run("ClaimTask", func(t *testing.T) { testClaimTask(t, open(t)) })
	t.Run("ConcurrentClaim", func(t *testing.T) { testConcurrentClaim(t, open(t)) })
	t.Run("CompleteValidation", func(t *testing.T) { testCompleteValidation(t, open(t)) })
	t.Run("FinalizeAndIssue", func(t *testing.T) { testFinalizeAndIssue(t, open(t)) })
	t.Run("IssuanceFailureAndDuplicate", func(t *testing.T) { testIssuanceFailureAndDuplicate(t, open(t)) })
}

// Returns a valid account with a fresh P-256 key.
func NewAccount(t *testing.T, id string) *acmeserver.Account {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	thumbprint, err := jws.Thumbprint(&key.PublicKey)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	return &acmeserver.Account{
		ID:                   id,
		Status:               acmeserver.AccountValid,
		Key:                  &key.PublicKey,
		KeyThumbprint:        thumbprint,
		Contact:              []string{"mailto:admin@example.test"},
		TermsOfServiceAgreed: true,
	}
}

// Checks that a created account reads back by ID and by key with revision 1.
func testCreateAndRead(t *testing.T, store acmeserver.Store) {
	ctx := context.Background()
	want := NewAccount(t, "acct-1")
	if err := store.CreateAccount(ctx, want); err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	if want.Revision != 1 {
		t.Fatalf("CreateAccount set Revision %d, want 1", want.Revision)
	}
	got, err := store.Account(ctx, want.ID)
	if err != nil {
		t.Fatalf("Account: %v", err)
	}
	assertAccountEqual(t, got, want)
	got, err = store.AccountByKey(ctx, want.KeyThumbprint)
	if err != nil {
		t.Fatalf("AccountByKey: %v", err)
	}
	assertAccountEqual(t, got, want)
}

// Checks the not found errors.
func testNotFound(t *testing.T, store acmeserver.Store) {
	ctx := context.Background()
	if _, err := store.Account(ctx, "missing"); !errors.Is(err, acmeserver.ErrNotFound) {
		t.Fatalf("Account(missing) error = %v, want ErrNotFound", err)
	}
	if _, err := store.AccountByKey(ctx, "missing"); !errors.Is(err, acmeserver.ErrNotFound) {
		t.Fatalf("AccountByKey(missing) error = %v, want ErrNotFound", err)
	}
}

// Checks that duplicate IDs and keys are refused without side effects.
func testCreateConflicts(t *testing.T, store acmeserver.Store) {
	ctx := context.Background()
	first := NewAccount(t, "acct-1")
	if err := store.CreateAccount(ctx, first); err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	sameID := NewAccount(t, "acct-1")
	if err := store.CreateAccount(ctx, sameID); !errors.Is(err, acmeserver.ErrConflict) {
		t.Fatalf("CreateAccount(same ID) error = %v, want ErrConflict", err)
	}
	sameKey := NewAccount(t, "acct-2")
	sameKey.Key, sameKey.KeyThumbprint = first.Key, first.KeyThumbprint
	if err := store.CreateAccount(ctx, sameKey); !errors.Is(err, acmeserver.ErrConflict) {
		t.Fatalf("CreateAccount(same key) error = %v, want ErrConflict", err)
	}
	if _, err := store.Account(ctx, "acct-2"); !errors.Is(err, acmeserver.ErrNotFound) {
		t.Fatalf("conflicting create left an account behind: %v", err)
	}
	got, err := store.AccountByKey(ctx, first.KeyThumbprint)
	if err != nil || got.ID != first.ID {
		t.Fatalf("AccountByKey after conflicts = %v, %v; want %s", got, err, first.ID)
	}
}

// Checks that a matching revision persists changes and advances the revision.
func testUpdate(t *testing.T, store acmeserver.Store) {
	ctx := context.Background()
	account := NewAccount(t, "acct-1")
	if err := store.CreateAccount(ctx, account); err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	account.Contact = []string{"mailto:ops@example.test"}
	account.Status = acmeserver.AccountDeactivated
	if err := store.UpdateAccount(ctx, account); err != nil {
		t.Fatalf("UpdateAccount: %v", err)
	}
	if account.Revision != 2 {
		t.Fatalf("UpdateAccount set Revision %d, want 2", account.Revision)
	}
	got, err := store.Account(ctx, account.ID)
	if err != nil {
		t.Fatalf("Account: %v", err)
	}
	assertAccountEqual(t, got, account)
}

// Checks that an update with an outdated revision is refused and changes nothing.
func testUpdateStale(t *testing.T, store acmeserver.Store) {
	ctx := context.Background()
	account := NewAccount(t, "acct-1")
	if err := store.CreateAccount(ctx, account); err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	stale, err := store.Account(ctx, account.ID)
	if err != nil {
		t.Fatalf("Account: %v", err)
	}
	account.Contact = []string{"mailto:first@example.test"}
	if err := store.UpdateAccount(ctx, account); err != nil {
		t.Fatalf("UpdateAccount: %v", err)
	}
	stale.Contact = []string{"mailto:second@example.test"}
	if err := store.UpdateAccount(ctx, stale); !errors.Is(err, acmeserver.ErrRevisionMismatch) {
		t.Fatalf("UpdateAccount(stale) error = %v, want ErrRevisionMismatch", err)
	}
	got, err := store.Account(ctx, account.ID)
	if err != nil {
		t.Fatalf("Account: %v", err)
	}
	assertAccountEqual(t, got, account)
}

// Checks that updating an unknown account reports not found.
func testUpdateMissing(t *testing.T, store acmeserver.Store) {
	account := NewAccount(t, "acct-1")
	account.Revision = 1
	if err := store.UpdateAccount(context.Background(), account); !errors.Is(err, acmeserver.ErrNotFound) {
		t.Fatalf("UpdateAccount(missing) error = %v, want ErrNotFound", err)
	}
}

// Checks key rollover and refusal of a thumbprint owned by another account.
func testUpdateKey(t *testing.T, store acmeserver.Store) {
	ctx := context.Background()
	account := NewAccount(t, "acct-1")
	other := NewAccount(t, "acct-2")
	for _, a := range []*acmeserver.Account{account, other} {
		if err := store.CreateAccount(ctx, a); err != nil {
			t.Fatalf("CreateAccount(%s): %v", a.ID, err)
		}
	}
	oldThumbprint := account.KeyThumbprint
	account.Key, account.KeyThumbprint = other.Key, other.KeyThumbprint
	if err := store.UpdateAccount(ctx, account); !errors.Is(err, acmeserver.ErrConflict) {
		t.Fatalf("UpdateAccount(key of another account) error = %v, want ErrConflict", err)
	}
	fresh := NewAccount(t, "unused")
	account.Key, account.KeyThumbprint = fresh.Key, fresh.KeyThumbprint
	if err := store.UpdateAccount(ctx, account); err != nil {
		t.Fatalf("UpdateAccount(new key): %v", err)
	}
	got, err := store.AccountByKey(ctx, fresh.KeyThumbprint)
	if err != nil || got.ID != account.ID {
		t.Fatalf("AccountByKey(new) = %v, %v; want %s", got, err, account.ID)
	}
	if _, err := store.AccountByKey(ctx, oldThumbprint); !errors.Is(err, acmeserver.ErrNotFound) {
		t.Fatalf("AccountByKey(old) error = %v, want ErrNotFound", err)
	}
	if got, err := store.AccountByKey(ctx, other.KeyThumbprint); err != nil || got.ID != other.ID {
		t.Fatalf("AccountByKey(other) = %v, %v; want %s", got, err, other.ID)
	}
}

// Checks that neither the caller's input nor the returned values alias stored state.
func testCopies(t *testing.T, store acmeserver.Store) {
	ctx := context.Background()
	account := NewAccount(t, "acct-1")
	if err := store.CreateAccount(ctx, account); err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	account.Contact[0] = "mailto:changed-input@example.test"
	got, err := store.Account(ctx, account.ID)
	if err != nil {
		t.Fatalf("Account: %v", err)
	}
	if got.Contact[0] != "mailto:admin@example.test" {
		t.Fatalf("stored account changed through the input: %q", got.Contact[0])
	}
	got.Contact[0] = "mailto:changed-output@example.test"
	got.Status = acmeserver.AccountRevoked
	again, err := store.Account(ctx, account.ID)
	if err != nil {
		t.Fatalf("Account: %v", err)
	}
	if again.Contact[0] != "mailto:admin@example.test" || again.Status != acmeserver.AccountValid {
		t.Fatalf("stored account changed through a returned copy: %+v", again)
	}
}

// Checks that exactly one of several racing creates with the same key wins.
func testConcurrentCreate(t *testing.T, store acmeserver.Store) {
	ctx := context.Background()
	template := NewAccount(t, "template")
	const racers = 16
	errs := make([]error, racers)
	var wg sync.WaitGroup
	for i := range racers {
		wg.Go(func() {
			account := *template
			account.ID = fmt.Sprintf("acct-%d", i)
			account.Contact = []string{"mailto:admin@example.test"}
			errs[i] = store.CreateAccount(ctx, &account)
		})
	}
	wg.Wait()
	created := 0
	for i, err := range errs {
		switch {
		case err == nil:
			created++
		case errors.Is(err, acmeserver.ErrConflict):
		default:
			t.Fatalf("racer %d: unexpected error %v", i, err)
		}
	}
	if created != 1 {
		t.Fatalf("%d racing creates succeeded, want exactly 1", created)
	}
}

// Checks that operations observe context cancellation.
func testCanceledContext(t *testing.T, store acmeserver.Store) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	account := NewAccount(t, "acct-1")
	err := store.CreateAccount(ctx, account)
	if err == nil || errors.Is(err, acmeserver.ErrConflict) || errors.Is(err, acmeserver.ErrNotFound) {
		t.Fatalf("CreateAccount(canceled) error = %v, want a context error", err)
	}
	if _, err := store.Account(context.Background(), account.ID); !errors.Is(err, acmeserver.ErrNotFound) {
		t.Fatalf("canceled create stored the account: %v", err)
	}
}

// Compares two accounts field by field, comparing keys by their PKIX encoding.
func assertAccountEqual(t *testing.T, got, want *acmeserver.Account) {
	t.Helper()
	if got.ID != want.ID || got.Status != want.Status || got.KeyThumbprint != want.KeyThumbprint ||
		got.TermsOfServiceAgreed != want.TermsOfServiceAgreed || got.ExternalAccountID != want.ExternalAccountID ||
		!got.CreatedAt.Equal(want.CreatedAt) || got.Revision != want.Revision {
		t.Fatalf("account mismatch\n got: %+v\nwant: %+v", got, want)
	}
	if fmt.Sprint(got.Contact) != fmt.Sprint(want.Contact) {
		t.Fatalf("contact mismatch: got %v, want %v", got.Contact, want.Contact)
	}
	gotKey, err := x509.MarshalPKIXPublicKey(got.Key)
	if err != nil {
		t.Fatalf("marshal returned key: %v", err)
	}
	wantKey, err := x509.MarshalPKIXPublicKey(want.Key)
	if err != nil {
		t.Fatalf("marshal expected key: %v", err)
	}
	if string(gotKey) != string(wantKey) {
		t.Fatalf("key mismatch")
	}
}
