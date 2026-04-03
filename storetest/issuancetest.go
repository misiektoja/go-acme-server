package storetest

import (
	"errors"
	"testing"
	"time"

	acmeserver "github.com/misiektoja/go-acme-server"
)

// Requires unchanged authorization revisions before dispatch and preserves unpublished CA results.
func testDispatchSnapshot(t *testing.T, store acmeserver.Store) {
	ctx := t.Context()
	order, authzs, _ := seedOrder(t, store)
	account, err := store.Account(ctx, order.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range authzs {
		a.Status = acmeserver.AuthorizationValid
		if err := store.UpdateAuthorization(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	order.Status = acmeserver.OrderProcessing
	if err := store.FinalizeOrder(ctx, order, newTask("dispatch", acmeserver.TaskIssue, order.ID, testNow)); err != nil {
		t.Fatal(err)
	}
	task, err := store.ClaimTask(ctx, testNow, testNow.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	order.Issuance = &acmeserver.IssuanceState{OperationID: task.ID, AuthorizedAt: testNow, Deadline: order.Expires,
		Validations: []acmeserver.Validation{{Identifier: order.Identifiers[0], Type: acmeserver.ChallengeHTTP01,
			Validated: testNow}}}
	stale := *authzs[0]
	if err := store.UpdateAuthorization(ctx, authzs[0]); err != nil {
		t.Fatal(err)
	}
	checked := append([]*acmeserver.Authorization(nil), authzs...)
	checked[0] = &stale
	revision := order.Revision
	if err := store.BeginIssuance(ctx, task, order, account, checked); !errors.Is(err, acmeserver.ErrRevisionMismatch) {
		t.Fatalf("stale dispatch = %v", err)
	}
	stored, err := store.Order(ctx, order.ID)
	if err != nil || stored.Issuance != nil || order.Revision != revision {
		t.Fatalf("failed dispatch changed state: %+v, %v", stored, err)
	}
	if err := store.BeginIssuance(ctx, task, order, account, authzs); err != nil {
		t.Fatal(err)
	}
	if err := store.BeginIssuance(ctx, task, order, account, authzs); !errors.Is(err, acmeserver.ErrRevisionMismatch) {
		t.Fatalf("repeated dispatch = %v", err)
	}
	authzs[0].Status = acmeserver.AuthorizationDeactivated
	if err := store.UpdateAuthorization(ctx, authzs[0]); err != nil {
		t.Fatal(err)
	}
	stored, err = store.Order(ctx, order.ID)
	if err != nil || stored.Status != acmeserver.OrderProcessing || stored.Issuance == nil {
		t.Fatalf("dispatched recovery lost: %+v, %v", stored, err)
	}
	order.Status = acmeserver.OrderInvalid
	order.UnpublishedResult = &acmeserver.IssueResult{Chain: [][]byte{[]byte("unacceptable CA result")},
		CAReference: "retained-reference",
		Rejected:    acmeserver.NewProblem(acmeserver.ErrorServerInternal, "conflicting result")}
	if err := store.CompleteIssuance(ctx, task, order, nil); err != nil {
		t.Fatal(err)
	}
	order.UnpublishedResult.Chain[0][0] = 'x'
	stored, err = store.Order(ctx, order.ID)
	if err != nil || stored.UnpublishedResult == nil ||
		string(stored.UnpublishedResult.Chain[0]) != "unacceptable CA result" ||
		stored.UnpublishedResult.CAReference != "retained-reference" || stored.UnpublishedResult.Rejected == nil {
		t.Fatalf("retained result = %+v, %v", stored, err)
	}
	stored.Issuance.Validations[0].Identifier.Value = "changed.test"
	again, err := store.Order(ctx, order.ID)
	if err != nil || again.Issuance.Validations[0].Identifier != order.Identifiers[0] {
		t.Fatal("issuance evidence aliases caller state")
	}
}

// Distinguishes base and wildcard scope and excludes expired or deactivated authorization.
func testAuthorizationScope(t *testing.T, store acmeserver.Store) {
	ctx := t.Context()
	account := NewAccount(t, "scope-account")
	if err := store.CreateAccount(ctx, account); err != nil {
		t.Fatal(err)
	}
	order, authzs, challenges := NewOrder(t, account.ID, "scope-order", "a.test", "a.test")
	authzs[1].Wildcard = true
	order.Identifiers[1].Value = "*.a.test"
	for _, a := range authzs {
		a.Status = acmeserver.AuthorizationValid
	}
	if err := store.CreateOrder(ctx, order, authzs, challenges); err != nil {
		t.Fatal(err)
	}
	assertAuthorized(t, store, account.ID, order.Identifiers, testNow, true)
	assertAuthorized(t, store, account.ID, order.Identifiers, order.Expires, false)
	assertAuthorized(t, store, "other-account", order.Identifiers, testNow, false)
	assertAuthorized(t, store, account.ID, nil, testNow, false)
	authzs[1].Status = acmeserver.AuthorizationDeactivated
	if err := store.UpdateAuthorization(ctx, authzs[1]); err != nil {
		t.Fatal(err)
	}
	assertAuthorized(t, store, account.ID, order.Identifiers[:1], testNow, true)
	assertAuthorized(t, store, account.ID, order.Identifiers, testNow, false)
	stored, err := store.Order(ctx, order.ID)
	if err != nil || stored.Status != acmeserver.OrderInvalid {
		t.Fatalf("order not invalidated: %+v, %v", stored, err)
	}
	account.Status = acmeserver.AccountDeactivated
	if err := store.UpdateAccount(ctx, account); err != nil {
		t.Fatal(err)
	}
	assertAuthorized(t, store, account.ID, order.Identifiers[:1], testNow, false)
}

// Checks the consistent authorization lookup without treating backend errors as a refusal.
func assertAuthorized(t *testing.T, store acmeserver.Store, accountID string, identifiers []acmeserver.Identifier, now time.Time, want bool) {
	t.Helper()
	got, err := store.AuthorizedFor(t.Context(), accountID, identifiers, now)
	if err != nil || got != want {
		t.Fatalf("AuthorizedFor(%s, %v) = %v, %v, want %v", accountID, identifiers, got, err, want)
	}
}
