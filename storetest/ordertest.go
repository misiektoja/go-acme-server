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

// The fixed clock value the order tests use.
var testNow = time.Date(2026, 3, 27, 10, 0, 0, 0, time.UTC)

// Returns a pending order with one authorization and one challenge per identifier.
func NewOrder(t *testing.T, accountID, orderID string, identifiers ...string) (*acmeserver.Order,
	[]*acmeserver.Authorization, []*acmeserver.Challenge) {
	t.Helper()
	order := &acmeserver.Order{
		ID:        orderID,
		AccountID: accountID,
		Status:    acmeserver.OrderPending,
		Expires:   testNow.Add(7 * 24 * time.Hour),
		CreatedAt: testNow,
	}
	authzs := make([]*acmeserver.Authorization, 0, len(identifiers))
	challenges := make([]*acmeserver.Challenge, 0, len(identifiers))
	for i, name := range identifiers {
		id := acmeserver.Identifier{Type: acmeserver.IdentifierDNS, Value: name}
		order.Identifiers = append(order.Identifiers, id)
		authz := &acmeserver.Authorization{
			ID:         fmt.Sprintf("%s-authz-%d", orderID, i),
			AccountID:  accountID,
			OrderID:    orderID,
			Identifier: id,
			Status:     acmeserver.AuthorizationPending,
			Expires:    order.Expires,
			CreatedAt:  testNow,
		}
		challenge := &acmeserver.Challenge{
			ID:              fmt.Sprintf("%s-chall-%d", orderID, i),
			AuthorizationID: authz.ID,
			AccountID:       accountID,
			Type:            acmeserver.ChallengeHTTP01,
			Status:          acmeserver.ChallengePending,
			Token:           fmt.Sprintf("token-%d", i),
		}
		authz.ChallengeIDs = []string{challenge.ID}
		order.AuthorizationIDs = append(order.AuthorizationIDs, authz.ID)
		authzs = append(authzs, authz)
		challenges = append(challenges, challenge)
	}
	return order, authzs, challenges
}

// Creates an account and an order with two identifiers and returns them.
func seedOrder(t *testing.T, store acmeserver.Store) (*acmeserver.Order, []*acmeserver.Authorization,
	[]*acmeserver.Challenge) {
	t.Helper()
	ctx := context.Background()
	account := NewAccount(t, "acct-1")
	if err := store.CreateAccount(ctx, account); err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	order, authzs, challenges := NewOrder(t, account.ID, "order-1", "a.example", "b.example")
	if err := store.CreateOrder(ctx, order, authzs, challenges); err != nil {
		t.Fatalf("CreateOrder: %v", err)
	}
	return order, authzs, challenges
}

// The IDs of the two tasks the claim test enqueues.
const (
	earlyTask = "early"
	lateTask  = "late"
)

// Returns a task for the target.
func newTask(id string, kind acmeserver.TaskKind, target string, runAt time.Time) *acmeserver.Task {
	return &acmeserver.Task{ID: id, Kind: kind, TargetID: target, AccountID: "acct-1", RunAt: runAt, CreatedAt: runAt}
}

// Checks that an order reads back with its authorizations and challenges at revision 1.
func testCreateOrder(t *testing.T, store acmeserver.Store) {
	ctx := context.Background()
	order, authzs, challenges := seedOrder(t, store)
	if order.Revision != 1 || authzs[0].Revision != 1 || challenges[0].Revision != 1 {
		t.Fatalf("CreateOrder revisions = %d %d %d, want 1", order.Revision, authzs[0].Revision, challenges[0].Revision)
	}
	got, err := store.Order(ctx, order.ID)
	if err != nil {
		t.Fatalf("Order: %v", err)
	}
	assertOrderEqual(t, got, order)
	authz, err := store.Authorization(ctx, authzs[1].ID)
	if err != nil {
		t.Fatalf("Authorization: %v", err)
	}
	if authz.OrderID != order.ID || authz.Identifier.Value != "b.example" || len(authz.ChallengeIDs) != 1 {
		t.Fatalf("Authorization = %+v", authz)
	}
	challenge, err := store.Challenge(ctx, challenges[1].ID)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	if challenge.AuthorizationID != authz.ID || challenge.Token != "token-1" ||
		challenge.Status != acmeserver.ChallengePending {
		t.Fatalf("Challenge = %+v", challenge)
	}
	for _, missing := range []func() error{
		func() error { _, err := store.Order(ctx, "missing"); return err },
		func() error { _, err := store.Authorization(ctx, "missing"); return err },
		func() error { _, err := store.Challenge(ctx, "missing"); return err },
		func() error { _, err := store.Certificate(ctx, "missing"); return err },
	} {
		if err := missing(); !errors.Is(err, acmeserver.ErrNotFound) {
			t.Fatalf("lookup of a missing resource = %v, want ErrNotFound", err)
		}
	}
}

// Checks that duplicate order, authorization or challenge IDs are refused without side effects.
func testCreateOrderConflicts(t *testing.T, store acmeserver.Store) {
	ctx := context.Background()
	order, authzs, _ := seedOrder(t, store)
	dup, _, _ := NewOrder(t, order.AccountID, order.ID, "c.example")
	if err := store.CreateOrder(ctx, dup, nil, nil); !errors.Is(err, acmeserver.ErrConflict) {
		t.Fatalf("CreateOrder(same order ID) error = %v, want ErrConflict", err)
	}
	second, secondAuthzs, secondChallenges := NewOrder(t, order.AccountID, "order-2", "c.example")
	secondAuthzs[0].ID = authzs[0].ID
	if err := store.CreateOrder(ctx, second, secondAuthzs, secondChallenges); !errors.Is(err, acmeserver.ErrConflict) {
		t.Fatalf("CreateOrder(same authz ID) error = %v, want ErrConflict", err)
	}
	if _, err := store.Order(ctx, "order-2"); !errors.Is(err, acmeserver.ErrNotFound) {
		t.Fatalf("conflicting CreateOrder left the order behind: %v", err)
	}
	ids, err := store.OrderIDs(ctx, order.AccountID, "", 10)
	if err != nil || len(ids) != 1 {
		t.Fatalf("OrderIDs = %v, %v; want one order", ids, err)
	}
}

// Checks creation order and cursor pagination of order IDs.
func testOrderIDs(t *testing.T, store acmeserver.Store) {
	ctx := context.Background()
	account := NewAccount(t, "acct-1")
	if err := store.CreateAccount(ctx, account); err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	for i := range 5 {
		order, authzs, challenges := NewOrder(t, account.ID, fmt.Sprintf("order-%d", i), "a.example")
		order.CreatedAt = testNow.Add(time.Duration(i) * time.Minute)
		if err := store.CreateOrder(ctx, order, authzs, challenges); err != nil {
			t.Fatalf("CreateOrder: %v", err)
		}
	}
	first, err := store.OrderIDs(ctx, account.ID, "", 2)
	if err != nil || fmt.Sprint(first) != "[order-0 order-1]" {
		t.Fatalf("OrderIDs(first page) = %v, %v", first, err)
	}
	rest, err := store.OrderIDs(ctx, account.ID, "order-1", 10)
	if err != nil || fmt.Sprint(rest) != "[order-2 order-3 order-4]" {
		t.Fatalf("OrderIDs(after order-1) = %v, %v", rest, err)
	}
	last, err := store.OrderIDs(ctx, account.ID, "order-4", 10)
	if err != nil || len(last) != 0 {
		t.Fatalf("OrderIDs(after last) = %v, %v", last, err)
	}
	if _, err := store.OrderIDs(ctx, account.ID, "unknown", 10); !errors.Is(err, acmeserver.ErrNotFound) {
		t.Fatalf("OrderIDs(unknown cursor) error = %v, want ErrNotFound", err)
	}
	none, err := store.OrderIDs(ctx, "other", "", 10)
	if err != nil || len(none) != 0 {
		t.Fatalf("OrderIDs(other account) = %v, %v", none, err)
	}
}

// Checks revision checked authorization updates.
func testUpdateAuthorization(t *testing.T, store acmeserver.Store) {
	ctx := context.Background()
	_, authzs, _ := seedOrder(t, store)
	authz := authzs[0]
	stale := *authz
	authz.Status = acmeserver.AuthorizationDeactivated
	if err := store.UpdateAuthorization(ctx, authz); err != nil {
		t.Fatalf("UpdateAuthorization: %v", err)
	}
	if authz.Revision != 2 {
		t.Fatalf("UpdateAuthorization set Revision %d, want 2", authz.Revision)
	}
	if err := store.UpdateAuthorization(ctx, &stale); !errors.Is(err, acmeserver.ErrRevisionMismatch) {
		t.Fatalf("UpdateAuthorization(stale) error = %v, want ErrRevisionMismatch", err)
	}
	got, err := store.Authorization(ctx, authz.ID)
	if err != nil || got.Status != acmeserver.AuthorizationDeactivated || got.Revision != 2 {
		t.Fatalf("Authorization after update = %+v, %v", got, err)
	}
	missing := *authz
	missing.ID = "missing"
	if err := store.UpdateAuthorization(ctx, &missing); !errors.Is(err, acmeserver.ErrNotFound) {
		t.Fatalf("UpdateAuthorization(missing) error = %v, want ErrNotFound", err)
	}
}

// Checks that accepting a challenge stores it and enqueues its task atomically.
func testAcceptChallenge(t *testing.T, store acmeserver.Store) {
	ctx := context.Background()
	_, _, challenges := seedOrder(t, store)
	challenge := challenges[0]
	stale := *challenge
	challenge.Status = acmeserver.ChallengeProcessing
	challenge.KeyThumbprint = "thumb"
	task := newTask("task-1", acmeserver.TaskValidate, challenge.ID, testNow)
	if err := store.AcceptChallenge(ctx, challenge, task); err != nil {
		t.Fatalf("AcceptChallenge: %v", err)
	}
	if challenge.Revision != 2 {
		t.Fatalf("AcceptChallenge set Revision %d, want 2", challenge.Revision)
	}
	got, err := store.Challenge(ctx, challenge.ID)
	if err != nil || got.Status != acmeserver.ChallengeProcessing || got.KeyThumbprint != "thumb" {
		t.Fatalf("Challenge after accept = %+v, %v", got, err)
	}
	pending, err := store.PendingTasks(ctx, testNow)
	if err != nil || pending != 1 {
		t.Fatalf("PendingTasks = %d, %v; want 1", pending, err)
	}
	stale.Status = acmeserver.ChallengeProcessing
	other := newTask("task-2", acmeserver.TaskValidate, challenge.ID, testNow)
	if err := store.AcceptChallenge(ctx, &stale, other); !errors.Is(err, acmeserver.ErrRevisionMismatch) {
		t.Fatalf("AcceptChallenge(stale) error = %v, want ErrRevisionMismatch", err)
	}
	dupTask := newTask("task-1", acmeserver.TaskValidate, challenges[1].ID, testNow)
	if err := store.AcceptChallenge(ctx, challenges[1], dupTask); !errors.Is(err, acmeserver.ErrConflict) {
		t.Fatalf("AcceptChallenge(duplicate task) error = %v, want ErrConflict", err)
	}
	if got, err := store.Challenge(ctx, challenges[1].ID); err != nil || got.Revision != 1 {
		t.Fatalf("failed accept changed the challenge: %+v, %v", got, err)
	}
	if pending, _ := store.PendingTasks(ctx, testNow); pending != 1 {
		t.Fatalf("failed accepts enqueued tasks: %d pending", pending)
	}
}

// Checks claim ordering, leases, fences and rescheduling.
func testClaimTask(t *testing.T, store acmeserver.Store) {
	ctx := context.Background()
	_, _, challenges := seedOrder(t, store)
	late := newTask(lateTask, acmeserver.TaskValidate, challenges[0].ID, testNow.Add(time.Hour))
	early := newTask(earlyTask, acmeserver.TaskValidate, challenges[1].ID, testNow)
	challenges[0].Status = acmeserver.ChallengeProcessing
	challenges[1].Status = acmeserver.ChallengeProcessing
	if err := store.AcceptChallenge(ctx, challenges[0], late); err != nil {
		t.Fatalf("AcceptChallenge(late): %v", err)
	}
	if err := store.AcceptChallenge(ctx, challenges[1], early); err != nil {
		t.Fatalf("AcceptChallenge(early): %v", err)
	}
	lease := testNow.Add(2 * time.Minute)
	claimed, err := store.ClaimTask(ctx, testNow, lease)
	if err != nil {
		t.Fatalf("ClaimTask: %v", err)
	}
	if claimed.ID != earlyTask || claimed.Fence != 1 || claimed.Attempts != 1 || !claimed.LeaseUntil.Equal(lease) {
		t.Fatalf("ClaimTask = %+v", claimed)
	}
	if _, err := store.ClaimTask(ctx, testNow, lease); !errors.Is(err, acmeserver.ErrNotFound) {
		t.Fatalf("ClaimTask(leased and future) error = %v, want ErrNotFound", err)
	}
	if pending, _ := store.PendingTasks(ctx, testNow); pending != 0 {
		t.Fatalf("PendingTasks during lease = %d, want 0", pending)
	}
	afterLease := lease.Add(time.Second)
	reclaimed, err := store.ClaimTask(ctx, afterLease, afterLease.Add(time.Minute))
	if err != nil || reclaimed.ID != earlyTask || reclaimed.Fence != 2 || reclaimed.Attempts != 2 {
		t.Fatalf("ClaimTask(after lease) = %+v, %v", reclaimed, err)
	}
	if err := store.FinishTask(ctx, claimed); !errors.Is(err, acmeserver.ErrRevisionMismatch) {
		t.Fatalf("FinishTask(stale fence) error = %v, want ErrRevisionMismatch", err)
	}
	reclaimed.RunAt = afterLease.Add(10 * time.Minute)
	if err := store.RescheduleTask(ctx, reclaimed); err != nil {
		t.Fatalf("RescheduleTask: %v", err)
	}
	_, err = store.ClaimTask(ctx, afterLease.Add(time.Minute), afterLease.Add(2*time.Minute))
	if !errors.Is(err, acmeserver.ErrNotFound) {
		t.Fatalf("ClaimTask(before rescheduled RunAt) error = %v, want ErrNotFound", err)
	}
	if pending, _ := store.PendingTasks(ctx, afterLease.Add(10*time.Minute)); pending != 1 {
		t.Fatalf("PendingTasks at rescheduled time = %d, want 1", pending)
	}
	third, err := store.ClaimTask(ctx, afterLease.Add(10*time.Minute), afterLease.Add(12*time.Minute))
	if err != nil || third.ID != earlyTask || third.Fence != 3 {
		t.Fatalf("ClaimTask(rescheduled) = %+v, %v", third, err)
	}
	if err := store.FinishTask(ctx, third); err != nil {
		t.Fatalf("FinishTask: %v", err)
	}
	if err := store.FinishTask(ctx, third); !errors.Is(err, acmeserver.ErrNotFound) {
		t.Fatalf("FinishTask(finished) error = %v, want ErrNotFound", err)
	}
	remaining, err := store.ClaimTask(ctx, testNow.Add(2*time.Hour), testNow.Add(3*time.Hour))
	if err != nil || remaining.ID != lateTask {
		t.Fatalf("ClaimTask(late) = %+v, %v", remaining, err)
	}
}

// Checks that racing claims hand each task to exactly one worker.
func testConcurrentClaim(t *testing.T, store acmeserver.Store) {
	ctx := context.Background()
	_, _, challenges := seedOrder(t, store)
	for i, ch := range challenges {
		ch.Status = acmeserver.ChallengeProcessing
		task := newTask(fmt.Sprintf("task-%d", i), acmeserver.TaskValidate, ch.ID, testNow)
		if err := store.AcceptChallenge(ctx, ch, task); err != nil {
			t.Fatalf("AcceptChallenge: %v", err)
		}
	}
	const workers = 8
	claimed := make([]*acmeserver.Task, workers)
	errs := make([]error, workers)
	var wg sync.WaitGroup
	for i := range workers {
		wg.Go(func() { claimed[i], errs[i] = store.ClaimTask(ctx, testNow, testNow.Add(time.Minute)) })
	}
	wg.Wait()
	seen := map[string]int{}
	for i := range workers {
		switch {
		case errs[i] == nil:
			seen[claimed[i].ID]++
		case errors.Is(errs[i], acmeserver.ErrNotFound):
		default:
			t.Fatalf("worker %d: %v", i, errs[i])
		}
	}
	if len(seen) != len(challenges) {
		t.Fatalf("claimed %d distinct tasks, want %d", len(seen), len(challenges))
	}
	for id, n := range seen {
		if n != 1 {
			t.Fatalf("task %s was claimed %d times", id, n)
		}
	}
}

// Checks that a validation outcome updates three resources and removes the task atomically.
func testCompleteValidation(t *testing.T, store acmeserver.Store) {
	ctx := context.Background()
	order, authzs, challenges := seedOrder(t, store)
	challenge := challenges[0]
	challenge.Status = acmeserver.ChallengeProcessing
	task1 := newTask("task-1", acmeserver.TaskValidate, challenge.ID, testNow)
	if err := store.AcceptChallenge(ctx, challenge, task1); err != nil {
		t.Fatalf("AcceptChallenge: %v", err)
	}
	task, err := store.ClaimTask(ctx, testNow, testNow.Add(time.Minute))
	if err != nil {
		t.Fatalf("ClaimTask: %v", err)
	}
	staleOrder := *order
	challenge.Status = acmeserver.ChallengeValid
	challenge.Validated = testNow
	authz := authzs[0]
	authz.Status = acmeserver.AuthorizationValid
	if err := store.CompleteValidation(ctx, task, challenge, authz, order); err != nil {
		t.Fatalf("CompleteValidation: %v", err)
	}
	if challenge.Revision != 3 || authz.Revision != 2 || order.Revision != 2 {
		t.Fatalf("revisions after completion = %d %d %d", challenge.Revision, authz.Revision, order.Revision)
	}
	gotOrder, err := store.Order(ctx, order.ID)
	if err != nil || gotOrder.Revision != 2 || gotOrder.Status != acmeserver.OrderPending {
		t.Fatalf("Order after completion = %+v, %v", gotOrder, err)
	}
	gotAuthz, err := store.Authorization(ctx, authz.ID)
	if err != nil || gotAuthz.Status != acmeserver.AuthorizationValid {
		t.Fatalf("Authorization after completion = %+v, %v", gotAuthz, err)
	}
	_, err = store.ClaimTask(ctx, testNow.Add(time.Hour), testNow.Add(2*time.Hour))
	if !errors.Is(err, acmeserver.ErrNotFound) {
		t.Fatalf("task survived completion: %v", err)
	}
	if err := store.CompleteValidation(ctx, task, challenge, authz, order); !errors.Is(err, acmeserver.ErrNotFound) {
		t.Fatalf("CompleteValidation(finished task) error = %v, want ErrNotFound", err)
	}
	second := challenges[1]
	second.Status = acmeserver.ChallengeProcessing
	task2Spec := newTask("task-2", acmeserver.TaskValidate, second.ID, testNow)
	if err := store.AcceptChallenge(ctx, second, task2Spec); err != nil {
		t.Fatalf("AcceptChallenge(second): %v", err)
	}
	task2, err := store.ClaimTask(ctx, testNow, testNow.Add(time.Minute))
	if err != nil {
		t.Fatalf("ClaimTask(second): %v", err)
	}
	second.Status = acmeserver.ChallengeValid
	authzs[1].Status = acmeserver.AuthorizationValid
	staleOrder.Status = acmeserver.OrderReady
	err = store.CompleteValidation(ctx, task2, second, authzs[1], &staleOrder)
	if !errors.Is(err, acmeserver.ErrRevisionMismatch) {
		t.Fatalf("CompleteValidation(stale order) error = %v, want ErrRevisionMismatch", err)
	}
	if got, _ := store.Challenge(ctx, second.ID); got.Status != acmeserver.ChallengeProcessing || got.Revision != 2 {
		t.Fatalf("failed completion changed the challenge: %+v", got)
	}
	if got, _ := store.Authorization(ctx, authzs[1].ID); got.Status != acmeserver.AuthorizationPending {
		t.Fatalf("failed completion changed the authorization: %+v", got)
	}
	if pending, _ := store.PendingTasks(ctx, testNow.Add(30*time.Second)); pending != 0 {
		t.Fatalf("PendingTasks with an active lease = %d, want 0", pending)
	}
	order.Status = acmeserver.OrderReady
	if err := store.CompleteValidation(ctx, task2, second, authzs[1], order); err != nil {
		t.Fatalf("CompleteValidation(fresh order): %v", err)
	}
	if got, _ := store.Order(ctx, order.ID); got.Status != acmeserver.OrderReady || got.Revision != 3 {
		t.Fatalf("Order after second completion = %+v", got)
	}
}

// Checks finalization and issuance completion including certificate publication.
func testFinalizeAndIssue(t *testing.T, store acmeserver.Store) {
	ctx := context.Background()
	order, _, _ := seedOrder(t, store)
	stale := *order
	order.Status = acmeserver.OrderProcessing
	order.CSR = []byte{0x30, 0x03, 0x02, 0x01, 0x01}
	if err := store.FinalizeOrder(ctx, order, newTask("issue-1", acmeserver.TaskIssue, order.ID, testNow)); err != nil {
		t.Fatalf("FinalizeOrder: %v", err)
	}
	if order.Revision != 2 {
		t.Fatalf("FinalizeOrder set Revision %d, want 2", order.Revision)
	}
	stale.Status = acmeserver.OrderProcessing
	err := store.FinalizeOrder(ctx, &stale, newTask("issue-2", acmeserver.TaskIssue, order.ID, testNow))
	if !errors.Is(err, acmeserver.ErrRevisionMismatch) {
		t.Fatalf("FinalizeOrder(stale) error = %v, want ErrRevisionMismatch", err)
	}
	task, err := store.ClaimTask(ctx, testNow, testNow.Add(time.Minute))
	if err != nil || task.Kind != acmeserver.TaskIssue || task.TargetID != order.ID {
		t.Fatalf("ClaimTask = %+v, %v", task, err)
	}
	cert := &acmeserver.Certificate{
		ID:        "cert-1",
		AccountID: order.AccountID,
		OrderID:   order.ID,
		Chain:     [][]byte{{0x30, 0x00}, {0x30, 0x01}},
		NotBefore: testNow,
		NotAfter:  testNow.Add(90 * 24 * time.Hour),
		Validations: []acmeserver.Validation{
			{Identifier: order.Identifiers[0], Type: acmeserver.ChallengeHTTP01, Validated: testNow},
		},
		CreatedAt: testNow,
	}
	order.Status = acmeserver.OrderValid
	order.CertificateID = cert.ID
	if err := store.CompleteIssuance(ctx, task, order, cert); err != nil {
		t.Fatalf("CompleteIssuance: %v", err)
	}
	if cert.Revision != 1 || order.Revision != 3 {
		t.Fatalf("revisions after issuance = cert %d order %d", cert.Revision, order.Revision)
	}
	gotCert, err := store.Certificate(ctx, cert.ID)
	if err != nil {
		t.Fatalf("Certificate: %v", err)
	}
	if len(gotCert.Chain) != 2 || gotCert.OrderID != order.ID || len(gotCert.Validations) != 1 {
		t.Fatalf("Certificate = %+v", gotCert)
	}
	gotCert.Chain[0][0] = 0xff
	again, _ := store.Certificate(ctx, cert.ID)
	if again.Chain[0][0] != 0x30 {
		t.Fatal("stored certificate changed through a returned copy")
	}
	gotOrder, _ := store.Order(ctx, order.ID)
	if gotOrder.Status != acmeserver.OrderValid || gotOrder.CertificateID != cert.ID ||
		string(gotOrder.CSR) != string(order.CSR) {
		t.Fatalf("Order after issuance = %+v", gotOrder)
	}
	_, err = store.ClaimTask(ctx, testNow.Add(time.Hour), testNow.Add(2*time.Hour))
	if !errors.Is(err, acmeserver.ErrNotFound) {
		t.Fatalf("issue task survived completion: %v", err)
	}
	staleCert := *gotCert
	gotOrder.Status = acmeserver.OrderInvalid
	gotCert.Revoked = true
	gotCert.RevokedAt = testNow.Add(time.Hour)
	gotCert.RevocationReason = 1
	if err := store.UpdateCertificate(ctx, gotCert); err != nil {
		t.Fatalf("UpdateCertificate: %v", err)
	}
	if err := store.UpdateCertificate(ctx, &staleCert); !errors.Is(err, acmeserver.ErrRevisionMismatch) {
		t.Fatalf("UpdateCertificate(stale) error = %v, want ErrRevisionMismatch", err)
	}
	revoked, _ := store.Certificate(ctx, cert.ID)
	if !revoked.Revoked || revoked.RevocationReason != 1 || revoked.Revision != 2 {
		t.Fatalf("Certificate after revocation = %+v", revoked)
	}
}

// Checks that a failed issuance records the order outcome without a certificate and that a
// duplicate certificate ID is refused.
func testIssuanceFailureAndDuplicate(t *testing.T, store acmeserver.Store) {
	ctx := context.Background()
	order, _, _ := seedOrder(t, store)
	order.Status = acmeserver.OrderProcessing
	if err := store.FinalizeOrder(ctx, order, newTask("issue-1", acmeserver.TaskIssue, order.ID, testNow)); err != nil {
		t.Fatalf("FinalizeOrder: %v", err)
	}
	task, err := store.ClaimTask(ctx, testNow, testNow.Add(time.Minute))
	if err != nil {
		t.Fatalf("ClaimTask: %v", err)
	}
	order.Status = acmeserver.OrderInvalid
	order.Error = acmeserver.NewProblem(acmeserver.ErrorServerInternal, "issuer rejected the request")
	if err := store.CompleteIssuance(ctx, task, order, nil); err != nil {
		t.Fatalf("CompleteIssuance(failure): %v", err)
	}
	got, _ := store.Order(ctx, order.ID)
	if got.Status != acmeserver.OrderInvalid || got.Error == nil || got.Error.Type != acmeserver.ErrorServerInternal {
		t.Fatalf("Order after failure = %+v", got)
	}
	got.Error.Detail = "changed"
	if again, _ := store.Order(ctx, order.ID); again.Error.Detail != "issuer rejected the request" {
		t.Fatal("stored order error changed through a returned copy")
	}

	second, authzs, challenges := NewOrder(t, order.AccountID, "order-2", "c.example")
	if err := store.CreateOrder(ctx, second, authzs, challenges); err != nil {
		t.Fatalf("CreateOrder: %v", err)
	}
	second.Status = acmeserver.OrderProcessing
	if err := store.FinalizeOrder(ctx, second, newTask("issue-2", acmeserver.TaskIssue, second.ID, testNow)); err != nil {
		t.Fatalf("FinalizeOrder(second): %v", err)
	}
	task, err = store.ClaimTask(ctx, testNow, testNow.Add(time.Minute))
	if err != nil {
		t.Fatalf("ClaimTask(second): %v", err)
	}
	cert := &acmeserver.Certificate{ID: "cert-dup", AccountID: order.AccountID, OrderID: second.ID,
		Chain: [][]byte{{0x30}}}
	second.Status = acmeserver.OrderValid
	if err := store.CompleteIssuance(ctx, task, second, cert); err != nil {
		t.Fatalf("CompleteIssuance: %v", err)
	}
	third, authzs, challenges := NewOrder(t, order.AccountID, "order-3", "d.example")
	if err := store.CreateOrder(ctx, third, authzs, challenges); err != nil {
		t.Fatalf("CreateOrder(third): %v", err)
	}
	third.Status = acmeserver.OrderProcessing
	if err := store.FinalizeOrder(ctx, third, newTask("issue-3", acmeserver.TaskIssue, third.ID, testNow)); err != nil {
		t.Fatalf("FinalizeOrder(third): %v", err)
	}
	task, err = store.ClaimTask(ctx, testNow, testNow.Add(time.Minute))
	if err != nil {
		t.Fatalf("ClaimTask(third): %v", err)
	}
	dup := &acmeserver.Certificate{ID: "cert-dup", AccountID: order.AccountID, OrderID: third.ID, Chain: [][]byte{{0x30}}}
	third.Status = acmeserver.OrderValid
	if err := store.CompleteIssuance(ctx, task, third, dup); !errors.Is(err, acmeserver.ErrConflict) {
		t.Fatalf("CompleteIssuance(duplicate cert) error = %v, want ErrConflict", err)
	}
	if got, _ := store.Order(ctx, third.ID); got.Status != acmeserver.OrderProcessing {
		t.Fatalf("failed issuance changed the order: %+v", got)
	}
	if _, err := store.ClaimTask(ctx, testNow.Add(time.Hour), testNow.Add(2*time.Hour)); err != nil {
		t.Fatalf("task of the failed issuance is gone: %v", err)
	}
}

// Compares two orders field by field.
func assertOrderEqual(t *testing.T, got, want *acmeserver.Order) {
	t.Helper()
	if got.ID != want.ID || got.AccountID != want.AccountID || got.Status != want.Status ||
		!got.Expires.Equal(want.Expires) || !got.CreatedAt.Equal(want.CreatedAt) || got.Revision != want.Revision ||
		fmt.Sprint(got.Identifiers) != fmt.Sprint(want.Identifiers) ||
		fmt.Sprint(got.AuthorizationIDs) != fmt.Sprint(want.AuthorizationIDs) {
		t.Fatalf("order mismatch\n got: %+v\nwant: %+v", got, want)
	}
}
