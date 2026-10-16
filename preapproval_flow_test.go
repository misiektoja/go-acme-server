package acmeserver_test

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	acmeserver "github.com/misiektoja/go-acme-server"
)

// A Policy that authorizes every name below approved.test without a challenge.
type preApprovingPolicy struct {
	acmeserver.AllowAll
	// Replaces the answer when set.
	answer func(order *acmeserver.Order) ([]acmeserver.Identifier, error)
}

// Returns the identifiers below approved.test or the scripted answer.
func (p preApprovingPolicy) PreApprove(_ context.Context, _ *acmeserver.Account, order *acmeserver.Order) ([]acmeserver.Identifier, error) {
	if p.answer != nil {
		return p.answer(order)
	}
	var approved []acmeserver.Identifier
	for _, id := range order.Identifiers {
		if strings.HasSuffix(id.Value, ".approved.test") {
			approved = append(approved, id)
		}
	}
	return approved, nil
}

// Starts an order whose names are all approved as ready, issues without a challenge and tells the
// CA which identifiers were pre-approved.
func TestPreApprovedOrderStartsReady(t *testing.T) {
	f := newFlow(t, func(c *acmeserver.Config) { c.Policy = preApprovingPolicy{} })
	f.runWorker()
	c := f.newClient()
	c.register()
	location, order := c.newOrder("www.approved.test", "*.approved.test")
	if order.Status != statusReady {
		t.Fatalf("order status = %q, want ready", order.Status)
	}
	for _, url := range order.Authorizations {
		var authz authzBody
		c.get(url, &authz)
		if authz.Status != statusValid || len(authz.Challenges) != 0 || authz.Expires == "" {
			t.Fatalf("authorization = %+v, want valid without challenges", authz)
		}
	}
	if rec := c.finalize(order, newKey(t)); rec.Code != http.StatusOK {
		t.Fatalf("finalize = %d %s", rec.Code, rec.Body.String())
	}
	c.waitOrder(location, statusValid)
	if f.validator.callCount() != 0 {
		t.Fatal("a validator ran for pre-approved names")
	}
	f.ca.mu.Lock()
	validations := f.ca.calls[0].Validations
	f.ca.mu.Unlock()
	if len(validations) != 2 {
		t.Fatalf("validations = %+v", validations)
	}
	for _, v := range validations {
		if !v.PreApproved || v.Type != "" || v.Validated.IsZero() {
			t.Fatalf("validation = %+v, want pre-approved evidence", v)
		}
	}
}

// Leaves the names that are not approved to their challenges.
func TestPartlyPreApprovedOrderWaitsForChallenges(t *testing.T) {
	f := newFlow(t, func(c *acmeserver.Config) { c.Policy = preApprovingPolicy{} })
	f.runWorker()
	c := f.newClient()
	c.register()
	location, order := c.newOrder("www.approved.test", "other.test")
	if order.Status != statusPending {
		t.Fatalf("order status = %q, want pending", order.Status)
	}
	c.respondHTTP01(order)
	c.waitOrder(location, statusReady)
	if calls := f.validator.callCount(); calls != 1 {
		t.Fatalf("validator ran %d times, want once for the name that was not approved", calls)
	}
}

// Refuses the order when the policy refuses it or names an identifier the order lacks.
func TestPreApproverAnswers(t *testing.T) {
	for _, tc := range []struct {
		name   string
		answer func(*acmeserver.Order) ([]acmeserver.Identifier, error)
		status int
		typ    acmeserver.ErrorType
	}{
		{"refusal", func(*acmeserver.Order) ([]acmeserver.Identifier, error) {
			return nil, acmeserver.NewProblem(acmeserver.ErrorRejectedIdentifier, "not approved")
		}, http.StatusBadRequest, acmeserver.ErrorRejectedIdentifier},
		{"foreign identifier", func(*acmeserver.Order) ([]acmeserver.Identifier, error) {
			return []acmeserver.Identifier{{Type: acmeserver.IdentifierDNS, Value: "elsewhere.test"}}, nil
		}, http.StatusInternalServerError, acmeserver.ErrorServerInternal},
		{"changed order", func(order *acmeserver.Order) ([]acmeserver.Identifier, error) {
			order.NotAfter = order.Expires
			return nil, nil
		}, http.StatusInternalServerError, acmeserver.ErrorServerInternal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFlow(t, func(c *acmeserver.Config) { c.Policy = preApprovingPolicy{answer: tc.answer} })
			c := f.newClient()
			c.register()
			rec := c.post(baseURL+"new-order", map[string]any{
				"identifiers": []map[string]string{{"type": "dns", "value": "www.approved.test"}},
			})
			assertProblem(t, rec, tc.status, tc.typ)
		})
	}
}

// Requires proof by a challenge before another account can revoke a certificate. An account that
// holds only pre-approved names may not.
func TestPreApprovalDoesNotAuthorizeRevocation(t *testing.T) {
	f := newFlow(t, func(c *acmeserver.Config) { c.Policy = preApprovingPolicy{} })
	f.runWorker()
	owner := f.newClient()
	owner.register()
	location, order := owner.newOrder("www.approved.test")
	owner.finalize(order, newKey(t))
	valid := owner.waitOrder(location, statusValid)
	chain := parsePEMChain(t, owner.get(valid.Certificate, nil).Body.Bytes())
	payload := map[string]any{"certificate": base64.RawURLEncoding.EncodeToString(chain[0].Raw)}
	other := f.newClient()
	other.register()
	location, _ = other.newOrder("www.approved.test")
	other.waitOrder(location, statusReady)
	assertProblem(t, other.post(baseURL+"revoke-cert", payload), http.StatusForbidden, acmeserver.ErrorUnauthorized)
}
