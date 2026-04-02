package acmeserver_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	acmeserver "github.com/misiektoja/go-acme-server"
)

func TestNewOrderCreatesAuthorizations(t *testing.T) {
	f := newFlow(t, nil)
	c := f.newClient()
	c.register()
	rec := c.post(baseURL+"new-order", map[string]any{
		"identifiers": []map[string]string{{"type": "dns", "value": "WWW.Example.test"}, {"type": "dns", "value": "*.example.test"}},
		"notBefore":   "2026-04-01T00:00:00Z",
		"notAfter":    "2026-04-30T00:00:00Z",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("new-order = %d %s", rec.Code, rec.Body.String())
	}
	location := rec.Header().Get("Location")
	if !strings.HasPrefix(location, baseURL+"order/") {
		t.Fatalf("Location = %q", location)
	}
	var order orderBody
	decode(t, rec, &order)
	if order.Status != statusPending || len(order.Authorizations) != 2 || order.Finalize != location+"/finalize" ||
		order.Certificate != "" || order.Expires == "" || order.NotBefore != "2026-04-01T00:00:00Z" {
		t.Fatalf("order = %+v", order)
	}
	if order.Identifiers[0].Value != "www.example.test" || order.Identifiers[1].Value != "*.example.test" {
		t.Fatalf("identifiers = %v", order.Identifiers)
	}
	var plain, wildcard authzBody
	c.get(order.Authorizations[0], &plain)
	c.get(order.Authorizations[1], &wildcard)
	if plain.Status != statusPending || plain.Wildcard || plain.Identifier.Value != "www.example.test" || len(plain.Challenges) != 2 {
		t.Fatalf("plain authz = %+v", plain)
	}
	if !wildcard.Wildcard || wildcard.Identifier.Value != "example.test" || len(wildcard.Challenges) != 1 ||
		wildcard.Challenges[0].Type != typeDNS01 {
		t.Fatalf("wildcard authz = %+v", wildcard)
	}
	for _, ch := range plain.Challenges {
		if ch.Status != statusPending || len(ch.Token) != 43 || !strings.HasPrefix(ch.URL, baseURL+"chall/") || ch.Validated != "" {
			t.Fatalf("challenge = %+v", ch)
		}
	}
	var fetched orderBody
	c.get(location, &fetched)
	if fetched.Status != statusPending || len(fetched.Authorizations) != 2 {
		t.Fatalf("fetched order = %+v", fetched)
	}
	other := f.newClient()
	other.register()
	assertProblem(t, other.post(location, nil), http.StatusForbidden, acmeserver.ErrorUnauthorized)
	assertProblem(t, other.post(order.Authorizations[0], nil), http.StatusForbidden, acmeserver.ErrorUnauthorized)
	assertProblem(t, other.post(plain.Challenges[0].URL, nil), http.StatusForbidden, acmeserver.ErrorUnauthorized)
	assertProblem(t, c.post(baseURL+"order/unknown", nil), http.StatusNotFound, acmeserver.ErrorMalformed)
	assertProblem(t, c.post(location, map[string]any{}), http.StatusBadRequest, acmeserver.ErrorMalformed)
}

func TestNewOrderRejects(t *testing.T) {
	f := newFlow(t, func(c *acmeserver.Config) {
		c.MaxIdentifiers = 2
		c.Validators = map[acmeserver.ChallengeType]acmeserver.Validator{acmeserver.ChallengeHTTP01: c.Validators[acmeserver.ChallengeHTTP01]}
	})
	c := f.newClient()
	c.register()
	dns := func(values ...string) []map[string]string {
		out := make([]map[string]string, 0, len(values))
		for _, v := range values {
			out = append(out, map[string]string{"type": "dns", "value": v})
		}
		return out
	}
	cases := map[string]struct {
		payload any
		typ     acmeserver.ErrorType
	}{
		"no identifiers":     {map[string]any{"identifiers": []any{}}, acmeserver.ErrorMalformed},
		"too many":           {map[string]any{"identifiers": dns("a.test", "b.test", "c.test")}, acmeserver.ErrorMalformed},
		"unknown type":       {map[string]any{"identifiers": []map[string]string{{"type": "email", "value": "a@b.test"}}}, acmeserver.ErrorUnsupportedIdentifier},
		"ip disabled":        {map[string]any{"identifiers": []map[string]string{{"type": "ip", "value": "192.0.2.1"}}}, acmeserver.ErrorUnsupportedIdentifier},
		"bad name":           {map[string]any{"identifiers": dns("bad..name")}, acmeserver.ErrorRejectedIdentifier},
		"duplicate":          {map[string]any{"identifiers": dns("a.test", "A.test")}, acmeserver.ErrorMalformed},
		"wildcard no dns-01": {map[string]any{"identifiers": dns("*.a.test")}, acmeserver.ErrorRejectedIdentifier},
		"bad notBefore":      {map[string]any{"identifiers": dns("a.test"), "notBefore": "yesterday"}, acmeserver.ErrorMalformed},
		"notAfter before":    {map[string]any{"identifiers": dns("a.test"), "notBefore": "2026-04-02T00:00:00Z", "notAfter": "2026-04-01T00:00:00Z"}, acmeserver.ErrorMalformed},
		"payload not object": {[]int{1}, acmeserver.ErrorMalformed},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			assertProblem(t, c.post(baseURL+"new-order", tc.payload), http.StatusBadRequest, tc.typ)
		})
	}
	if ids, _ := f.store.OrderIDs(t.Context(), strings.TrimPrefix(c.kid, baseURL+"acct/"), "", 10); len(ids) != 0 {
		t.Fatalf("rejected orders were stored: %v", ids)
	}
}

func TestNewOrderIPIdentifiers(t *testing.T) {
	f := newFlow(t, func(c *acmeserver.Config) { c.IPIdentifiers = true })
	c := f.newClient()
	c.register()
	rec := c.post(baseURL+"new-order", map[string]any{"identifiers": []map[string]string{{"type": "ip", "value": "2001:DB8::1"}}})
	if rec.Code != http.StatusCreated {
		t.Fatalf("new-order = %d %s", rec.Code, rec.Body.String())
	}
	var order orderBody
	decode(t, rec, &order)
	var authz authzBody
	c.get(order.Authorizations[0], &authz)
	if authz.Identifier.Type != "ip" || authz.Identifier.Value != "2001:db8::1" || len(authz.Challenges) != 1 ||
		authz.Challenges[0].Type != typeHTTP01 {
		t.Fatalf("ip authz = %+v", authz)
	}
}

func TestOrderPolicyHook(t *testing.T) {
	f := newFlow(t, func(c *acmeserver.Config) { c.Policy = denyPolicy{} })
	c := f.newClient()
	assertProblem(t, c.post(baseURL+"new-account", map[string]any{"termsOfServiceAgreed": true,
		"contact": []string{"mailto:blocked@example.test"}}), http.StatusForbidden, acmeserver.ErrorUnauthorized)
	c.register()
	assertProblem(t, c.post(baseURL+"new-order", map[string]any{"identifiers": []map[string]string{{"type": "dns", "value": "blocked.test"}}}),
		http.StatusBadRequest, acmeserver.ErrorRejectedIdentifier)
	assertProblem(t, c.post(baseURL+"new-order", map[string]any{"identifiers": []map[string]string{{"type": "dns", "value": "broken.test"}}}),
		http.StatusInternalServerError, acmeserver.ErrorServerInternal)
	if !strings.Contains(f.logs.String(), "order policy failed") {
		t.Fatalf("policy error not logged: %s", f.logs.String())
	}
}

func TestAuthorizationDeactivation(t *testing.T) {
	f := newFlow(t, nil)
	c := f.newClient()
	c.register()
	_, order := c.newOrder("a.test")
	assertProblem(t, c.post(order.Authorizations[0], map[string]any{"status": statusValid}), http.StatusBadRequest,
		acmeserver.ErrorMalformed)
	rec := c.post(order.Authorizations[0], map[string]any{"status": "deactivated"})
	if rec.Code != http.StatusOK {
		t.Fatalf("deactivate = %d %s", rec.Code, rec.Body.String())
	}
	var authz authzBody
	decode(t, rec, &authz)
	if authz.Status != "deactivated" {
		t.Fatalf("authz = %+v", authz)
	}
	rec = c.post(order.Authorizations[0], map[string]any{"status": "deactivated"})
	if rec.Code != http.StatusOK {
		t.Fatalf("repeated deactivate = %d", rec.Code)
	}
	assertProblem(t, c.post(authz.Challenges[0].URL, map[string]any{}), http.StatusBadRequest, acmeserver.ErrorMalformed)
	var ch challengeBody
	c.get(authz.Challenges[0].URL, &ch)
	if ch.Status != statusPending {
		t.Fatalf("challenge after refused response = %+v", ch)
	}
}

func TestIssuanceFlow(t *testing.T) {
	f := newFlow(t, nil)
	f.runWorker()
	c := f.newClient()
	c.register()
	location, order := c.newOrder("a.test", "b.test")
	var authz authzBody
	c.get(order.Authorizations[0], &authz)
	var http01 challengeBody
	for _, ch := range authz.Challenges {
		if ch.Type == typeHTTP01 {
			http01 = ch
		}
	}
	rec := c.post(http01.URL, map[string]any{})
	if rec.Code != http.StatusOK {
		t.Fatalf("challenge response = %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(strings.Join(rec.Header().Values("Link"), " "), `<`+order.Authorizations[0]+`>;rel="up"`) {
		t.Fatalf("Link = %v", rec.Header().Values("Link"))
	}
	var responded challengeBody
	decode(t, rec, &responded)
	if responded.Status != statusProcessing && responded.Status != statusValid {
		t.Fatalf("challenge after response = %+v", responded)
	}
	waitFor(t, "first authorization valid", func() bool {
		c.get(order.Authorizations[0], &authz)
		return authz.Status == statusValid
	})
	if len(authz.Challenges) != 1 || authz.Challenges[0].Type != typeHTTP01 || authz.Challenges[0].Validated == "" {
		t.Fatalf("valid authz lists %+v", authz.Challenges)
	}
	if n := f.validator.callCount(); n != 1 {
		t.Fatalf("validator called %d times", n)
	}
	call := f.validator.calls[0]
	if call.Identifier.Value != "a.test" || call.KeyAuthorization != http01.Token+"."+thumbprint(t, &c.key.PublicKey) ||
		call.AccountKeyThumbprint != thumbprint(t, &c.key.PublicKey) || call.Challenge.Type != acmeserver.ChallengeHTTP01 {
		t.Fatalf("validation request = %+v", call)
	}
	var current orderBody
	c.get(location, &current)
	if current.Status != statusPending {
		t.Fatalf("order with one valid authz = %s", current.Status)
	}
	certKey := newKey(t)
	assertProblem(t, c.finalize(order, certKey), http.StatusForbidden, acmeserver.ErrorOrderNotReady)
	c.respondHTTP01(order)
	c.waitOrder(location, statusReady)
	csr := makeCSR(t, certKey, []string{"a.test", "b.test"}, nil)
	rec = c.finalizeCSR(order, csr)
	if rec.Code != http.StatusOK {
		t.Fatalf("finalize = %d %s", rec.Code, rec.Body.String())
	}
	var finalized orderBody
	decode(t, rec, &finalized)
	if finalized.Status != statusProcessing && finalized.Status != statusValid {
		t.Fatalf("order after finalize = %+v", finalized)
	}
	if finalized.Status == statusProcessing && rec.Header().Get("Retry-After") == "" {
		t.Fatal("processing order without Retry-After")
	}
	valid := c.waitOrder(location, statusValid)
	if !strings.HasPrefix(valid.Certificate, baseURL+"cert/") {
		t.Fatalf("certificate URL = %q", valid.Certificate)
	}
	again := c.finalizeCSR(order, csr)
	if again.Code != http.StatusOK {
		t.Fatalf("repeated finalize with the same CSR = %d %s", again.Code, again.Body.String())
	}
	assertProblem(t, c.finalize(order, newKey(t)), http.StatusForbidden, acmeserver.ErrorOrderNotReady)
	checkIssuedCertificate(t, f, c, valid.Certificate, certKey)
	other := f.newClient()
	other.register()
	assertProblem(t, other.post(valid.Certificate, nil), http.StatusForbidden, acmeserver.ErrorUnauthorized)
	assertProblem(t, c.post(valid.Certificate, map[string]any{}), http.StatusBadRequest, acmeserver.ErrorMalformed)
	var list struct {
		Orders []string `json:"orders"`
	}
	c.get(c.kid+"/orders", &list)
	if len(list.Orders) != 1 || list.Orders[0] != location {
		t.Fatalf("orders = %v", list.Orders)
	}
	if strings.Contains(f.logs.String(), "Run is not active") {
		t.Fatalf("worker warning logged although Run is active: %s", f.logs.String())
	}
}

// Checks the published chain and the issue request the test CA received for it.
func checkIssuedCertificate(t *testing.T, f *flow, c *client, certURL string, certKey *ecdsa.PrivateKey) {
	t.Helper()
	rec := c.get(certURL, nil)
	if rec.Header().Get("Content-Type") != "application/pem-certificate-chain" {
		t.Fatalf("Content-Type = %q", rec.Header().Get("Content-Type"))
	}
	chain := parsePEMChain(t, rec.Body.Bytes())
	if len(chain) != 2 || strings.Join(chain[0].DNSNames, ",") != "a.test,b.test" {
		t.Fatalf("chain = %d certificates, leaf names %v", len(chain), chain[0].DNSNames)
	}
	if err := chain[0].CheckSignatureFrom(chain[1]); err != nil {
		t.Fatalf("leaf not signed by the test CA: %v", err)
	}
	leafKey, _ := x509.MarshalPKIXPublicKey(chain[0].PublicKey)
	wantKey, _ := x509.MarshalPKIXPublicKey(&certKey.PublicKey)
	if string(leafKey) != string(wantKey) {
		t.Fatal("leaf key is not the CSR key")
	}
	if n := f.ca.callCount(); n != 1 {
		t.Fatalf("issuer called %d times", n)
	}
	if req := f.ca.calls[0]; len(req.Validations) != 2 || req.Validations[0].Type != acmeserver.ChallengeHTTP01 ||
		req.Validations[0].Validated.IsZero() || req.OperationID == "" || req.Deadline.IsZero() {
		t.Fatalf("issue request = %+v", req)
	}
}

func TestFinalizeRejectsBadCSRs(t *testing.T) {
	f := newFlow(t, nil)
	f.runWorker()
	c := f.newClient()
	c.register()
	location, order := c.newOrder("a.test")
	c.respondHTTP01(order)
	c.waitOrder(location, statusReady)
	certKey := newKey(t)
	post := func(csr string) {
		assertProblem(t, c.post(order.Finalize, map[string]string{"csr": csr}), http.StatusBadRequest, acmeserver.ErrorBadCSR)
	}
	post(base64.RawURLEncoding.EncodeToString(makeCSR(t, certKey, []string{"a.test", "extra.test"}, nil)))
	post(base64.RawURLEncoding.EncodeToString(makeCSR(t, certKey, []string{"other.test"}, nil)))
	post(base64.RawURLEncoding.EncodeToString(makeCSR(t, certKey, []string{"a.test"}, []net.IP{net.ParseIP("192.0.2.1")})))
	post(base64.RawURLEncoding.EncodeToString(makeCSR(t, c.key, []string{"a.test"}, nil)))
	post(base64.RawURLEncoding.EncodeToString([]byte{0x30, 0x03, 0x02, 0x01, 0x01}))
	tampered := makeCSR(t, certKey, []string{"a.test"}, nil)
	tampered[len(tampered)-1] ^= 0xff
	post(base64.RawURLEncoding.EncodeToString(tampered))
	assertProblem(t, c.post(order.Finalize, map[string]string{"csr": "not base64!"}), http.StatusBadRequest, acmeserver.ErrorMalformed)
	assertProblem(t, c.post(order.Finalize, map[string]string{"csr": base64.StdEncoding.EncodeToString(makeCSR(t, certKey, []string{"a.test"}, nil))}),
		http.StatusBadRequest, acmeserver.ErrorMalformed)
	var current orderBody
	c.get(location, &current)
	if current.Status != statusReady {
		t.Fatalf("order after rejected CSRs = %s", current.Status)
	}
	rec := c.finalize(order, certKey)
	if rec.Code != http.StatusOK {
		t.Fatalf("finalize with a good CSR = %d %s", rec.Code, rec.Body.String())
	}
	c.waitOrder(location, statusValid)
}

func TestFailedValidationInvalidatesOrder(t *testing.T) {
	f := newFlow(t, nil)
	f.validator.script(func(req acmeserver.ValidationRequest, _ int) error {
		if req.Identifier.Value == "bad.test" {
			return acmeserver.NewProblem(acmeserver.ErrorIncorrectResponse, "wrong key authorization")
		}
		return nil
	})
	f.runWorker()
	c := f.newClient()
	c.register()
	location, order := c.newOrder("good.test", "bad.test")
	c.respondHTTP01(order)
	invalid := c.waitOrder(location, statusInvalid)
	var bad authzBody
	c.get(order.Authorizations[1], &bad)
	if bad.Status != statusInvalid || len(bad.Challenges) != 2 {
		t.Fatalf("failed authz = %+v", bad)
	}
	for _, ch := range bad.Challenges {
		if ch.Type == typeHTTP01 && (ch.Status != statusInvalid || ch.Error == nil || ch.Error.Type != acmeserver.ErrorIncorrectResponse) {
			t.Fatalf("failed challenge = %+v", ch)
		}
	}
	assertProblem(t, c.finalize(invalid, newKey(t)), http.StatusForbidden, acmeserver.ErrorOrderNotReady)
	var list struct {
		Orders []string `json:"orders"`
	}
	c.get(c.kid+"/orders", &list)
	if len(list.Orders) != 0 {
		t.Fatalf("invalid order listed: %v", list.Orders)
	}
}

func TestValidationRetriesTransientErrors(t *testing.T) {
	f := newFlow(t, nil)
	f.validator.script(func(_ acmeserver.ValidationRequest, attempt int) error {
		if attempt < 3 {
			return errTransient
		}
		return nil
	})
	f.runWorker()
	c := f.newClient()
	c.register()
	location, order := c.newOrder("a.test")
	c.respondHTTP01(order)
	c.waitOrder(location, statusReady)
	if n := f.validator.callCount(); n != 3 {
		t.Fatalf("validator called %d times, want 3", n)
	}
	f.validator.script(func(acmeserver.ValidationRequest, int) error { return errTransient })
	location, order = c.newOrder("b.test")
	c.respondHTTP01(order)
	c.waitOrder(location, statusInvalid)
	var authz authzBody
	c.get(order.Authorizations[0], &authz)
	if authz.Status != statusInvalid || authz.Challenges[0].Error == nil || authz.Challenges[0].Error.Type != acmeserver.ErrorServerInternal {
		t.Fatalf("authz after exhausted retries = %+v", authz)
	}
	if n := f.validator.callCount(); n != 6 {
		t.Fatalf("validator called %d times, want 6", n)
	}
}

func TestIssuerPendingRetryAndRejection(t *testing.T) {
	f := newFlow(t, nil)
	f.ca.pending = 2
	f.ca.failures = 1
	f.runWorker()
	c := f.newClient()
	c.register()
	location, order := c.newOrder("a.test")
	c.respondHTTP01(order)
	c.waitOrder(location, statusReady)
	if rec := c.finalize(order, newKey(t)); rec.Code != http.StatusOK {
		t.Fatalf("finalize = %d", rec.Code)
	}
	c.waitOrder(location, statusValid)
	if n := f.ca.callCount(); n != 4 {
		t.Fatalf("issuer called %d times, want 4", n)
	}
	ops := map[string]bool{}
	for _, call := range f.ca.calls {
		ops[call.OperationID] = true
	}
	if len(ops) != 1 {
		t.Fatalf("operation IDs changed across retries: %d distinct", len(ops))
	}
	f.ca.mu.Lock()
	f.ca.reject = acmeserver.NewProblem(acmeserver.ErrorRejectedIdentifier, "policy refused b.test")
	f.ca.mu.Unlock()
	location, order = c.newOrder("b.test")
	c.respondHTTP01(order)
	c.waitOrder(location, statusReady)
	c.finalize(order, newKey(t))
	invalid := c.waitOrder(location, statusInvalid)
	if invalid.Error == nil || invalid.Error.Type != acmeserver.ErrorRejectedIdentifier || invalid.Certificate != "" {
		t.Fatalf("rejected order = %+v", invalid)
	}
}

// Recovers an uncertain issuance even after the validation retry limit has passed.
func TestIssuerRetriesUncertainOutcome(t *testing.T) {
	f := newFlow(t, nil)
	f.ca.failures = 10
	f.runWorker()
	c := f.newClient()
	c.register()
	location, order := c.newOrder("a.test")
	c.respondHTTP01(order)
	c.waitOrder(location, statusReady)
	c.finalize(order, newKey(t))
	c.waitOrder(location, statusValid)
	if n := f.ca.callCount(); n != 11 {
		t.Fatalf("issuer called %d times, want 11", n)
	}
}

func TestUnacceptableChainIsNotPublished(t *testing.T) {
	f := newFlow(t, nil)
	rogue := newTestCA(t)
	chain, err := rogue.sign(&newKey(t).PublicKey, []acmeserver.Identifier{{Type: acmeserver.IdentifierDNS, Value: "a.test"}}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	f.ca.fixedChain = chain
	f.runWorker()
	c := f.newClient()
	c.register()
	location, order := c.newOrder("a.test")
	c.respondHTTP01(order)
	c.waitOrder(location, statusReady)
	c.finalize(order, newKey(t))
	invalid := c.waitOrder(location, statusInvalid)
	if invalid.Certificate != "" || invalid.Error == nil {
		t.Fatalf("order with a foreign key chain = %+v", invalid)
	}
	if !strings.Contains(f.logs.String(), "unacceptable certificate") {
		t.Fatalf("unacceptable chain not logged: %s", f.logs.String())
	}
}

func TestRevocation(t *testing.T) {
	f := newFlow(t, nil)
	f.runWorker()
	c := f.newClient()
	c.register()
	certKey := newKey(t)
	location, order := c.newOrder("a.test")
	c.respondHTTP01(order)
	c.waitOrder(location, statusReady)
	c.finalize(order, certKey)
	valid := c.waitOrder(location, statusValid)
	chain := parsePEMChain(t, c.get(valid.Certificate, nil).Body.Bytes())
	leaf := base64.RawURLEncoding.EncodeToString(chain[0].Raw)
	other := f.newClient()
	other.register()
	assertProblem(t, other.post(baseURL+"revoke-cert", map[string]any{"certificate": leaf}), http.StatusForbidden,
		acmeserver.ErrorUnauthorized)
	assertProblem(t, c.post(baseURL+"revoke-cert", map[string]any{"certificate": leaf, "reason": 6}), http.StatusBadRequest,
		acmeserver.ErrorBadRevocationReason)
	assertProblem(t, c.post(baseURL+"revoke-cert", map[string]any{"certificate": base64.RawURLEncoding.EncodeToString(chain[1].Raw)}),
		http.StatusNotFound, acmeserver.ErrorMalformed)
	assertProblem(t, c.post(baseURL+"revoke-cert", map[string]any{"certificate": "AAAA"}), http.StatusBadRequest,
		acmeserver.ErrorMalformed)
	stranger := &client{f: f, key: newKey(t)}
	assertProblem(t, stranger.post(baseURL+"revoke-cert", map[string]any{"certificate": leaf}), http.StatusForbidden,
		acmeserver.ErrorUnauthorized)
	f.revoker.err = errTransient
	assertProblem(t, c.post(baseURL+"revoke-cert", map[string]any{"certificate": leaf}), http.StatusInternalServerError,
		acmeserver.ErrorServerInternal)
	f.revoker.err = nil
	rec := c.post(baseURL+"revoke-cert", map[string]any{"certificate": leaf, "reason": 1})
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 || rec.Header().Get("Replay-Nonce") == "" {
		t.Fatalf("revoke = %d %q", rec.Code, rec.Body.String())
	}
	if len(f.revoker.requests) != 2 || f.revoker.requests[1].Reason != 1 || f.revoker.requests[1].AccountID == "" ||
		f.revoker.requests[1].Certificate.SerialNumber.Cmp(chain[0].SerialNumber) != 0 {
		t.Fatalf("revoker requests = %+v", f.revoker.requests)
	}
	assertProblem(t, c.post(baseURL+"revoke-cert", map[string]any{"certificate": leaf}), http.StatusBadRequest,
		acmeserver.ErrorAlreadyRevoked)

	location, order = c.newOrder("b.test")
	c.respondHTTP01(order)
	c.waitOrder(location, statusReady)
	c.finalize(order, certKey)
	valid = c.waitOrder(location, statusValid)
	chain = parsePEMChain(t, c.get(valid.Certificate, nil).Body.Bytes())
	byKey := &client{f: f, key: certKey}
	rec = byKey.post(baseURL+"revoke-cert", map[string]any{"certificate": base64.RawURLEncoding.EncodeToString(chain[0].Raw)})
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke by certificate key = %d %s", rec.Code, rec.Body.String())
	}
	if last := f.revoker.requests[len(f.revoker.requests)-1]; last.AccountID != "" || last.Reason != 0 {
		t.Fatalf("revoke by key request = %+v", last)
	}
}

func TestReadyAndRunGuards(t *testing.T) {
	f := newFlow(t, nil)
	if err := f.srv.Ready(t.Context()); err != nil {
		t.Fatalf("Ready with no work: %v", err)
	}
	c := f.newClient()
	c.register()
	_, order := c.newOrder("a.test")
	c.respondHTTP01(order)
	if !strings.Contains(f.logs.String(), "Run is not active") {
		t.Fatalf("missing worker warning: %s", f.logs.String())
	}
	waitFor(t, "stale work detection", func() bool { return f.srv.Ready(t.Context()) != nil })
	f.runWorker()
	waitFor(t, "work drained", func() bool { return f.srv.Ready(t.Context()) == nil })
	if err := f.srv.Run(t.Context()); err == nil {
		t.Fatal("second Run did not fail")
	}
}

// Parses a PEM chain and checks the erratum 5983 layout of one newline after each block.
func parsePEMChain(t *testing.T, body []byte) []*x509.Certificate {
	t.Helper()
	if strings.Contains(string(body), "\n\n") || !strings.HasSuffix(string(body), "-----END CERTIFICATE-----\n") {
		t.Fatalf("PEM chain layout is wrong:\n%s", body)
	}
	var chain []*x509.Certificate
	rest := body
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		chain = append(chain, cert)
	}
	return chain
}

// A Policy that refuses specific contacts and names.
type denyPolicy struct{}

// Refuses accounts whose first contact is blocked.
func (denyPolicy) NewAccount(_ context.Context, account *acmeserver.Account) error {
	if len(account.Contact) > 0 && account.Contact[0] == "mailto:blocked@example.test" {
		return acmeserver.NewProblem(acmeserver.ErrorUnauthorized, "contact is blocked")
	}
	return nil
}

// Refuses blocked names and fails on broken ones.
func (denyPolicy) NewOrder(_ context.Context, _ *acmeserver.Account, order *acmeserver.Order) error {
	switch order.Identifiers[0].Value {
	case "blocked.test":
		return acmeserver.NewProblem(acmeserver.ErrorRejectedIdentifier, "name is blocked").WithIdentifier(order.Identifiers[0])
	case "broken.test":
		return errTransient
	}
	return nil
}

// A non-problem error for retry paths.
var errTransient = errors.New("temporary failure")
