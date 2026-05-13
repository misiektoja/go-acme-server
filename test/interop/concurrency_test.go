package interop

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	acmeserver "github.com/misiektoja/go-acme-server"
)

// Repeats and races account creation with one key and expects exactly one account.
func TestLostResponseAccountCreation(t *testing.T) {
	h := newHarness(t, harnessOptions{httpPort: availablePort(t)})
	d := h.resources(t)
	key := newKey(t)
	request := joseRequest{alg: jose.ES256, key: key, url: d.NewAccount}
	payload := []byte(`{"termsOfServiceAgreed":true}`)
	response, body := h.post(t, d.NewAccount, h.joseSign(t, request, payload))
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("first newAccount: %d %s", response.StatusCode, body)
	}
	location := response.Header.Get("Location")
	response, body = h.post(t, d.NewAccount, h.joseSign(t, request, payload))
	if response.StatusCode != http.StatusOK || response.Header.Get("Location") != location {
		t.Fatalf("retried newAccount: %d %s Location %q", response.StatusCode, body, response.Header.Get("Location"))
	}
	fresh := newKey(t)
	bodies := make([][]byte, 8)
	for i := range bodies {
		bodies[i] = h.joseSign(t, joseRequest{alg: jose.ES256, key: fresh, url: d.NewAccount}, payload)
	}
	replies := concurrently(len(bodies), func(i int) reply { return h.postRaw(d.NewAccount, bodies[i]) })
	created := countStatus(t, replies, http.StatusCreated)
	existing := countStatus(t, replies, http.StatusOK)
	if created != 1 || existing != len(replies)-1 {
		t.Fatalf("created=%d existing=%d", created, existing)
	}
	for _, r := range replies {
		if r.header.Get("Location") != replies[0].header.Get("Location") {
			t.Fatalf("racing registrations returned different accounts: %q vs %q", r.header.Get("Location"), replies[0].header.Get("Location"))
		}
	}
	account, err := h.store.AccountByKey(t.Context(), joseThumbprint(t, &fresh.PublicKey))
	if err != nil || h.https.URL+"/acme/acct/"+account.ID != replies[0].header.Get("Location") {
		t.Fatalf("stored account = %+v, %v", account, err)
	}
	response, body = h.post(t, d.NewAccount, h.joseSign(t, joseRequest{alg: jose.ES256, key: newKey(t), url: d.NewAccount}, []byte(`{"onlyReturnExisting":true}`)))
	requireProblem(t, response, body, http.StatusBadRequest, acmeserver.ErrorAccountDoesNotExist)
	t.Log("retried and racing registrations with one key returned one account")
}

// Races repeated challenge responses and finalizations for one order and expects one validation
// and one issuance.
func TestLostResponseChallengeAndFinalize(t *testing.T) {
	s, port := newSolver(t, false)
	h := newHarness(t, harnessOptions{httpPort: port})
	c := h.newProtocolClient(t)
	orderURL, order := c.newOrder(testHost)
	_, ch := c.challenge(order.Authorizations[0], acmeserver.ChallengeHTTP01)
	c.presentHTTP(s, ch)
	bodies := make([][]byte, 8)
	for i := range bodies {
		bodies[i] = c.sign(ch.URL, []byte("{}"))
	}
	replies := concurrently(len(bodies), func(i int) reply { return h.postRaw(ch.URL, bodies[i]) })
	if countStatus(t, replies, http.StatusOK) != len(replies) {
		t.Fatalf("challenge responses: %+v", replies)
	}
	for _, r := range replies {
		var view challengeJSON
		if err := json.Unmarshal(r.body, &view); err != nil || (view.Status != "processing" && view.Status != "valid") {
			t.Fatalf("challenge view %s, %v", r.body, err)
		}
	}
	order = c.waitOrder(orderURL, "ready")
	s.mu.RLock()
	hits := s.hits
	s.mu.RUnlock()
	if hits != 1 {
		t.Fatalf("HTTP proof fetched %d times", hits)
	}
	stored, err := h.store.Challenge(t.Context(), ch.URL[strings.LastIndex(ch.URL, "/")+1:])
	if err != nil || stored.Status != acmeserver.ChallengeValid || stored.Validated.IsZero() {
		t.Fatalf("stored challenge = %+v, %v", stored, err)
	}
	var again challengeJSON
	if r := c.post(ch.URL, []byte("{}"), &again); r.status != http.StatusOK || again.Status != "valid" {
		t.Fatalf("response after validation: %d %s", r.status, r.body)
	}
	key, csr := newCSR(t, testHost)
	finalize := finalizePayload(t, csr)
	for i := range bodies {
		bodies[i] = c.sign(order.Finalize, finalize)
	}
	replies = concurrently(len(bodies), func(i int) reply { return h.postRaw(order.Finalize, bodies[i]) })
	if countStatus(t, replies, http.StatusOK) != len(replies) {
		t.Fatalf("finalizations: %+v", replies)
	}
	order = c.waitOrder(orderURL, "valid")
	if r := c.post(order.Finalize, finalize, nil); r.status != http.StatusOK || !bytes.Contains(r.body, []byte(`"certificate"`)) {
		t.Fatalf("finalize after issuance: %d %s", r.status, r.body)
	}
	_, other := newCSR(t, testHost)
	r := c.post(order.Finalize, finalizePayload(t, other), nil)
	if r.status != http.StatusForbidden || !bytes.Contains(r.body, []byte(string(acmeserver.ErrorOrderNotReady))) {
		t.Fatalf("finalize with another CSR: %d %s", r.status, r.body)
	}
	if rows, calls := h.issuances(t); rows != 1 || calls != 1 {
		t.Fatalf("issuance rows=%d calls=%d", rows, calls)
	}
	h.verify(t, c.certificate(order), &key.PublicKey, []string{testHost}, acmeserver.ChallengeHTTP01)
	t.Log("eight concurrent challenge responses and finalizations produced one validation and one issuance")
}

// Races finalizations with two different CSRs and expects exactly one accepted CSR.
func TestCompetingFinalizations(t *testing.T) {
	s, port := newSolver(t, false)
	h := newHarness(t, harnessOptions{httpPort: port})
	c := h.newProtocolClient(t)
	orderURL, order := c.newOrder(testHost)
	_, ch := c.challenge(order.Authorizations[0], acmeserver.ChallengeHTTP01)
	c.presentHTTP(s, ch)
	c.post(ch.URL, []byte("{}"), nil)
	order = c.waitOrder(orderURL, "ready")
	keyA, csrA := newCSR(t, testHost)
	keyB, csrB := newCSR(t, testHost)
	csrs := [][]byte{csrA, csrB}
	bodies := make([][]byte, 6)
	for i := range bodies {
		bodies[i] = c.sign(order.Finalize, finalizePayload(t, csrs[i%2]))
	}
	replies := concurrently(len(bodies), func(i int) reply { return h.postRaw(order.Finalize, bodies[i]) })
	accepted := countStatus(t, replies, http.StatusOK)
	refused := countStatus(t, replies, http.StatusForbidden)
	if accepted < 1 || accepted+refused != len(replies) {
		t.Fatalf("accepted=%d refused=%d replies=%+v", accepted, refused, replies)
	}
	stored, err := h.store.Order(t.Context(), orderURL[strings.LastIndex(orderURL, "/")+1:])
	if err != nil {
		t.Fatal(err)
	}
	winner, loser, winnerKey := csrA, csrB, keyA
	if bytes.Equal(stored.CSR, csrB) {
		winner, loser, winnerKey = csrB, csrA, keyB
	} else if !bytes.Equal(stored.CSR, csrA) {
		t.Fatal("stored CSR is neither competitor")
	}
	for i, r := range replies {
		if (r.status == http.StatusOK) != bytes.Equal(csrs[i%2], winner) {
			t.Fatalf("reply %d status %d does not match the winning CSR", i, r.status)
		}
	}
	order = c.waitOrder(orderURL, "valid")
	if r := c.post(order.Finalize, finalizePayload(t, loser), nil); r.status != http.StatusForbidden {
		t.Fatalf("losing CSR after issuance: %d %s", r.status, r.body)
	}
	if r := c.post(order.Finalize, finalizePayload(t, winner), nil); r.status != http.StatusOK {
		t.Fatalf("winning CSR after issuance: %d %s", r.status, r.body)
	}
	if rows, calls := h.issuances(t); rows != 1 || calls != 1 {
		t.Fatalf("issuance rows=%d calls=%d", rows, calls)
	}
	h.verify(t, c.certificate(order), &winnerKey.PublicKey, []string{testHost}, acmeserver.ChallengeHTTP01)
	t.Log("competing CSRs: one accepted, the other refused before and after issuance, one CA call")
}

// Races key changes for one account and expects exactly one new key, then checks the RFC 8555
// conflict answer for a key another account already uses.
func TestSimultaneousKeyRollover(t *testing.T) {
	h := newHarness(t, harnessOptions{httpPort: availablePort(t)})
	c := h.newProtocolClient(t)
	d := c.d
	candidates := make([]joseRequest, 4)
	bodies := make([][]byte, len(candidates))
	oldJWK := mustJSON(t, jose.JSONWebKey{Key: &c.key.PublicKey})
	for i := range candidates {
		candidates[i] = joseRequest{alg: jose.ES256, key: newKey(t), url: d.KeyChange, noNonce: true}
		inner := h.joseSign(t, candidates[i], []byte(`{"account":"`+c.kid+`","oldKey":`+string(oldJWK)+`}`))
		bodies[i] = c.sign(d.KeyChange, inner)
	}
	replies := concurrently(len(bodies), func(i int) reply { return h.postRaw(d.KeyChange, bodies[i]) })
	if countStatus(t, replies, http.StatusOK) != 1 {
		t.Fatalf("key changes: %+v", replies)
	}
	account, err := h.store.Account(t.Context(), c.kid[strings.LastIndex(c.kid, "/")+1:])
	if err != nil {
		t.Fatal(err)
	}
	winner := -1
	for i, r := range replies {
		thumbprint := joseThumbprint(t, &candidates[i].key.(*ecdsa.PrivateKey).PublicKey)
		switch {
		case r.status == http.StatusOK && account.KeyThumbprint == thumbprint:
			winner = i
		case r.status == http.StatusOK:
			t.Fatalf("reply %d succeeded but the stored key differs", i)
		case r.status != http.StatusConflict && r.status != http.StatusForbidden:
			t.Fatalf("reply %d: %d %s", i, r.status, r.body)
		}
	}
	if winner < 0 {
		t.Fatal("no winning key change")
	}
	response, body := h.post(t, c.kid, c.sign(c.kid, []byte{}))
	requireProblem(t, response, body, http.StatusForbidden, acmeserver.ErrorUnauthorized)
	c.key = candidates[winner].key.(*ecdsa.PrivateKey)
	if r := c.post(c.kid, []byte{}, nil); r.status != http.StatusOK {
		t.Fatalf("new key: %d %s", r.status, r.body)
	}
	other := h.newProtocolClient(t)
	inner := h.joseSign(t, joseRequest{alg: jose.ES256, key: c.key, url: d.KeyChange, noNonce: true},
		[]byte(`{"account":"`+other.kid+`","oldKey":`+string(mustJSON(t, jose.JSONWebKey{Key: &other.key.PublicKey}))+`}`))
	r := other.post(d.KeyChange, inner, nil)
	if r.status != http.StatusConflict || r.header.Get("Location") != c.kid {
		t.Fatalf("rollover to a used key: %d Location %q %s", r.status, r.header.Get("Location"), r.body)
	}
	t.Log("one of four racing key changes won, the old key was refused and a used key answered 409 with its owner")
}

// Uses one nonce concurrently and expects exactly one accepted request.
func TestConcurrentNonceReuse(t *testing.T) {
	h := newHarness(t, harnessOptions{httpPort: availablePort(t)})
	c := h.newProtocolClient(t)
	body := c.sign(c.kid, []byte{})
	replies := concurrently(6, func(int) reply { return h.postRaw(c.kid, body) })
	if countStatus(t, replies, http.StatusOK) != 1 {
		t.Fatalf("nonce reuse: %+v", replies)
	}
	for _, r := range replies {
		if r.status == http.StatusOK {
			continue
		}
		var p problem
		if r.status != http.StatusBadRequest || json.Unmarshal(r.body, &p) != nil || !strings.HasSuffix(p.Type, string(acmeserver.ErrorBadNonce)) || r.header.Get("Replay-Nonce") == "" {
			t.Fatalf("replay reply: %d %s", r.status, r.body)
		}
	}
	t.Log("one nonce used by six concurrent requests was accepted once")
}

// Validates four authorizations of one order concurrently while two workers share the store.
func TestConcurrentAuthorizationsAndWorkers(t *testing.T) {
	responder, endpoint := newDNSResponder(t)
	s, port := newSolver(t, false)
	h := newHarness(t, harnessOptions{httpPort: port, dns: endpoint})
	runWorker(t, configuredServer(t, h.https.URL+"/acme/", h.options, h.store, h.ca))
	names := []string{"a." + testHost, "b." + testHost, "c." + testHost, "d." + testHost}
	c := h.newProtocolClient(t)
	orderURL, order := c.newOrder(names...)
	challenges := make([]challengeJSON, len(order.Authorizations))
	for i, authzURL := range order.Authorizations {
		authz, ch := c.challenge(authzURL, acmeserver.ChallengeDNS01)
		c.presentDNS(responder, authz.Identifier.Value, ch)
		challenges[i] = ch
	}
	bodies := make([][]byte, len(challenges))
	for i, ch := range challenges {
		bodies[i] = c.sign(ch.URL, []byte("{}"))
	}
	replies := concurrently(len(bodies), func(i int) reply { return h.postRaw(challenges[i].URL, bodies[i]) })
	if countStatus(t, replies, http.StatusOK) != len(replies) {
		t.Fatalf("challenge responses: %+v", replies)
	}
	order = c.waitOrder(orderURL, "ready")
	key, csr := newCSR(t, names...)
	if r := c.post(order.Finalize, finalizePayload(t, csr), nil); r.status != http.StatusOK {
		t.Fatalf("finalize: %d %s", r.status, r.body)
	}
	order = c.waitOrder(orderURL, "valid")
	h.verify(t, c.certificate(order), &key.PublicKey, names, acmeserver.ChallengeDNS01)
	clients := make([]*protocolClient, 5)
	for i := range clients {
		clients[i] = h.newProtocolClient(t)
	}
	results := concurrently(len(clients), func(i int) reply {
		client := clients[i]
		orderURL, order := client.newOrder(testHost)
		_, ch := client.challenge(order.Authorizations[0], acmeserver.ChallengeHTTP01)
		client.presentHTTP(s, ch)
		client.post(ch.URL, []byte("{}"), nil)
		order = client.waitOrder(orderURL, "ready")
		_, csr := newCSR(t, testHost)
		client.post(order.Finalize, finalizePayload(t, csr), nil)
		order = client.waitOrder(orderURL, "valid")
		return reply{status: http.StatusOK, body: client.certificate(order)}
	})
	for _, r := range results {
		if r.status != http.StatusOK || !bytes.Contains(r.body, []byte("BEGIN CERTIFICATE")) {
			t.Fatalf("parallel order result: %+v", r)
		}
	}
	if rows, calls := h.issuances(t); rows != 1+len(clients) || calls != rows {
		t.Fatalf("issuance rows=%d calls=%d", rows, calls)
	}
	s.mu.RLock()
	hits := s.hits
	s.mu.RUnlock()
	if hits != len(clients) {
		t.Fatalf("HTTP proofs fetched %d times for %d orders", hits, len(clients))
	}
	if _, err := h.store.ClaimTask(t.Context(), time.Now().Add(time.Hour), time.Now().Add(2*time.Hour)); err == nil {
		t.Fatal("work remained after every order completed")
	}
	t.Logf("four concurrent authorizations and %d parallel orders completed once each across two workers", len(clients))
}

// Marshals a value or fails the test.
func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
