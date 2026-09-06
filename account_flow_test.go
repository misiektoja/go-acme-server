package acmeserver_test

import (
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	acmeserver "github.com/misiektoja/go-acme-server"
)

func TestNewAccountCreatesAndReturnsExisting(t *testing.T) {
	f := newFlow(t, func(c *acmeserver.Config) { c.Meta.TermsOfService = "https://acme.test/terms" })
	c := f.newClient()
	rec := c.post(baseURL+"new-account", map[string]any{"termsOfServiceAgreed": true,
		"contact": []string{"mailto:admin@example.test"}})
	if rec.Code != http.StatusCreated {
		t.Fatalf("new-account = %d %s", rec.Code, rec.Body.String())
	}
	location := rec.Header().Get("Location")
	if !strings.HasPrefix(location, baseURL+"acct/") || rec.Header().Get("Replay-Nonce") == "" {
		t.Fatalf("headers = %v", rec.Header())
	}
	if !strings.Contains(strings.Join(rec.Header().Values("Link"), " "), `rel="terms-of-service"`) {
		t.Fatalf("Link = %v", rec.Header().Values("Link"))
	}
	var account accountBody
	decode(t, rec, &account)
	if account.Status != statusValid || len(account.Contact) != 1 || !account.TermsOfServiceAgreed ||
		account.Orders != location+"/orders" {
		t.Fatalf("account = %+v", account)
	}
	again := c.post(baseURL+"new-account", map[string]any{"termsOfServiceAgreed": true})
	if again.Code != http.StatusOK || again.Header().Get("Location") != location {
		t.Fatalf("second new-account = %d Location %q", again.Code, again.Header().Get("Location"))
	}
	existing := c.post(baseURL+"new-account", map[string]any{"onlyReturnExisting": true})
	if existing.Code != http.StatusOK || existing.Header().Get("Location") != location {
		t.Fatalf("onlyReturnExisting = %d", existing.Code)
	}
	other := f.newClient()
	assertProblem(t, other.post(baseURL+"new-account", map[string]any{"onlyReturnExisting": true}),
		http.StatusBadRequest, acmeserver.ErrorAccountDoesNotExist)
	if _, err := f.store.AccountByKey(t.Context(), thumbprint(t, &other.key.PublicKey)); err == nil {
		t.Fatal("onlyReturnExisting created an account")
	}
}

func TestNewAccountRejects(t *testing.T) {
	f := newFlow(t, func(c *acmeserver.Config) {
		c.Meta.TermsOfService = "https://acme.test/terms"
		c.RequireTermsOfServiceAgreed = true
	})
	cases := []struct {
		name    string
		payload any
		status  int
		typ     acmeserver.ErrorType
	}{
		{"terms not agreed", map[string]any{"contact": []string{"mailto:a@example.test"}}, http.StatusForbidden,
			acmeserver.ErrorUserActionRequired},
		{"unsupported contact scheme", map[string]any{"termsOfServiceAgreed": true, "contact": []string{"tel:+1555"}},
			http.StatusBadRequest, acmeserver.ErrorUnsupportedContact},
		{"contact with hfields", map[string]any{"termsOfServiceAgreed": true,
			"contact": []string{"mailto:a@example.test?subject=x"}}, http.StatusBadRequest, acmeserver.ErrorInvalidContact},
		{"contact with two addresses", map[string]any{"termsOfServiceAgreed": true,
			"contact": []string{"mailto:a@example.test,b@example.test"}}, http.StatusBadRequest, acmeserver.ErrorInvalidContact},
		{"contact not an address", map[string]any{"termsOfServiceAgreed": true, "contact": []string{"mailto:nobody"}},
			http.StatusBadRequest, acmeserver.ErrorInvalidContact},
		{"contact with display name", map[string]any{"termsOfServiceAgreed": true,
			"contact": []string{"mailto:Admin <a@example.test>"}}, http.StatusBadRequest, acmeserver.ErrorInvalidContact},
		{"too many contacts", map[string]any{"termsOfServiceAgreed": true, "contact": manyContacts(11)},
			http.StatusBadRequest, acmeserver.ErrorMalformed},
		{"payload not an object", []string{"x"}, http.StatusBadRequest, acmeserver.ErrorMalformed},
		{"eab not accepted", map[string]any{"termsOfServiceAgreed": true,
			"externalAccountBinding": map[string]string{"protected": "e30", "payload": "e30", "signature": "AA"}},
			http.StatusBadRequest, acmeserver.ErrorMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := f.newClient()
			assertProblem(t, c.post(baseURL+"new-account", tc.payload), tc.status, tc.typ)
		})
	}
	c := f.newClient()
	c.register()
	assertProblem(t, c.postRaw(baseURL+"new-account", []byte(`{"termsOfServiceAgreed":true}`), false),
		http.StatusBadRequest, acmeserver.ErrorMalformed)
	if rec := c.post(baseURL+"new-order", map[string]any{"identifiers": []map[string]string{{"type": "dns", "value": "a.test"}}}); rec.Code != http.StatusCreated {
		t.Fatalf("new-order after registration = %d %s", rec.Code, rec.Body.String())
	}
}

// Returns n distinct mailto contacts.
func manyContacts(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "mailto:user" + string(rune('a'+i)) + "@example.test"
	}
	return out
}

// Builds an external account binding JWS over a payload.
func binding(kid string, key []byte, url string, payload []byte, alg string) map[string]string {
	protected, _ := json.Marshal(map[string]string{"alg": alg, "kid": kid, "url": url})
	p := base64.RawURLEncoding.EncodeToString(protected)
	pl := base64.RawURLEncoding.EncodeToString(payload)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(p + "." + pl))
	return map[string]string{"protected": p, "payload": pl, "signature": base64.RawURLEncoding.EncodeToString(h.Sum(nil))}
}

func TestNewAccountWithExternalAccountBinding(t *testing.T) {
	const kid = "kid-1"
	mac := []byte("0123456789abcdef0123456789abcdef")
	f := newFlow(t, func(c *acmeserver.Config) {
		c.Meta.ExternalAccountRequired = true
		c.ExternalAccounts = eabKeys{kid: mac}
	})
	c := f.newClient()
	assertProblem(t, c.post(baseURL+"new-account", map[string]any{"termsOfServiceAgreed": true}),
		http.StatusForbidden, acmeserver.ErrorExternalAccountRequired)
	jwk := publicJWK(t, &c.key.PublicKey)
	good := binding(kid, mac, baseURL+"new-account", jwk, "HS256")
	rec := c.post(baseURL+"new-account", map[string]any{"termsOfServiceAgreed": true, "externalAccountBinding": good})
	if rec.Code != http.StatusCreated {
		t.Fatalf("new-account with EAB = %d %s", rec.Code, rec.Body.String())
	}
	id := strings.TrimPrefix(rec.Header().Get("Location"), baseURL+"acct/")
	account, err := f.store.Account(t.Context(), id)
	if err != nil || account.ExternalAccountID != kid || account.ExternalAccountClaim != "" {
		t.Fatalf("stored account = %+v, %v", account, err)
	}
	// Without single use the same key identifier may bind further accounts.
	second := f.newClient()
	if rec := second.post(baseURL+"new-account", map[string]any{"termsOfServiceAgreed": true,
		"externalAccountBinding": binding(kid, mac, baseURL+"new-account", publicJWK(t, &second.key.PublicKey), "HS256")}); rec.Code != http.StatusCreated {
		t.Fatalf("second account with the same kid = %d %s", rec.Code, rec.Body.String())
	}
	otherKey := newKey(t)
	newAccount := baseURL + "new-account"
	cases := map[string]struct {
		build  func(jwk json.RawMessage) map[string]string
		status int
		typ    acmeserver.ErrorType
	}{
		"unknown kid": {func(jwk json.RawMessage) map[string]string { return binding("kid-2", mac, newAccount, jwk, "HS256") },
			http.StatusForbidden, acmeserver.ErrorUnauthorized},
		"wrong mac": {func(jwk json.RawMessage) map[string]string {
			return binding(kid, []byte("wrong"), newAccount, jwk, "HS256")
		},
			http.StatusForbidden, acmeserver.ErrorUnauthorized},
		"wrong url": {func(jwk json.RawMessage) map[string]string {
			return binding(kid, mac, baseURL+"new-order", jwk, "HS256")
		},
			http.StatusBadRequest, acmeserver.ErrorMalformed},
		"other key": {func(json.RawMessage) map[string]string {
			return binding(kid, mac, newAccount, publicJWK(t, &otherKey.PublicKey), "HS256")
		}, http.StatusBadRequest, acmeserver.ErrorMalformed},
		"signature alg": {func(jwk json.RawMessage) map[string]string { return binding(kid, mac, newAccount, jwk, "ES256") },
			http.StatusBadRequest, acmeserver.ErrorBadSignatureAlgorithm},
		"payload not a key": {func(json.RawMessage) map[string]string {
			return binding(kid, mac, newAccount, []byte(`{"a":1}`), "HS256")
		},
			http.StatusBadRequest, acmeserver.ErrorMalformed},
		"binding with nonce": {func(jwk json.RawMessage) map[string]string {
			b := binding(kid, mac, newAccount, jwk, "HS256")
			protected, _ := json.Marshal(map[string]string{"alg": "HS256", "kid": kid, "url": newAccount, "nonce": "x"})
			b["protected"] = base64.RawURLEncoding.EncodeToString(protected)
			return b
		}, http.StatusBadRequest, acmeserver.ErrorMalformed},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			fresh := f.newClient()
			assertProblem(t, fresh.post(newAccount, map[string]any{"termsOfServiceAgreed": true,
				"externalAccountBinding": tc.build(publicJWK(t, &fresh.key.PublicKey))}), tc.status, tc.typ)
		})
	}
}

// Binds each external account key identifier to one account when configured.
func TestSingleUseExternalAccount(t *testing.T) {
	const kid = "kid-1"
	mac := []byte("0123456789abcdef0123456789abcdef")
	f := newFlow(t, func(c *acmeserver.Config) {
		c.ExternalAccounts = eabKeys{kid: mac, "kid-2": mac}
		c.SingleUseExternalAccounts = true
	})
	newAccount := baseURL + "new-account"
	c := f.newClient()
	register := func(c *client, kid string) *httptest.ResponseRecorder {
		return c.post(newAccount, map[string]any{"termsOfServiceAgreed": true,
			"externalAccountBinding": binding(kid, mac, newAccount, publicJWK(t, &c.key.PublicKey), "HS256")})
	}
	rec := register(c, kid)
	if rec.Code != http.StatusCreated {
		t.Fatalf("first account = %d %s", rec.Code, rec.Body.String())
	}
	location := rec.Header().Get("Location")
	account, err := f.store.Account(t.Context(), strings.TrimPrefix(location, baseURL+"acct/"))
	if err != nil || account.ExternalAccountID != kid || account.ExternalAccountClaim != kid {
		t.Fatalf("stored account = %+v, %v", account, err)
	}
	// A lost response is retried with the same key and finds the existing account.
	if rec := register(c, kid); rec.Code != http.StatusOK || rec.Header().Get("Location") != location {
		t.Fatalf("retried registration = %d Location %q", rec.Code, rec.Header().Get("Location"))
	}
	// Another key may not claim the identifier again, but an unclaimed identifier still works.
	assertProblem(t, register(f.newClient(), kid), http.StatusForbidden, acmeserver.ErrorUnauthorized)
	if rec := register(f.newClient(), "kid-2"); rec.Code != http.StatusCreated {
		t.Fatalf("account with an unclaimed kid = %d %s", rec.Code, rec.Body.String())
	}
	// A registration without a binding still succeeds because bindings are not required here.
	if rec := f.newClient().post(newAccount, map[string]any{"termsOfServiceAgreed": true}); rec.Code != http.StatusCreated {
		t.Fatalf("account without binding = %d %s", rec.Code, rec.Body.String())
	}
}

func TestAccountResource(t *testing.T) {
	f := newFlow(t, nil)
	c := f.newClient()
	location := c.register()
	var account accountBody
	c.get(location, &account)
	if account.Status != statusValid || account.Contact[0] != "mailto:admin@example.test" {
		t.Fatalf("account = %+v", account)
	}
	rec := c.post(location, map[string]any{"contact": []string{"mailto:ops@example.test"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("update = %d %s", rec.Code, rec.Body.String())
	}
	decode(t, rec, &account)
	if account.Contact[0] != "mailto:ops@example.test" {
		t.Fatalf("updated account = %+v", account)
	}
	assertProblem(t, c.post(location, map[string]any{"contact": []string{"tel:1"}}), http.StatusBadRequest,
		acmeserver.ErrorUnsupportedContact)
	assertProblem(t, c.post(location, map[string]any{"status": statusValid}), http.StatusBadRequest, acmeserver.ErrorMalformed)
	other := f.newClient()
	other.register()
	assertProblem(t, other.post(location, nil), http.StatusForbidden, acmeserver.ErrorUnauthorized)
	assertProblem(t, c.post(baseURL+"acct/does-not-exist", nil), http.StatusForbidden, acmeserver.ErrorUnauthorized)
	rec = c.post(location, map[string]any{"status": "deactivated"})
	if rec.Code != http.StatusOK {
		t.Fatalf("deactivate = %d %s", rec.Code, rec.Body.String())
	}
	decode(t, rec, &account)
	if account.Status != "deactivated" {
		t.Fatalf("account after deactivation = %+v", account)
	}
	assertProblem(t, c.post(location, nil), http.StatusForbidden, acmeserver.ErrorUnauthorized)
	assertProblem(t, c.post(baseURL+"new-order", map[string]any{"identifiers": []map[string]string{{"type": "dns", "value": "a.test"}}}),
		http.StatusForbidden, acmeserver.ErrorUnauthorized)
	c.kid = ""
	assertProblem(t, c.post(baseURL+"new-account", map[string]any{"onlyReturnExisting": true}), http.StatusForbidden,
		acmeserver.ErrorUnauthorized)
}

func TestAccountOrdersList(t *testing.T) {
	f := newFlow(t, nil)
	c := f.newClient()
	location := c.register()
	urls := make([]string, 0, 3)
	for i := range 3 {
		u, _ := c.newOrder("host" + string(rune('a'+i)) + ".example")
		urls = append(urls, u)
	}
	var list struct {
		Orders []string `json:"orders"`
	}
	rec := c.get(location+"/orders", &list)
	if strings.Join(list.Orders, " ") != strings.Join(urls, " ") {
		t.Fatalf("orders = %v, want %v", list.Orders, urls)
	}
	if rec.Header().Get("Link") == "" || strings.Contains(strings.Join(rec.Header().Values("Link"), " "), `rel="next"`) {
		t.Fatalf("Link = %v", rec.Header().Values("Link"))
	}
	assertProblem(t, c.post(location+"/orders", map[string]any{}), http.StatusBadRequest, acmeserver.ErrorMalformed)
	assertProblem(t, c.post(location+"/orders?cursor=unknown", nil), http.StatusBadRequest, acmeserver.ErrorMalformed)
	other := f.newClient()
	other.register()
	assertProblem(t, other.post(location+"/orders", nil), http.StatusForbidden, acmeserver.ErrorUnauthorized)
	header := map[string]any{"nonce": c.nonce(), "url": location + "/orders", "kid": c.kid}
	r := httptest.NewRequest(http.MethodPost, location+"/orders?cursor=x", strings.NewReader(string(signECDSA(t, c.key, header, nil))))
	r.Header.Set("Content-Type", "application/jose+json")
	assertProblem(t, f.do(r), http.StatusForbidden, acmeserver.ErrorUnauthorized)
}

func TestKeyChange(t *testing.T) {
	f := newFlow(t, nil)
	c := f.newClient()
	location := c.register()
	taken := f.newClient()
	taken.register()
	newKey := newKey(t)
	innerWith := func(signer *ecdsa.PrivateKey, url, account string, oldKey json.RawMessage) []byte {
		payload, _ := json.Marshal(map[string]any{"account": account, "oldKey": oldKey})
		header := map[string]any{"url": url, "jwk": publicJWK(t, &signer.PublicKey)}
		return signECDSA(t, signer, header, payload)
	}
	inner := func(_ json.RawMessage, url, account string, oldKey json.RawMessage) []byte {
		return innerWith(newKey, url, account, oldKey)
	}
	oldJWK := publicJWK(t, &c.key.PublicKey)
	newJWK := publicJWK(t, &newKey.PublicKey)
	cases := map[string]struct {
		body []byte
	}{
		"wrong inner url": {inner(newJWK, baseURL+"new-account", location, oldJWK)},
		"wrong account":   {inner(newJWK, baseURL+"key-change", baseURL+"acct/other", oldJWK)},
		"wrong old key":   {inner(newJWK, baseURL+"key-change", location, newJWK)},
		"inner has nonce": {signECDSA(t, newKey, map[string]any{"url": baseURL + "key-change", "jwk": newJWK, "nonce": "x"}, nil)},
		"inner uses kid":  {signECDSA(t, newKey, map[string]any{"url": baseURL + "key-change", "kid": location}, nil)},
		"not a jws":       {[]byte(`{"account":"x"}`)},
		"inner signed by another key": {signECDSA(t, c.key, map[string]any{"url": baseURL + "key-change", "jwk": newJWK},
			mustJSON(t, map[string]any{"account": location, "oldKey": oldJWK}))},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			assertProblem(t, c.postRaw(baseURL+"key-change", tc.body, false), http.StatusBadRequest, acmeserver.ErrorMalformed)
		})
	}
	conflict := c.postRaw(baseURL+"key-change", innerWith(taken.key, baseURL+"key-change", location, oldJWK), false)
	assertProblem(t, conflict, http.StatusConflict, acmeserver.ErrorMalformed)
	if conflict.Header().Get("Location") != taken.kid {
		t.Fatalf("conflict Location = %q, want %q", conflict.Header().Get("Location"), taken.kid)
	}
	rec := c.postRaw(baseURL+"key-change", inner(newJWK, baseURL+"key-change", location, oldJWK), false)
	if rec.Code != http.StatusOK {
		t.Fatalf("key-change = %d %s", rec.Code, rec.Body.String())
	}
	assertProblem(t, c.post(location, nil), http.StatusForbidden, acmeserver.ErrorUnauthorized)
	c.key = newKey
	var account accountBody
	c.get(location, &account)
	if account.Status != statusValid {
		t.Fatalf("account after key change = %+v", account)
	}
	assertProblem(t, c.postRaw(baseURL+"key-change", inner(newJWK, baseURL+"key-change", location, newJWK), false),
		http.StatusBadRequest, acmeserver.ErrorMalformed)
}

// Marshals v or fails.
func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
