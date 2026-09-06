package acmeserver_test

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	acmeserver "github.com/misiektoja/go-acme-server"
)

// The renewalInfo object the tests decode.
type renewalBody struct {
	SuggestedWindow struct {
		Start time.Time `json:"start"`
		End   time.Time `json:"end"`
	} `json:"suggestedWindow"`
	ExplanationURL string `json:"explanationURL"`
}

// Issues one certificate for the names and returns the leaf.
func (c *client) issue(names ...string) *x509.Certificate {
	location, order := c.newOrder(names...)
	c.respondHTTP01(order)
	c.waitOrder(location, statusReady)
	c.finalize(order, newKey(c.f.t))
	valid := c.waitOrder(location, statusValid)
	chain := parsePEMChain(c.f.t, c.get(valid.Certificate, nil).Body.Bytes())
	return chain[0]
}

// Builds the RFC 9773 identifier of a leaf the way clients do.
func ariID(t *testing.T, leaf *x509.Certificate) string {
	t.Helper()
	serial := leaf.SerialNumber.Bytes()
	if serial[0]&0x80 != 0 {
		serial = append([]byte{0}, serial...)
	}
	if len(leaf.AuthorityKeyId) == 0 {
		t.Fatal("leaf has no authority key identifier")
	}
	return base64.RawURLEncoding.EncodeToString(leaf.AuthorityKeyId) + "." + base64.RawURLEncoding.EncodeToString(serial)
}

// Fetches renewal information with a plain GET.
func (f *flow) renewalInfo(id string) *httptest.ResponseRecorder {
	return f.do(httptest.NewRequest(http.MethodGet, baseURL+"renewal-info/"+id, nil))
}

// Posts a new order with a replaces member.
func (c *client) replacingOrder(replaces string, names ...string) *httptest.ResponseRecorder {
	identifiers := make([]map[string]string, 0, len(names))
	for _, name := range names {
		identifiers = append(identifiers, map[string]string{"type": "dns", "value": name})
	}
	return c.post(baseURL+"new-order", map[string]any{"identifiers": identifiers, "replaces": replaces})
}

func TestRenewalInfoOff(t *testing.T) {
	f := newFlow(t, nil)
	f.runWorker()
	var dir map[string]any
	decode(t, f.do(httptest.NewRequest(http.MethodGet, baseURL+"directory", nil)), &dir)
	if _, ok := dir["renewalInfo"]; ok {
		t.Fatalf("renewalInfo advertised without an advisor: %v", dir)
	}
	c := f.newClient()
	c.register()
	leaf := c.issue("a.test")
	assertProblem(t, f.renewalInfo(ariID(t, leaf)), http.StatusNotFound, acmeserver.ErrorMalformed)
	// Without the extension, replaces is an unknown member and the order carries none.
	rec := c.replacingOrder(ariID(t, leaf), "a.test")
	if rec.Code != http.StatusCreated || strings.Contains(rec.Body.String(), "replaces") {
		t.Fatalf("order with replaces while off = %d %s", rec.Code, rec.Body.String())
	}
}

func TestRenewalInfoWindow(t *testing.T) {
	f := newFlow(t, func(c *acmeserver.Config) {
		c.RenewalInfo = acmeserver.LifetimeRenewal{ExplanationURL: "https://ca.example/ari", RetryAfter: 90 * time.Minute}
	})
	f.runWorker()
	var dir map[string]any
	decode(t, f.do(httptest.NewRequest(http.MethodGet, baseURL+"directory", nil)), &dir)
	if dir["renewalInfo"] != baseURL+"renewal-info" {
		t.Fatalf("directory renewalInfo = %v", dir["renewalInfo"])
	}
	c := f.newClient()
	c.register()
	leaf := c.issue("a.test")
	rec := f.renewalInfo(ariID(t, leaf))
	if rec.Code != http.StatusOK || rec.Header().Get("Retry-After") != "5400" || rec.Header().Get("Replay-Nonce") != "" {
		t.Fatalf("renewalInfo = %d %v %s", rec.Code, rec.Header(), rec.Body.String())
	}
	var info renewalBody
	decode(t, rec, &info)
	lifetime := leaf.NotAfter.Sub(leaf.NotBefore)
	wantStart := leaf.NotBefore.Add(lifetime * 2 / 3).Truncate(time.Second)
	wantEnd := leaf.NotBefore.Add(lifetime * 5 / 6).Truncate(time.Second)
	if !info.SuggestedWindow.Start.Equal(wantStart) || !info.SuggestedWindow.End.Equal(wantEnd) ||
		info.ExplanationURL != "https://ca.example/ari" {
		t.Fatalf("window = %+v, want %s to %s", info, wantStart, wantEnd)
	}
	if rec := f.do(httptest.NewRequest(http.MethodHead, baseURL+"renewal-info/"+ariID(t, leaf), nil)); rec.Code != http.StatusOK {
		t.Fatalf("HEAD renewalInfo = %d", rec.Code)
	}
	assertProblem(t, f.renewalInfo("unknown.serial"), http.StatusNotFound, acmeserver.ErrorMalformed)
	assertProblem(t, f.renewalInfo("not-an-identifier"), http.StatusNotFound, acmeserver.ErrorMalformed)
	if rec := f.do(httptest.NewRequest(http.MethodPost, baseURL+"renewal-info/"+ariID(t, leaf), nil)); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST renewalInfo = %d", rec.Code)
	}
	// Revocation moves the window to the past so clients renew at once.
	if rec := c.post(baseURL+"revoke-cert", map[string]any{"certificate": base64.RawURLEncoding.EncodeToString(leaf.Raw)}); rec.Code != http.StatusOK {
		t.Fatalf("revoke = %d %s", rec.Code, rec.Body.String())
	}
	decode(t, f.renewalInfo(ariID(t, leaf)), &info)
	if !info.SuggestedWindow.End.Before(time.Now().Add(2*time.Minute)) || !info.SuggestedWindow.End.After(info.SuggestedWindow.Start) {
		t.Fatalf("window after revocation = %+v", info)
	}
}

func TestRenewalInfoInvalidWindow(t *testing.T) {
	f := newFlow(t, func(c *acmeserver.Config) { c.RenewalInfo = acmeserver.LifetimeRenewal{Start: 0.9, End: 0.5} })
	f.runWorker()
	c := f.newClient()
	c.register()
	leaf := c.issue("a.test")
	assertProblem(t, f.renewalInfo(ariID(t, leaf)), http.StatusInternalServerError, acmeserver.ErrorServerInternal)
	if !strings.Contains(f.logs.String(), "renewal information failed") {
		t.Fatalf("invalid window was not logged: %s", f.logs.String())
	}
}

func TestReplacesClaim(t *testing.T) {
	f := newFlow(t, func(c *acmeserver.Config) { c.RenewalInfo = acmeserver.LifetimeRenewal{} })
	f.runWorker()
	c := f.newClient()
	c.register()
	leaf := c.issue("a.test", "b.test")
	id := ariID(t, leaf)
	assertProblem(t, c.replacingOrder("not-an-identifier", "a.test"), http.StatusBadRequest, acmeserver.ErrorMalformed)
	assertProblem(t, c.replacingOrder("unknown.serial", "a.test"), http.StatusBadRequest, acmeserver.ErrorMalformed)
	assertProblem(t, c.replacingOrder(id, "c.test"), http.StatusBadRequest, acmeserver.ErrorMalformed)
	other := f.newClient()
	other.register()
	assertProblem(t, other.replacingOrder(id, "a.test"), http.StatusForbidden, acmeserver.ErrorUnauthorized)

	rec := c.replacingOrder(id, "b.test")
	if rec.Code != http.StatusCreated {
		t.Fatalf("replacing order = %d %s", rec.Code, rec.Body.String())
	}
	var order struct {
		orderBody
		Replaces string `json:"replaces"`
	}
	decode(t, rec, &order)
	location := rec.Header().Get("Location")
	if order.Replaces != id {
		t.Fatalf("order replaces = %q, want %q", order.Replaces, id)
	}
	decode(t, c.get(location, nil), &order)
	if order.Replaces != id {
		t.Fatalf("fetched order replaces = %q", order.Replaces)
	}
	stored, err := f.store.CertificateByRenewalID(t.Context(), id)
	if err != nil || stored.ReplacedByOrderID != location[len(baseURL+"order/"):] {
		t.Fatalf("stored certificate = %+v, %v", stored, err)
	}
	assertProblem(t, c.replacingOrder(id, "a.test"), http.StatusConflict, acmeserver.ErrorAlreadyReplaced)

	// Once the replacing order is invalid the certificate may be replaced again.
	f.validator.script(func(acmeserver.ValidationRequest, int) error { return errors.New("down") })
	c.respondHTTP01(order.orderBody)
	c.waitOrder(location, statusInvalid)
	f.validator.script(nil)
	rec = c.replacingOrder(id, "a.test")
	if rec.Code != http.StatusCreated {
		t.Fatalf("replacement after an invalid order = %d %s", rec.Code, rec.Body.String())
	}
	decode(t, rec, &order)
	c.respondHTTP01(order.orderBody)
	c.waitOrder(rec.Header().Get("Location"), statusReady)
	c.finalize(order.orderBody, newKey(t))
	c.waitOrder(rec.Header().Get("Location"), statusValid)
	stored, err = f.store.CertificateByRenewalID(t.Context(), id)
	if err != nil || stored.ReplacedByOrderID != rec.Header().Get("Location")[len(baseURL+"order/"):] {
		t.Fatalf("stored certificate after the second claim = %+v, %v", stored, err)
	}
}
