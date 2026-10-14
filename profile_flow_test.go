package acmeserver_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	acmeserver "github.com/misiektoja/go-acme-server"
)

// The description the flow tests publish for the server-described profile.
const serverClientDescription = "TLS server and client certificate"

// Configures two locally described profiles and one described elsewhere.
func withProfiles(c *acmeserver.Config) {
	c.Profiles = []acmeserver.Profile{
		{Name: "tls-server-client", Description: serverClientDescription},
		{Name: "tls-client", Description: "TLS client certificate"},
		{Name: "short-lived", URL: "https://docs.acme.test/profiles/short-lived"},
	}
	c.DefaultProfile = "tls-server-client"
}

// Posts a newOrder for one name with an optional profile member.
func (c *client) newOrderWithProfile(name, profile string) *httptest.ResponseRecorder {
	payload := map[string]any{"identifiers": []map[string]string{{"type": "dns", "value": name}}}
	if profile != "" {
		payload["profile"] = profile
	}
	return c.post(baseURL+"new-order", payload)
}

// Advertises every profile in the directory meta and serves the local descriptions as text.
func TestProfilesDirectoryAndDescriptions(t *testing.T) {
	f := newFlow(t, withProfiles)
	var dir struct {
		Meta struct {
			Profiles map[string]string `json:"profiles"`
		} `json:"meta"`
	}
	decode(t, f.do(httptest.NewRequest(http.MethodGet, baseURL+"directory", nil)), &dir)
	want := map[string]string{
		"tls-server-client": baseURL + "profiles/tls-server-client",
		"tls-client":        baseURL + "profiles/tls-client",
		"short-lived":       "https://docs.acme.test/profiles/short-lived",
	}
	if len(dir.Meta.Profiles) != len(want) {
		t.Fatalf("meta.profiles = %v", dir.Meta.Profiles)
	}
	for name, url := range want {
		if dir.Meta.Profiles[name] != url {
			t.Fatalf("meta.profiles[%s] = %q, want %q", name, dir.Meta.Profiles[name], url)
		}
	}
	rec := f.do(httptest.NewRequest(http.MethodGet, baseURL+"profiles/tls-server-client", nil))
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "text/plain; charset=utf-8" ||
		rec.Body.String() != serverClientDescription {
		t.Fatalf("GET description = %d %q %q", rec.Code, rec.Header().Get("Content-Type"), rec.Body.String())
	}
	rec = f.do(httptest.NewRequest(http.MethodHead, baseURL+"profiles/tls-server-client", nil))
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 ||
		rec.Header().Get("Content-Length") != "33" {
		t.Fatalf("HEAD description = %d %q length %q", rec.Code, rec.Body.String(), rec.Header().Get("Content-Length"))
	}
	rec = f.do(httptest.NewRequest(http.MethodPost, baseURL+"profiles/tls-client", nil))
	assertProblem(t, rec, http.StatusMethodNotAllowed, acmeserver.ErrorMalformed)
	if rec.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("Allow = %q", rec.Header().Get("Allow"))
	}
	for _, path := range []string{"profiles/short-lived", "profiles/unknown", "profiles/", "profiles/tls-client/x"} {
		rec := f.do(httptest.NewRequest(http.MethodGet, baseURL+path, nil))
		assertProblem(t, rec, http.StatusNotFound, acmeserver.ErrorMalformed)
	}
}

// Issues under the requested profile, falls back to the default and refuses unadvertised names.
func TestProfileSelection(t *testing.T) {
	f := newFlow(t, withProfiles)
	f.runWorker()
	c := f.newClient()
	c.register()
	for _, tc := range []struct{ name, requested, want string }{
		{"client.test", "tls-client", "tls-client"},
		{"default.test", "", "tls-server-client"},
	} {
		rec := c.newOrderWithProfile(tc.name, tc.requested)
		if rec.Code != http.StatusCreated {
			t.Fatalf("new-order %s = %d %s", tc.name, rec.Code, rec.Body.String())
		}
		var order orderBody
		decode(t, rec, &order)
		location := rec.Header().Get("Location")
		if order.Profile != tc.want {
			t.Fatalf("%s: order profile = %q, want %q", tc.name, order.Profile, tc.want)
		}
		c.respondHTTP01(order)
		order = c.waitOrder(location, statusReady)
		if rec := c.finalize(order, newKey(t)); rec.Code != http.StatusOK {
			t.Fatalf("finalize %s = %d %s", tc.name, rec.Code, rec.Body.String())
		}
		order = c.waitOrder(location, statusValid)
		if order.Profile != tc.want {
			t.Fatalf("%s: valid order profile = %q", tc.name, order.Profile)
		}
		f.ca.mu.Lock()
		got := f.ca.calls[len(f.ca.calls)-1].Profile
		f.ca.mu.Unlock()
		if got != tc.want {
			t.Fatalf("%s: IssueRequest.Profile = %q, want %q", tc.name, got, tc.want)
		}
	}
	for _, requested := range []string{"classic", "TLS-CLIENT", "tls-client ", strings.Repeat("a", 200)} {
		rec := c.newOrderWithProfile("refused.test", requested)
		assertProblem(t, rec, http.StatusBadRequest, acmeserver.ErrorInvalidProfile)
		if strings.Contains(rec.Body.String(), requested) {
			t.Fatalf("problem echoes the requested profile: %s", rec.Body.String())
		}
	}
}

// Refuses a named profile when the server offers none and omits the order member.
func TestProfileWithoutProfiles(t *testing.T) {
	f := newFlow(t, nil)
	c := f.newClient()
	c.register()
	assertProblem(t, c.newOrderWithProfile("named.test", "classic"), http.StatusBadRequest,
		acmeserver.ErrorInvalidProfile)
	rec := c.newOrderWithProfile("plain.test", "")
	if rec.Code != http.StatusCreated || strings.Contains(rec.Body.String(), `"profile"`) {
		t.Fatalf("new-order without profiles = %d %s", rec.Code, rec.Body.String())
	}
	var dir map[string]any
	decode(t, f.do(httptest.NewRequest(http.MethodGet, baseURL+"directory", nil)), &dir)
	if _, ok := dir["meta"]; ok {
		t.Fatalf("directory meta without configuration: %v", dir["meta"])
	}
	rec = f.do(httptest.NewRequest(http.MethodGet, baseURL+"profiles/classic", nil))
	assertProblem(t, rec, http.StatusNotFound, acmeserver.ErrorMalformed)
}

// Refuses to finalize an order whose profile the server withdrew and leaves the order ready.
func TestFinalizeRefusesWithdrawnProfile(t *testing.T) {
	f := newFlow(t, withProfiles)
	f.runWorker()
	c := f.newClient()
	c.register()
	rec := c.newOrderWithProfile("withdrawn.test", "tls-client")
	if rec.Code != http.StatusCreated {
		t.Fatalf("new-order = %d %s", rec.Code, rec.Body.String())
	}
	var order orderBody
	decode(t, rec, &order)
	location := rec.Header().Get("Location")
	c.respondHTTP01(order)
	order = c.waitOrder(location, statusReady)
	reduced := newFlow(t, func(cfg *acmeserver.Config) {
		cfg.Store = f.store
		cfg.Profiles = []acmeserver.Profile{{Name: "tls-server-client", Description: serverClientDescription}}
		cfg.DefaultProfile = "tls-server-client"
	})
	later := &client{f: reduced, key: c.key, kid: c.kid}
	assertProblem(t, later.finalize(order, newKey(t)), http.StatusBadRequest, acmeserver.ErrorInvalidProfile)
	later.get(location, &order)
	if order.Status != statusReady || order.Profile != "tls-client" {
		t.Fatalf("order after refused finalize = %+v", order)
	}
	if f.ca.callCount() != 0 {
		t.Fatalf("issuer called %d times for a withdrawn profile", f.ca.callCount())
	}
}
