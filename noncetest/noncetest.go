// Package noncetest checks an acmeserver.NonceManager against the replay protection contract.
package noncetest

import (
	"context"
	"regexp"
	"sync"
	"testing"

	acmeserver "github.com/misiektoja/go-acme-server"
)

// RFC 8555 section 6.5.1 requires a nonce to be base64url without padding.
var base64url = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// Runs the contract suite. The open function returns a fresh manager for each subtest.
func Run(t *testing.T, open func(t *testing.T) acmeserver.NonceManager) {
	t.Run("IssueFormat", func(t *testing.T) { testIssueFormat(t, open(t)) })
	t.Run("IssueUnique", func(t *testing.T) { testIssueUnique(t, open(t)) })
	t.Run("ConsumeOnce", func(t *testing.T) { testConsumeOnce(t, open(t)) })
	t.Run("UnknownNonce", func(t *testing.T) { testUnknown(t, open(t)) })
	t.Run("ConcurrentConsume", func(t *testing.T) {
		m := open(t)
		testConcurrentConsume(t, m, m)
	})
	t.Run("CanceledContext", func(t *testing.T) { testCanceledContext(t, open(t)) })
}

// Runs the checks for managers that share nonces between replicas. The open function returns two
// managers over the same fresh shared state, as two processes behind one load balancer would see it.
func RunShared(t *testing.T, open func(t *testing.T) (acmeserver.NonceManager, acmeserver.NonceManager)) {
	t.Run("ConsumeOnOtherReplica", func(t *testing.T) {
		a, b := open(t)
		testCrossReplica(t, a, b)
	})
	t.Run("ConcurrentConsumeAcrossReplicas", func(t *testing.T) {
		a, b := open(t)
		testConcurrentConsume(t, a, b)
	})
}

// Issues a nonce and fails the test on error.
func issue(t *testing.T, m acmeserver.NonceManager) string {
	t.Helper()
	value, err := m.Issue(context.Background())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return value
}

// Consumes a nonce and fails the test on error.
func consume(t *testing.T, m acmeserver.NonceManager, value string) bool {
	t.Helper()
	ok, err := m.Consume(context.Background(), value)
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	return ok
}

// Checks that a nonce is non-empty base64url, which clients copy into the JWS header.
func testIssueFormat(t *testing.T, m acmeserver.NonceManager) {
	if value := issue(t, m); !base64url.MatchString(value) {
		t.Fatalf("Issue returned %q, want base64url without padding", value)
	}
}

// Checks that outstanding nonces never repeat.
func testIssueUnique(t *testing.T, m acmeserver.NonceManager) {
	seen := make(map[string]bool, 1000)
	for range 1000 {
		value := issue(t, m)
		if seen[value] {
			t.Fatalf("Issue returned %q twice", value)
		}
		seen[value] = true
	}
}

// Checks that a nonce is valid exactly once.
func testConsumeOnce(t *testing.T, m acmeserver.NonceManager) {
	value := issue(t, m)
	if !consume(t, m, value) {
		t.Fatal("a fresh nonce was not valid")
	}
	if consume(t, m, value) {
		t.Fatal("a consumed nonce was valid again")
	}
}

// Checks that values the manager never issued are invalid rather than errors.
func testUnknown(t *testing.T, m acmeserver.NonceManager) {
	issued := issue(t, m)
	unknown := []string{
		"",
		"AAAAAAAAAAAAAAAAAAAAAA",
		issued + "x",
		"not base64url!",
		string(make([]byte, 4096)),
	}
	for _, value := range unknown {
		if consume(t, m, value) {
			t.Fatalf("Consume(%.20q) reported a nonce that was never issued as valid", value)
		}
	}
	if !consume(t, m, issued) {
		t.Fatal("consuming unknown values invalidated an issued nonce")
	}
}

// Checks that concurrent requests carrying one nonce succeed exactly once, split over a and b.
func testConcurrentConsume(t *testing.T, a, b acmeserver.NonceManager) {
	const attempts = 16
	for range 20 {
		value := issue(t, a)
		results := make([]bool, attempts)
		errs := make([]error, attempts)
		var wg sync.WaitGroup
		for i := range attempts {
			m := a
			if i%2 == 1 {
				m = b
			}
			wg.Go(func() { results[i], errs[i] = m.Consume(context.Background(), value) })
		}
		wg.Wait()
		valid := 0
		for i := range attempts {
			if errs[i] != nil {
				t.Fatalf("Consume: %v", errs[i])
			}
			if results[i] {
				valid++
			}
		}
		if valid != 1 {
			t.Fatalf("%d concurrent requests accepted one nonce, want exactly 1", valid)
		}
	}
}

// Checks that a canceled request neither issues a nonce nor reports one as valid.
func testCanceledContext(t *testing.T, m acmeserver.NonceManager) {
	value := issue(t, m)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if issued, err := m.Issue(ctx); err == nil {
		t.Fatalf("Issue with a canceled context returned %q and no error", issued)
	}
	if ok, err := m.Consume(ctx, value); ok && err == nil {
		t.Fatal("Consume with a canceled context reported the nonce as valid")
	}
}

// Checks that a nonce issued by one replica is valid exactly once on another.
func testCrossReplica(t *testing.T, a, b acmeserver.NonceManager) {
	value := issue(t, a)
	if !consume(t, b, value) {
		t.Fatal("a nonce issued by one replica was not valid on the other")
	}
	if consume(t, a, value) {
		t.Fatal("a nonce consumed on one replica was valid again on the replica that issued it")
	}
	value = issue(t, b)
	if !consume(t, a, value) {
		t.Fatal("a nonce issued by the second replica was not valid on the first")
	}
}
