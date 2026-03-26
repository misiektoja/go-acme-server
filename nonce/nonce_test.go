package nonce

import (
	"context"
	"errors"
	"regexp"
	"sync"
	"testing"
	"time"
)

// A settable clock.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

// Returns the current fake time.
func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Moves the fake time forward.
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func TestIssueAndConsume(t *testing.T) {
	ctx := context.Background()
	m := New(Options{})
	value, err := m.Issue(ctx)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`).MatchString(value) {
		t.Fatalf("nonce %q is not 22 base64url characters", value)
	}
	if ok, err := m.Consume(ctx, value); err != nil || !ok {
		t.Fatalf("first Consume = %v, %v", ok, err)
	}
	if ok, err := m.Consume(ctx, value); err != nil || ok {
		t.Fatalf("second Consume = %v, %v, want false", ok, err)
	}
	if ok, err := m.Consume(ctx, "unknown"); err != nil || ok {
		t.Fatalf("Consume(unknown) = %v, %v", ok, err)
	}
	if ok, err := m.Consume(ctx, ""); err != nil || ok {
		t.Fatalf("Consume(empty) = %v, %v", ok, err)
	}
}

func TestExpiry(t *testing.T) {
	ctx := context.Background()
	clock := &fakeClock{now: time.Date(2026, 3, 26, 12, 0, 0, 0, time.UTC)}
	m := New(Options{TTL: time.Minute, Now: clock.Now})
	old, _ := m.Issue(ctx)
	clock.Advance(59 * time.Second)
	fresh, _ := m.Issue(ctx)
	clock.Advance(time.Second)
	if ok, _ := m.Consume(ctx, old); ok {
		t.Fatal("expired nonce consumed")
	}
	if ok, _ := m.Consume(ctx, fresh); !ok {
		t.Fatal("unexpired nonce rejected")
	}
	clock.Advance(time.Hour)
	if _, err := m.Issue(ctx); err != nil {
		t.Fatal(err)
	}
	if got := m.Len(); got != 1 {
		t.Fatalf("Len() = %d after purge, want 1", got)
	}
}

func TestCapacityEvictsOldest(t *testing.T) {
	ctx := context.Background()
	m := New(Options{Capacity: 3})
	values := make([]string, 0, 4)
	for range 4 {
		v, err := m.Issue(ctx)
		if err != nil {
			t.Fatal(err)
		}
		values = append(values, v)
	}
	if got := m.Len(); got != 3 {
		t.Fatalf("Len() = %d, want 3", got)
	}
	if ok, _ := m.Consume(ctx, values[0]); ok {
		t.Fatal("evicted nonce consumed")
	}
	for _, v := range values[1:] {
		if ok, _ := m.Consume(ctx, v); !ok {
			t.Fatalf("retained nonce %s rejected", v)
		}
	}
	if got := m.Len(); got != 0 {
		t.Fatalf("Len() = %d, want 0", got)
	}
}

func TestEvictionSkipsConsumed(t *testing.T) {
	ctx := context.Background()
	m := New(Options{Capacity: 2})
	first, _ := m.Issue(ctx)
	second, _ := m.Issue(ctx)
	if ok, _ := m.Consume(ctx, first); !ok {
		t.Fatal("first nonce rejected")
	}
	third, _ := m.Issue(ctx)
	if ok, _ := m.Consume(ctx, second); !ok {
		t.Fatal("second nonce evicted although a consumed entry was older")
	}
	if ok, _ := m.Consume(ctx, third); !ok {
		t.Fatal("third nonce rejected")
	}
}

func TestQueueCompaction(t *testing.T) {
	ctx := context.Background()
	m := New(Options{Capacity: 8})
	for range 1000 {
		v, err := m.Issue(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if ok, _ := m.Consume(ctx, v); !ok {
			t.Fatal("nonce rejected")
		}
	}
	m.mu.Lock()
	queued := len(m.queue)
	m.mu.Unlock()
	if queued > 16 {
		t.Fatalf("queue holds %d entries after compaction", queued)
	}
}

func TestConcurrentUse(t *testing.T) {
	ctx := context.Background()
	m := New(Options{Capacity: 10_000})
	const workers, perWorker = 32, 200
	var wg sync.WaitGroup
	failures := make([]int, workers)
	for w := range workers {
		wg.Go(func() {
			for range perWorker {
				v, err := m.Issue(ctx)
				if err != nil {
					failures[w]++
					continue
				}
				if ok, err := m.Consume(ctx, v); err != nil || !ok {
					failures[w]++
				}
				if ok, _ := m.Consume(ctx, v); ok {
					failures[w]++
				}
			}
		})
	}
	wg.Wait()
	for w, n := range failures {
		if n != 0 {
			t.Fatalf("worker %d saw %d failures", w, n)
		}
	}
	if got := m.Len(); got != 0 {
		t.Fatalf("Len() = %d after consuming everything", got)
	}
}

func TestContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m := New(Options{})
	if _, err := m.Issue(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Issue error = %v", err)
	}
	if _, err := m.Consume(ctx, "x"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Consume error = %v", err)
	}
}

func TestDefaults(t *testing.T) {
	m := New(Options{TTL: -1, Capacity: -1})
	if m.ttl != DefaultTTL || m.capacity != DefaultCapacity || m.now == nil || m.rand == nil {
		t.Fatalf("defaults not applied: %+v", m)
	}
}
