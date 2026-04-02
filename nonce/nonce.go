// Package nonce provides a bounded single-process implementation of acmeserver.NonceManager.
package nonce

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"sync"
	"time"
)

// Defaults used when Options leaves a field zero.
const (
	DefaultTTL      = time.Hour
	DefaultCapacity = 100_000
)

// The random length of a nonce. 128 bits make collisions negligible.
const nonceBytes = 16

// Configures a Manager. Zero values select the defaults.
type Options struct {
	// How long an issued nonce stays valid.
	TTL time.Duration
	// Bounds the number of outstanding nonces. The oldest are dropped beyond it.
	Capacity int
	// Supplies the current time. It defaults to time.Now.
	Now func() time.Time
	// Supplies randomness. It defaults to crypto/rand.
	Rand io.Reader
}

// Issues single-use nonces for one process. Consumption, expiry, eviction and restarts only ever
// invalidate nonces. Replicas that share traffic need a coordinated implementation.
type Manager struct {
	ttl      time.Duration
	capacity int
	now      func() time.Time
	rand     io.Reader

	mu    sync.Mutex
	live  map[string]time.Time
	queue []entry
	head  int
}

// Records a nonce in issue order for expiry and eviction.
type entry struct {
	value   string
	expires time.Time
}

// Returns a Manager with the given options.
func New(opts Options) *Manager {
	m := &Manager{ttl: opts.TTL, capacity: opts.Capacity, now: opts.Now, rand: opts.Rand, live: make(map[string]time.Time)}
	if m.ttl <= 0 {
		m.ttl = DefaultTTL
	}
	if m.capacity <= 0 {
		m.capacity = DefaultCapacity
	}
	if m.now == nil {
		m.now = time.Now
	}
	if m.rand == nil {
		m.rand = rand.Reader
	}
	return m
}

// Returns a fresh nonce and drops expired or surplus nonces.
func (m *Manager) Issue(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	buf := make([]byte, nonceBytes)
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	m.purge(now)
	for len(m.live) >= m.capacity && m.head < len(m.queue) {
		m.evictOldest()
	}
	for {
		if _, err := io.ReadFull(m.rand, buf); err != nil {
			return "", err
		}
		value := base64.RawURLEncoding.EncodeToString(buf)
		if _, exists := m.live[value]; exists {
			continue
		}
		expires := now.Add(m.ttl)
		m.live[value] = expires
		m.queue = append(m.queue, entry{value: value, expires: expires})
		return value, nil
	}
}

// Invalidates the nonce and reports whether it was valid.
func (m *Manager) Consume(ctx context.Context, value string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	expires, ok := m.live[value]
	if !ok {
		return false, nil
	}
	delete(m.live, value)
	return m.now().Before(expires), nil
}

// Returns the number of outstanding nonces.
func (m *Manager) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.live)
}

// Drops expired nonces from the front of the queue and skips consumed ones.
func (m *Manager) purge(now time.Time) {
	for m.head < len(m.queue) {
		e := m.queue[m.head]
		if expires, ok := m.live[e.value]; ok && now.Before(expires) {
			break
		}
		delete(m.live, e.value)
		m.head++
	}
	m.compact()
}

// Drops the oldest outstanding nonce.
func (m *Manager) evictOldest() {
	for m.head < len(m.queue) {
		e := m.queue[m.head]
		m.head++
		if _, ok := m.live[e.value]; ok {
			delete(m.live, e.value)
			break
		}
	}
	m.compact()
}

// Compacts consumed entries once either the prefix or retained tombstones reach the bound.
func (m *Manager) compact() {
	if m.head < len(m.queue)/2 && len(m.queue)-len(m.live) < m.capacity {
		return
	}
	n := 0
	for _, e := range m.queue[m.head:] {
		if expires, ok := m.live[e.value]; ok && expires.Equal(e.expires) {
			m.queue[n] = e
			n++
		}
	}
	clear(m.queue[n:])
	m.queue = m.queue[:n]
	m.head = 0
}
