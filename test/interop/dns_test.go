package interop

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mholt/acmez/v3"
	"github.com/mholt/acmez/v3/acme"
	"golang.org/x/net/dns/dnsmessage"

	acmeserver "github.com/misiektoja/go-acme-server"
)

// Answers TXT queries over TCP with the records the independent client provisioned.
type dnsResponder struct {
	mu      sync.Mutex
	records map[string][]string
	// Number of TXT values returned by each answered query, in order.
	answered []int
	// Optional directory whose files hold one TXT value per line, named by owner without the
	// trailing dot. External hook scripts write them.
	dir string
}

// Starts the isolated DNS responder on an ephemeral loopback port.
func newDNSResponder(t *testing.T) (*dnsResponder, netip.AddrPort) {
	t.Helper()
	d := &dnsResponder{records: make(map[string][]string)}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			d.serve(connection)
		}
	}()
	t.Cleanup(func() { listener.Close(); <-done })
	return d, netip.MustParseAddrPort(listener.Addr().String())
}

// Reads one length-prefixed question and answers it from the provisioned records.
func (d *dnsResponder) serve(connection net.Conn) {
	defer connection.Close()
	connection.SetDeadline(time.Now().Add(2 * time.Second))
	var size [2]byte
	if _, err := io.ReadFull(connection, size[:]); err != nil {
		return
	}
	wire := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err := io.ReadFull(connection, wire); err != nil {
		return
	}
	var message dnsmessage.Message
	if message.Unpack(wire) != nil || len(message.Questions) != 1 {
		return
	}
	message.Response, message.RecursionAvailable = true, true
	question := message.Questions[0]
	name := strings.ToLower(question.Name.String())
	d.mu.Lock()
	values := slices.Clone(d.records[name])
	if d.dir != "" {
		values = append(values, d.fileValues(name)...)
	}
	if question.Type == dnsmessage.TypeTXT {
		d.answered = append(d.answered, len(values))
	}
	d.mu.Unlock()
	if values == nil {
		message.RCode = dnsmessage.RCodeNameError
	}
	if question.Type == dnsmessage.TypeTXT {
		for _, value := range values {
			message.Answers = append(message.Answers, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 5},
				Body:   &dnsmessage.TXTResource{TXT: []string{value}}})
		}
	}
	wire, err := message.Pack()
	if err != nil {
		return
	}
	binary.BigEndian.PutUint16(size[:], uint16(len(wire)))
	connection.Write(append(size[:], wire...))
}

// Reads the TXT values a hook script wrote for an owner, ignoring blank lines.
func (d *dnsResponder) fileValues(name string) []string {
	data, err := os.ReadFile(filepath.Join(d.dir, strings.TrimSuffix(name, ".")))
	if err != nil {
		return nil
	}
	return slices.DeleteFunc(strings.Split(string(data), "\n"), func(v string) bool { return strings.TrimSpace(v) == "" })
}

// Adds one TXT value at a lowercase fully qualified owner name.
func (d *dnsResponder) add(name, value string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.records[name] = append(d.records[name], value)
}

// Removes one TXT value and forgets the owner when it holds no more values.
func (d *dnsResponder) remove(name, value string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	remaining := slices.DeleteFunc(d.records[name], func(v string) bool { return v == value })
	if len(remaining) == 0 {
		delete(d.records, name)
	} else {
		d.records[name] = remaining
	}
}

// Reports the largest number of TXT values returned in one answer and whether records remain.
func (d *dnsResponder) summary() (int, int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Max(append([]int{0}, d.answered...)), len(d.records)
}

// Provisions the client-computed DNS-01 digests exactly where acmez says they belong.
type dnsSolver struct {
	responder *dnsResponder
	wrong     bool
}

// Adds the TXT digest for one authorization, or a same-length wrong value.
func (s *dnsSolver) Present(_ context.Context, ch acme.Challenge) error {
	value := ch.DNS01KeyAuthorization()
	if s.wrong {
		value = strings.Repeat("x", len(value))
	}
	s.responder.add(s.owner(ch), value)
	return nil
}

// Removes only the value this authorization presented.
func (s *dnsSolver) CleanUp(_ context.Context, ch acme.Challenge) error {
	value := ch.DNS01KeyAuthorization()
	if s.wrong {
		value = strings.Repeat("x", len(value))
	}
	s.responder.remove(s.owner(ch), value)
	return nil
}

// Returns the fully qualified lowercase TXT owner the client derives from the challenge.
func (*dnsSolver) owner(ch acme.Challenge) string {
	return strings.ToLower(ch.DNS01TXTRecordName()) + "."
}

// Registers the DNS responder as the only acmez solver.
func dnsSolvers(s *dnsSolver) map[string]acmez.Solver {
	return map[string]acmez.Solver{acme.ChallengeTypeDNS01: s}
}

// Issues one certificate for a wildcard and its base domain through separate DNS-01 proofs
// that share the same TXT owner name.
func TestAcmezDNS01Wildcard(t *testing.T) {
	responder, endpoint := newDNSResponder(t)
	h := newHarness(t, harnessOptions{dns: endpoint})
	s := &dnsSolver{responder: responder}
	client, account := h.acmez(t, dnsSolvers(s))
	key := newKey(t)
	names := []string{"*." + testHost, testHost}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	certs, err := client.ObtainCertificateForSANs(ctx, account, key, names)
	if err != nil || len(certs) != 1 {
		t.Fatalf("issuance = %v, %v", len(certs), err)
	}
	h.verify(t, certs[0].ChainPEM, &key.PublicKey, names, acmeserver.ChallengeDNS01)
	concurrent, remaining := responder.summary()
	if concurrent != 2 || remaining != 0 {
		t.Fatalf("most TXT values in one answer = %d, owners left = %d", concurrent, remaining)
	}
	t.Log("wildcard and base-domain DNS-01 proofs coexisted at one TXT owner and were cleaned up")
}

// Proves that a wildcard order fails without CA issuance when the TXT digest is wrong.
func TestAcmezRejectsWrongDNSProof(t *testing.T) {
	responder, endpoint := newDNSResponder(t)
	h := newHarness(t, harnessOptions{dns: endpoint})
	client, account := h.acmez(t, dnsSolvers(&dnsSolver{responder: responder, wrong: true}))
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	if _, err := client.ObtainCertificateForSANs(ctx, account, newKey(t), []string{"*." + testHost}); err == nil {
		t.Fatal("incorrect DNS proof accepted")
	}
	h.verifyRejected(t, account, acmeserver.ChallengeDNS01)
}
