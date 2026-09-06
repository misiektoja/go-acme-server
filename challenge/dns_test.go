package challenge

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	acmeserver "github.com/misiektoja/go-acme-server"
)

// Names the oversized DNS response case.
const oversizedReply = "large"

// Serves bounded test DNS messages over a local TCP socket.
func dnsServer(t *testing.T, answer func(*dnsmessage.Message)) netip.AddrPort {
	t.Helper()
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
			serveDNSMessage(connection, answer)
		}
	}()
	t.Cleanup(func() { listener.Close(); <-done })
	return netip.MustParseAddrPort(listener.Addr().String())
}

// Reads one question and returns the scripted response without retaining client data.
func serveDNSMessage(connection net.Conn, answer func(*dnsmessage.Message)) {
	defer connection.Close()
	connection.SetDeadline(time.Now().Add(time.Second))
	var size [2]byte
	if _, err := io.ReadFull(connection, size[:]); err != nil {
		return
	}
	wire := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err := io.ReadFull(connection, wire); err != nil {
		return
	}
	var message dnsmessage.Message
	if message.Unpack(wire) != nil {
		return
	}
	message.Response = true
	answer(&message)
	wire, err := message.Pack()
	if err != nil {
		return
	}
	binary.BigEndian.PutUint16(size[:], uint16(len(wire)))
	connection.Write(append(size[:], wire...))
}

// Builds an IN record with a typed DNS body.
func dnsRecord(name string, typ dnsmessage.Type, body dnsmessage.ResourceBody) dnsmessage.Resource {
	return dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET, TTL: 60}, Body: body}
}

// Validates several TXT proofs and follows an explicit CNAME across separate DNS queries.
func TestDNSProofWithCNAMEAndConcurrentRecords(t *testing.T) {
	request := proofRequest(acmeserver.ChallengeDNS01, "a.test")
	digest := sha256.Sum256([]byte(request.KeyAuthorization))
	proof := base64.RawURLEncoding.EncodeToString(digest[:])
	var queries atomic.Int32
	endpoint := dnsServer(t, func(message *dnsmessage.Message) {
		queries.Add(1)
		name := message.Questions[0].Name.String()
		if name == "_acme-challenge.a.test." {
			message.Answers = []dnsmessage.Resource{dnsRecord(name, dnsmessage.TypeCNAME, &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("delegated.test.")})}
			return
		}
		message.Answers = []dnsmessage.Resource{
			dnsRecord(name, dnsmessage.TypeTXT, &dnsmessage.TXTResource{TXT: []string{"concurrent proof"}}),
			dnsRecord(name, dnsmessage.TypeTXT, &dnsmessage.TXTResource{TXT: []string{proof[:20], proof[20:]}}),
		}
	})
	resolver, err := NewResolver(ResolverOptions{Servers: []netip.AddrPort{endpoint}})
	if err != nil {
		t.Fatal(err)
	}
	validator, err := NewDNS01(DNSOptions{Resolver: resolver})
	if err != nil {
		t.Fatal(err)
	}
	for _, wildcard := range []bool{false, true} {
		request.Wildcard = wildcard
		if err := validator.Validate(t.Context(), request); err != nil {
			t.Fatal(err)
		}
	}
	if queries.Load() != 4 {
		t.Fatalf("queries = %d", queries.Load())
	}
}

// Rejects malformed envelopes, unrelated proof records and unbounded CNAME or record sets.
func TestDNSNegativeReplies(t *testing.T) {
	request := proofRequest(acmeserver.ChallengeDNS01, "a.test")
	digest := sha256.Sum256([]byte(request.KeyAuthorization))
	proof := base64.RawURLEncoding.EncodeToString(digest[:])
	for _, mode := range []string{"wrong proof", "unrelated owner", "wrong ID", "wrong question", "loop", "long chain", "records", oversizedReply, "NXDOMAIN", "SERVFAIL"} {
		t.Run(mode, func(t *testing.T) {
			endpoint := dnsServer(t, func(message *dnsmessage.Message) {
				name := message.Questions[0].Name.String()
				message.Answers = []dnsmessage.Resource{dnsRecord(name, dnsmessage.TypeTXT, &dnsmessage.TXTResource{TXT: []string{proof}})}
				switch mode {
				case "wrong proof":
					message.Answers[0].Body = &dnsmessage.TXTResource{TXT: []string{"wrong"}}
				case "unrelated owner":
					message.Answers[0].Header.Name = dnsmessage.MustNewName("other.test.")
				case "wrong ID":
					message.ID++
				case "wrong question":
					message.Questions[0].Type = dnsmessage.TypeA
				case "loop":
					message.Answers = []dnsmessage.Resource{dnsRecord(name, dnsmessage.TypeCNAME, &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(name)})}
				case "long chain":
					message.Answers = []dnsmessage.Resource{dnsRecord(name, dnsmessage.TypeCNAME, &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("x." + name)})}
				case "records":
					for range 5 {
						message.Answers = append(message.Answers, message.Answers[0])
					}
				case oversizedReply:
					message.Answers[0].Body = &dnsmessage.TXTResource{TXT: []string{string(make([]byte, 200))}}
				case "NXDOMAIN":
					message.RCode = dnsmessage.RCodeNameError
				case "SERVFAIL":
					message.RCode = dnsmessage.RCodeServerFailure
				}
			})
			options := ResolverOptions{Servers: []netip.AddrPort{endpoint}, MaxCNAMEs: 2, MaxRecords: 4}
			if mode == oversizedReply {
				options.MaxResponseBytes = 100
			}
			resolver, err := NewResolver(options)
			if err != nil {
				t.Fatal(err)
			}
			validator, err := NewDNS01(DNSOptions{Resolver: resolver})
			if err != nil {
				t.Fatal(err)
			}
			err = validator.Validate(t.Context(), request)
			if err == nil {
				t.Fatal("invalid DNS reply accepted")
			}
			if _, terminal := acmeserver.AsProblem(err); mode == "SERVFAIL" && terminal {
				t.Fatal("transient resolver error became terminal")
			}
		})
	}
}

// Resolves both address families from matching answer owners through the configured TCP resolver.
func TestResolverAddresses(t *testing.T) {
	endpoint := dnsServer(t, func(message *dnsmessage.Message) {
		q := message.Questions[0]
		var body dnsmessage.ResourceBody = &dnsmessage.AResource{A: [4]byte{8, 8, 8, 8}}
		if q.Type == dnsmessage.TypeAAAA {
			body = &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2606:4700:4700::1111").As16()}
		}
		message.Answers = []dnsmessage.Resource{dnsRecord(q.Name.String(), q.Type, body)}
	})
	resolver, err := NewResolver(ResolverOptions{Servers: []netip.AddrPort{endpoint}})
	if err != nil {
		t.Fatal(err)
	}
	addresses, err := resolver.LookupNetIP(t.Context(), "ip", "a.test.")
	if err != nil || len(addresses) != 2 || !addresses[0].Is4() || !addresses[1].Is6() {
		t.Fatalf("addresses = %v, %v", addresses, err)
	}
}

// Ignores unrelated SVCB and HTTPS bodies without running their specialized decoders.
func TestResolverSkipsUnrelatedRecordBodies(t *testing.T) {
	endpoint := dnsServer(t, func(message *dnsmessage.Message) {
		name := message.Questions[0].Name.String()
		message.Answers = []dnsmessage.Resource{
			dnsRecord(name, dnsmessage.TypeSVCB, &dnsmessage.UnknownResource{Type: dnsmessage.TypeSVCB, Data: []byte{0}}),
			dnsRecord(name, dnsmessage.TypeHTTPS, &dnsmessage.UnknownResource{Type: dnsmessage.TypeHTTPS, Data: []byte{0}}),
			dnsRecord(name, dnsmessage.TypeTXT, &dnsmessage.TXTResource{TXT: []string{"proof"}}),
		}
	})
	resolver, err := NewResolver(ResolverOptions{Servers: []netip.AddrPort{endpoint}})
	if err != nil {
		t.Fatal(err)
	}
	values, err := resolver.LookupTXT(t.Context(), "_acme-challenge.a.test.")
	if err != nil || len(values) != 1 || values[0] != "proof" {
		t.Fatalf("TXT = %v, %v", values, err)
	}
}

// Checks that decoded DNS responses stay within the record bound and carry only validation types.
func FuzzDNSResponse(f *testing.F) {
	question := dnsmessage.Question{Name: dnsmessage.MustNewName("_acme-challenge.a.test."), Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}
	valid := dnsmessage.Message{Header: dnsmessage.Header{ID: 7, Response: true}, Questions: []dnsmessage.Question{question},
		Answers: []dnsmessage.Resource{
			dnsRecord(question.Name.String(), dnsmessage.TypeTXT, &dnsmessage.TXTResource{TXT: []string{"proof"}}),
			dnsRecord(question.Name.String(), dnsmessage.TypeCNAME, &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("b.test.")}),
			dnsRecord("b.test.", dnsmessage.TypeA, &dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}}),
			dnsRecord("b.test.", dnsmessage.TypeSVCB, &dnsmessage.UnknownResource{Type: dnsmessage.TypeSVCB, Data: []byte{0}}),
		}}
	wire, err := valid.Pack()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(wire)
	f.Add(wire[:12])
	f.Add([]byte{})
	resolver, err := NewResolver(ResolverOptions{Servers: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:53")}, MaxRecords: 8})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, response []byte) {
		answers, err := resolver.parseResponse(response, 7, question)
		if err != nil {
			return
		}
		if len(answers) > 8 {
			t.Fatalf("accepted %d answers", len(answers))
		}
		for _, answer := range answers {
			var want dnsmessage.Type
			switch answer.Body.(type) {
			case *dnsmessage.AResource:
				want = dnsmessage.TypeA
			case *dnsmessage.AAAAResource:
				want = dnsmessage.TypeAAAA
			case *dnsmessage.CNAMEResource:
				want = dnsmessage.TypeCNAME
			case *dnsmessage.TXTResource:
				want = dnsmessage.TypeTXT
			default:
				t.Fatalf("decoded unrelated body %T", answer.Body)
			}
			if answer.Header.Type != want {
				t.Fatalf("body %T under header type %v", answer.Body, answer.Header.Type)
			}
		}
	})
}
