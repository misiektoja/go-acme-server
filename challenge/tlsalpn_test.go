package challenge

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	acmeserver "github.com/misiektoja/go-acme-server"
)

// Creates an ephemeral challenge certificate with optional malformed proof fields.
func alpnCertificate(t testing.TB, request acmeserver.ValidationRequest, mode string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(request.KeyAuthorization))
	proof, err := asn1.Marshal(digest[:])
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}, Critical: true, Value: proof}}}
	if request.Identifier.Type == acmeserver.IdentifierIP {
		certificate.IPAddresses = []net.IP{net.ParseIP(request.Identifier.Value)}
	} else {
		certificate.DNSNames = []string{strings.ToUpper(request.Identifier.Value)}
	}
	switch mode {
	case "wrong name":
		certificate.DNSNames = []string{"other.test"}
	case "extra SAN":
		certificate.EmailAddresses = []string{"admin@example.test"}
	case "not critical":
		certificate.ExtraExtensions[0].Critical = false
	case "wrong digest":
		certificate.ExtraExtensions[0].Value[len(proof)-1] ^= 1
	case "missing proof":
		certificate.ExtraExtensions = nil
	case "malformed proof":
		certificate.ExtraExtensions[0].Value = []byte{4, 1, 0}
	case "expired":
		certificate.NotAfter = time.Now().Add(-time.Minute)
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// Starts a real TLS listener and captures the client's SNI without exchanging application data.
func alpnServer(t *testing.T, certificate tls.Certificate, protocol string) (net.Listener, <-chan string) {
	t.Helper()
	names := make(chan string, 8)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate},
		NextProtos: []string{protocol}, GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) { names <- hello.ServerName; return nil, nil }})
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
			connection.SetDeadline(time.Now().Add(time.Second))
			connection.(*tls.Conn).Handshake()
			connection.Close()
		}
	}()
	t.Cleanup(func() { listener.Close(); <-done })
	return listener, names
}

// Exercises negotiated ALPN, complete SAN checks and critical proof bytes over real TLS.
func TestTLSALPNProofs(t *testing.T) {
	for _, mode := range []string{"valid", "wrong name", "extra SAN", "not critical", "wrong digest", "missing proof", "malformed proof", "wrong ALPN", "expired"} {
		t.Run(mode, func(t *testing.T) {
			request := proofRequest(acmeserver.ChallengeTLSALPN01, "a.test")
			protocol := ALPNProtocol
			if mode == "wrong ALPN" {
				protocol = "http/1.1"
			}
			listener, names := alpnServer(t, alpnCertificate(t, request, mode), protocol)
			validator, err := NewTLSALPN01(TLSALPNOptions{Network: localNetwork(), TestPort: listenerPort(t, listener.Addr())})
			if err != nil {
				t.Fatal(err)
			}
			err = validator.Validate(t.Context(), request)
			valid := mode == "valid" || mode == "expired"
			if (err == nil) != valid {
				t.Fatalf("Validate = %v, valid = %v", err, valid)
			}
			if name := <-names; name != "a.test" {
				t.Fatalf("SNI = %q", name)
			}
		})
	}
}

// Skips DNS resolution for IP proof and sends reverse-mapping SNI with an IP SAN.
func TestTLSALPNIP(t *testing.T) {
	request := proofRequest(acmeserver.ChallengeTLSALPN01, "127.0.0.1")
	listener, names := alpnServer(t, alpnCertificate(t, request, "valid"), ALPNProtocol)
	network := localNetwork()
	network.Resolver = ipResolverFunc(func(_ context.Context, _, _ string) ([]netip.Addr, error) {
		t.Error("IP proof performed DNS resolution")
		return nil, nil
	})
	validator, err := NewTLSALPN01(TLSALPNOptions{Network: network, TestPort: listenerPort(t, listener.Addr())})
	if err != nil {
		t.Fatal(err)
	}
	if err := validator.Validate(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	if name := <-names; name != "1.0.0.127.in-addr.arpa" {
		t.Fatalf("SNI = %q", name)
	}
	if name := reverseName(netip.MustParseAddr("2001:db8::1")); name != "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa" {
		t.Fatalf("IPv6 SNI = %q", name)
	}
}

// Checks that only a critical exact digest with exactly one matching SAN passes the proof check.
func FuzzALPNProof(f *testing.F) {
	request := proofRequest(acmeserver.ChallengeTLSALPN01, "a.test")
	id, err := request.Identifier.Normalize()
	if err != nil {
		f.Fatal(err)
	}
	valid, err := x509.ParseCertificate(alpnCertificate(f, request, "valid").Certificate[0])
	if err != nil {
		f.Fatal(err)
	}
	var sanDER, proofDER []byte
	for _, extension := range valid.Extensions {
		switch {
		case extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}):
			sanDER = extension.Value
		case extension.Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}):
			proofDER = extension.Value
		}
	}
	f.Add(sanDER, proofDER, true)
	f.Add(sanDER, proofDER, false)
	f.Add([]byte{0x30, 0x00}, proofDER, true)
	f.Add(sanDER, []byte{0x04, 0x00}, true)
	f.Fuzz(func(t *testing.T, san, proof []byte, critical bool) {
		cert := &x509.Certificate{Extensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: san},
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}, Critical: critical, Value: proof}}}
		state := tls.ConnectionState{NegotiatedProtocol: ALPNProtocol, PeerCertificates: []*x509.Certificate{cert}}
		err := checkALPNProof(state, id, request.KeyAuthorization)
		if err == nil {
			var names []asn1.RawValue
			rest, parseErr := asn1.Unmarshal(san, &names)
			if !critical || !bytes.Equal(proof, proofDER) || parseErr != nil || len(rest) != 0 || len(names) != 1 ||
				names[0].Tag != 2 || !strings.EqualFold(string(names[0].Bytes), "a.test") {
				t.Fatalf("accepted san=%x proof=%x critical=%v", san, proof, critical)
			}
			return
		}
		if _, terminal := acmeserver.AsProblem(err); !terminal {
			t.Fatalf("proof check returned a retryable error: %v", err)
		}
	})
}
