package challenge

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	acmeserver "github.com/misiektoja/go-acme-server"
)

// The x5u URL the tests configure as the trusted Token Authority.
const authorityURL = "https://authority.example.test/cert"

// A Token Authority with the certificate that signs its Authority Tokens.
type authority struct {
	key         *ecdsa.PrivateKey
	certificate *x509.Certificate
}

// Returns a Token Authority whose certificate is valid for the given window around now.
func newAuthority(t *testing.T, notBefore, notAfter time.Time) *authority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "token authority"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &authority{key: key, certificate: certificate}
}

// Signs a compact ES256 token with the given header and claims.
func (a *authority) sign(t *testing.T, header, claims map[string]any) string {
	t.Helper()
	protected, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	input := base64.RawURLEncoding.EncodeToString(protected) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	der, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	var pair struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &pair); err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	pair.R.FillBytes(signature[:32])
	pair.S.FillBytes(signature[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// The TN authorization list the tests authorize, a service provider code entry for 1234.
var testAuthorityList = []byte{0x30, 0x08, 0xa0, 0x06, 0x16, 0x04, '1', '2', '3', '4'}

// Returns the base64url identifier value of the test authority list.
func testTNAuthList() string { return base64.RawURLEncoding.EncodeToString(testAuthorityList) }

// Returns a tkauth-01 request for the test authority list carrying the token.
func tokenRequest(token string) acmeserver.ValidationRequest {
	thumb := strings.Repeat("A", 43)
	challenge := strings.Repeat("B", 43)
	return acmeserver.ValidationRequest{
		Identifier:           acmeserver.Identifier{Type: acmeserver.IdentifierTNAuthList, Value: testTNAuthList()},
		Challenge:            acmeserver.Challenge{Type: acmeserver.ChallengeTKAuth01, Token: challenge},
		AccountKeyThumbprint: thumb,
		KeyAuthorization:     challenge + "." + thumb,
		AuthorityToken:       token,
	}
}

// Returns the claim set of a token that should validate.
func validClaims() map[string]any {
	return map[string]any{
		"iss": "https://authority.example.test",
		"exp": time.Now().Add(time.Hour).Unix(),
		"jti": "id6098364921",
		"atc": map[string]any{"tktype": "TNAuthList", "tkvalue": testTNAuthList(),
			"fingerprint": strings.Repeat("A", 43)},
	}
}

// Returns a validator that trusts the authority at the test x5u URL.
func tokenValidator(t *testing.T, a *authority) *TKAuth01 {
	t.Helper()
	validator, err := NewTKAuth01(TKAuthOptions{
		Authorities: StaticTokenAuthorities{ByURL: map[string]*x509.Certificate{authorityURL: a.certificate}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return validator
}

// Returns the header of a token that names the trusted authority through x5u.
func authorityHeader() map[string]any {
	return map[string]any{"typ": "JWT", "alg": "ES256", "x5u": authorityURL}
}

// Accepts a token bound to the account key and reports the CA grant it carries.
func TestTKAuth01Accepts(t *testing.T) {
	now := time.Now()
	a := newAuthority(t, now.Add(-time.Hour), now.Add(time.Hour))
	validator := tokenValidator(t, a)
	digest, err := base64.RawURLEncoding.DecodeString(strings.Repeat("A", 43))
	if err != nil {
		t.Fatal(err)
	}
	hexPrint := strings.ToUpper(hex.EncodeToString(digest))
	var colons []string
	for i := 0; i < len(hexPrint); i += 2 {
		colons = append(colons, hexPrint[i:i+2])
	}
	cases := map[string]struct {
		mutate func(map[string]any)
		ca     bool
	}{
		"thumbprint fingerprint": {mutate: func(map[string]any) {}},
		"hex fingerprint": {mutate: func(claims map[string]any) {
			claims["atc"].(map[string]any)["fingerprint"] = "SHA256 " + strings.Join(colons, ":")
		}},
		"padded authority list": {mutate: func(claims map[string]any) {
			claims["atc"].(map[string]any)["tkvalue"] = base64.URLEncoding.EncodeToString(testAuthorityList)
		}},
		"ca grant": {mutate: func(claims map[string]any) {
			claims["atc"].(map[string]any)["ca"] = true
		}, ca: true},
		"RFC 9447 example spelling": {mutate: func(claims map[string]any) {
			claims["atc"].(map[string]any)["tktype"] = "TnAuthList"
		}},
		"not before in the past": {mutate: func(claims map[string]any) {
			claims["nbf"] = now.Add(-time.Minute).Unix()
		}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			claims := validClaims()
			tc.mutate(claims)
			grant, err := validator.ValidateGrant(t.Context(), tokenRequest(a.sign(t, authorityHeader(), claims)))
			if err != nil {
				t.Fatalf("ValidateGrant: %v", err)
			}
			if grant.CACertificate != tc.ca {
				t.Fatalf("CACertificate = %v, want %v", grant.CACertificate, tc.ca)
			}
			if exp, _ := claims["exp"].(int64); !grant.Expires.Equal(time.Unix(exp, 0)) {
				t.Fatalf("Expires = %v, want the exp claim %d", grant.Expires, exp)
			}
		})
	}
}

// Refuses tokens that fail any check of RFC 9448 section 6.
func TestTKAuth01Refuses(t *testing.T) {
	now := time.Now()
	a := newAuthority(t, now.Add(-time.Hour), now.Add(time.Hour))
	validator := tokenValidator(t, a)
	other := newAuthority(t, now.Add(-time.Hour), now.Add(time.Hour))
	cases := map[string]func() string{
		"another signer": func() string {
			return other.sign(t, authorityHeader(), validClaims())
		},
		"untrusted x5u": func() string {
			header := authorityHeader()
			header["x5u"] = "https://other.example.test/cert"
			return a.sign(t, header, validClaims())
		},
		"insecure x5u": func() string {
			header := authorityHeader()
			header["x5u"] = "http://authority.example.test/cert"
			return a.sign(t, header, validClaims())
		},
		"no authority reference": func() string {
			return a.sign(t, map[string]any{"typ": "JWT", "alg": "ES256"}, validClaims())
		},
		"untrusted chain": func() string {
			header := map[string]any{"typ": "JWT", "alg": "ES256",
				"x5c": []string{base64.StdEncoding.EncodeToString(a.certificate.Raw)}}
			return a.sign(t, header, validClaims())
		},
		"expired token": func() string {
			claims := validClaims()
			claims["exp"] = now.Add(-2 * time.Minute).Unix()
			return a.sign(t, authorityHeader(), claims)
		},
		"not valid yet": func() string {
			claims := validClaims()
			claims["nbf"] = now.Add(2 * time.Minute).Unix()
			return a.sign(t, authorityHeader(), claims)
		},
		"no exp": func() string {
			claims := validClaims()
			delete(claims, "exp")
			return a.sign(t, authorityHeader(), claims)
		},
		"no jti": func() string {
			claims := validClaims()
			delete(claims, "jti")
			return a.sign(t, authorityHeader(), claims)
		},
		"no atc": func() string {
			claims := validClaims()
			delete(claims, "atc")
			return a.sign(t, authorityHeader(), claims)
		},
		"no fingerprint": func() string {
			claims := validClaims()
			delete(claims["atc"].(map[string]any), "fingerprint")
			return a.sign(t, authorityHeader(), claims)
		},
		"another token type": func() string {
			claims := validClaims()
			claims["atc"].(map[string]any)["tktype"] = "dns"
			return a.sign(t, authorityHeader(), claims)
		},
		"another authority list": func() string {
			claims := validClaims()
			claims["atc"].(map[string]any)["tkvalue"] = base64.RawURLEncoding.EncodeToString(
				[]byte{0x30, 0x08, 0xa0, 0x06, 0x16, 0x04, '9', '9', '9', '9'})
			return a.sign(t, authorityHeader(), claims)
		},
		"another account key": func() string {
			claims := validClaims()
			claims["atc"].(map[string]any)["fingerprint"] = strings.Repeat("C", 43)
			return a.sign(t, authorityHeader(), claims)
		},
		"not a token": func() string { return "not.a.token" },
		"empty token": func() string { return "" },
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := validator.ValidateGrant(t.Context(), tokenRequest(build()))
			if err == nil {
				t.Fatal("an unacceptable authority token was accepted")
			}
			p, terminal := acmeserver.AsProblem(err)
			if !terminal || p.Type != acmeserver.ErrorIncorrectResponse {
				t.Fatalf("error = %v, want an incorrectResponse problem", err)
			}
		})
	}
}

// Refuses a token whose Token Authority certificate is outside its validity period.
func TestTKAuth01AuthorityCertificateValidity(t *testing.T) {
	now := time.Now()
	a := newAuthority(t, now.Add(-2*time.Hour), now.Add(-time.Hour))
	validator := tokenValidator(t, a)
	_, err := validator.ValidateGrant(t.Context(), tokenRequest(a.sign(t, authorityHeader(), validClaims())))
	if p, terminal := acmeserver.AsProblem(err); !terminal || p.Type != acmeserver.ErrorIncorrectResponse {
		t.Fatalf("error = %v, want an incorrectResponse problem", err)
	}
}

// Accepts a trusted certificate presented in the x5c header.
func TestTKAuth01AcceptsChain(t *testing.T) {
	now := time.Now()
	a := newAuthority(t, now.Add(-time.Hour), now.Add(time.Hour))
	validator, err := NewTKAuth01(TKAuthOptions{
		Authorities: StaticTokenAuthorities{Certificates: []*x509.Certificate{a.certificate}},
	})
	if err != nil {
		t.Fatal(err)
	}
	header := map[string]any{"typ": "JWT", "alg": "ES256",
		"x5c": []string{base64.StdEncoding.EncodeToString(a.certificate.Raw)}}
	if err := validator.Validate(t.Context(), tokenRequest(a.sign(t, header, validClaims()))); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

// A trust source whose lookup could not be completed.
type failingAuthorities struct{}

// Reports a lookup failure that is not a protocol refusal.
func (failingAuthorities) AuthorityCertificate(context.Context, TokenAuthorityRef) (*x509.Certificate, error) {
	return nil, errors.New("trust list unavailable")
}

// Keeps a trust lookup failure retryable instead of failing the challenge.
func TestTKAuth01RetriesLookupFailure(t *testing.T) {
	now := time.Now()
	a := newAuthority(t, now.Add(-time.Hour), now.Add(time.Hour))
	validator, err := NewTKAuth01(TKAuthOptions{Authorities: failingAuthorities{}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = validator.ValidateGrant(t.Context(), tokenRequest(a.sign(t, authorityHeader(), validClaims())))
	if err == nil {
		t.Fatal("a failed trust lookup was accepted")
	}
	if _, terminal := acmeserver.AsProblem(err); terminal {
		t.Fatalf("a failed trust lookup became terminal: %v", err)
	}
}

// Refuses a request whose identifier or captured proof does not fit the challenge.
func TestTKAuth01RequestScope(t *testing.T) {
	now := time.Now()
	a := newAuthority(t, now.Add(-time.Hour), now.Add(time.Hour))
	validator := tokenValidator(t, a)
	token := a.sign(t, authorityHeader(), validClaims())
	cases := map[string]func(*acmeserver.ValidationRequest){
		"dns identifier": func(req *acmeserver.ValidationRequest) {
			req.Identifier = acmeserver.Identifier{Type: acmeserver.IdentifierDNS, Value: "a.test"}
		},
		"uri identifier": func(req *acmeserver.ValidationRequest) {
			req.Identifier = acmeserver.Identifier{Type: acmeserver.IdentifierURI, Value: "https://a.test/"}
		},
		"another challenge type": func(req *acmeserver.ValidationRequest) {
			req.Challenge.Type = acmeserver.ChallengeDNS01
		},
		"wildcard": func(req *acmeserver.ValidationRequest) { req.Wildcard = true },
		"broken key authorization": func(req *acmeserver.ValidationRequest) {
			req.KeyAuthorization = "wrong"
		},
		"missing token": func(req *acmeserver.ValidationRequest) { req.AuthorityToken = "" },
		"oversized token": func(req *acmeserver.ValidationRequest) {
			req.AuthorityToken = strings.Repeat("a", maxAuthorityTokenLength+1)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			request := tokenRequest(token)
			mutate(&request)
			if _, err := validator.ValidateGrant(t.Context(), request); err == nil {
				t.Fatal("an out-of-scope request was accepted")
			}
		})
	}
}

// Rejects a configuration without a trust source.
func TestNewTKAuth01Rejects(t *testing.T) {
	if _, err := NewTKAuth01(TKAuthOptions{}); err == nil {
		t.Fatal("a validator without token authorities was accepted")
	}
	if _, err := NewTKAuth01(TKAuthOptions{Authorities: failingAuthorities{}, ClockSkew: -time.Second}); err == nil {
		t.Fatal("a negative clock skew was accepted")
	}
}

// The NF instance the NF token tests authorize.
const testNfInstance = "4ace9d34-2c69-4f99-92d5-a73a3fe8e23b"

// Returns a tkauth-01 request for the test NF instance carrying the token.
func nfRequest(token string) acmeserver.ValidationRequest {
	request := tokenRequest(token)
	request.Identifier = acmeserver.Identifier{Type: acmeserver.IdentifierNfInstanceID, Value: testNfInstance}
	return request
}

// Returns the claim set of an NF Certificate Authority Token that should validate, after the
// example of 3GPP TS 33.310 clause J.3.3.3.
func nfClaims() map[string]any {
	return map[string]any{
		"exp": time.Now().Add(time.Hour).Unix(),
		"jti": "id6098364921",
		"atc": map[string]any{"tktype": "NfInstanceId", "tkvalue": testNfInstance,
			"fingerprint": strings.Repeat("A", 43), "nftype": "AMF", "sans": []string{"amf1234.example.test"}},
	}
}

// Accepts an NF token and reports the NF type and the names it grants.
func TestTKAuth01AcceptsNfInstance(t *testing.T) {
	now := time.Now()
	a := newAuthority(t, now.Add(-time.Hour), now.Add(time.Hour))
	validator := tokenValidator(t, a)
	dns := func(value string) acmeserver.Identifier {
		return acmeserver.Identifier{Type: acmeserver.IdentifierDNS, Value: value}
	}
	cases := map[string]struct {
		mutate func(atc map[string]any)
		names  []acmeserver.Identifier
		nfType string
	}{
		"specification example": {mutate: func(map[string]any) {},
			names: []acmeserver.Identifier{dns("amf1234.example.test")}, nfType: "AMF"},
		"upper-case instance": {mutate: func(atc map[string]any) {
			atc["tkvalue"] = strings.ToUpper(testNfInstance)
		}, names: []acmeserver.Identifier{dns("amf1234.example.test")}, nfType: "AMF"},
		"every name kind": {mutate: func(atc map[string]any) {
			atc["sans"] = []string{"AMF1.Example.test", "192.0.2.10", "2001:db8::10",
				"HTTPS://Amf1.Example.test/api", "urn:uuid:" + strings.ToUpper(testNfInstance), "amf1.example.test"}
		}, names: []acmeserver.Identifier{
			dns("amf1.example.test"),
			{Type: acmeserver.IdentifierIP, Value: "192.0.2.10"},
			{Type: acmeserver.IdentifierIP, Value: "2001:db8::10"},
			{Type: acmeserver.IdentifierURI, Value: "https://amf1.example.test/api"},
		}, nfType: "AMF"},
		"wildcard left to the host": {mutate: func(atc map[string]any) {
			atc["sans"] = []string{"*.amf.example.test"}
		}, names: []acmeserver.Identifier{dns("*.amf.example.test")}, nfType: "AMF"},
		"no profile parameters": {mutate: func(atc map[string]any) {
			delete(atc, "nftype")
			delete(atc, "sans")
		}},
		"ca member ignored": {mutate: func(atc map[string]any) {
			atc["ca"] = true
			delete(atc, "sans")
		}, nfType: "AMF"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			claims := nfClaims()
			tc.mutate(claims["atc"].(map[string]any))
			grant, err := validator.ValidateGrant(t.Context(), nfRequest(a.sign(t, authorityHeader(), claims)))
			if err != nil {
				t.Fatalf("ValidateGrant: %v", err)
			}
			if !slices.Equal(grant.Names, tc.names) || grant.NFType != tc.nfType || grant.CACertificate {
				t.Fatalf("grant = %+v, want names %v and NF type %q", grant, tc.names, tc.nfType)
			}
			if exp, _ := claims["exp"].(int64); !grant.Expires.Equal(time.Unix(exp, 0)) {
				t.Fatalf("Expires = %v, want the exp claim %d", grant.Expires, exp)
			}
		})
	}
}

// Refuses NF tokens that fail a check of 3GPP TS 33.310 clause J.3.3.4 or carry unusable names.
func TestTKAuth01RefusesNfInstance(t *testing.T) {
	now := time.Now()
	a := newAuthority(t, now.Add(-time.Hour), now.Add(time.Hour))
	validator := tokenValidator(t, a)
	tooMany := make([]string, maxTokenNames+1)
	for i := range tooMany {
		tooMany[i] = "nf" + strconv.Itoa(i) + ".example.test"
	}
	cases := map[string]func(claims, atc map[string]any){
		"another instance":      func(_, atc map[string]any) { atc["tkvalue"] = "5bce9d34-2c69-4f99-92d5-a73a3fe8e23b" },
		"TNAuthList token type": func(_, atc map[string]any) { atc["tktype"] = "TNAuthList" },
		"another account key":   func(_, atc map[string]any) { atc["fingerprint"] = strings.Repeat("C", 43) },
		"expired token":         func(claims, _ map[string]any) { claims["exp"] = now.Add(-2 * time.Minute).Unix() },
		"empty nftype":          func(_, atc map[string]any) { atc["nftype"] = "" },
		"nftype with a space":   func(_, atc map[string]any) { atc["nftype"] = "A MF" },
		"nftype too long":       func(_, atc map[string]any) { atc["nftype"] = strings.Repeat("A", 33) },
		"nftype not a string":   func(_, atc map[string]any) { atc["nftype"] = 7 },
		"sans not a list":       func(_, atc map[string]any) { atc["sans"] = "amf1.example.test" },
		"too many sans":         func(_, atc map[string]any) { atc["sans"] = tooMany },
		"another instance URN":  func(_, atc map[string]any) { atc["sans"] = []string{"urn:uuid:5bce9d34-2c69-4f99-92d5-a73a3fe8e23b"} },
		"http URI":              func(_, atc map[string]any) { atc["sans"] = []string{"http://amf1.example.test/api"} },
		"URI with user info":    func(_, atc map[string]any) { atc["sans"] = []string{"https://user@amf1.example.test/"} },
		"invalid DNS name":      func(_, atc map[string]any) { atc["sans"] = []string{"amf_1.example.test"} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			claims := nfClaims()
			mutate(claims, claims["atc"].(map[string]any))
			_, err := validator.ValidateGrant(t.Context(), nfRequest(a.sign(t, authorityHeader(), claims)))
			if p, terminal := acmeserver.AsProblem(err); !terminal || p.Type != acmeserver.ErrorIncorrectResponse {
				t.Fatalf("error = %v, want an incorrectResponse problem", err)
			}
		})
	}
}
