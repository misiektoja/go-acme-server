package challenge

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"
	"time"

	acmeserver "github.com/misiektoja/go-acme-server"
	"github.com/misiektoja/go-acme-server/internal/jws"
)

// Bounds the Authority Token the server may hand to the validator.
const maxAuthorityTokenLength = 16 << 10

// Names the Token Authority that an Authority Token points at. Every field comes from a token
// whose signature is still unverified.
type TokenAuthorityRef struct {
	// The x5u URL of the token header, already checked to be an https URL. It is empty when the
	// token carries a chain instead.
	URL string
	// The DER certificate chain of the token header, leaf first. It is empty when the token
	// carries an x5u URL instead.
	Chain [][]byte
	// The iss claim, empty when the token omits it.
	Issuer string
	// The kid header, empty when the token omits it.
	KeyID string
}

// Supplies the certificate of the Token Authority an ecosystem trusts, see RFC 9448 section 6
// steps 2 and 3. The validator additionally requires the returned certificate to be within its
// validity period. Returning a *acmeserver.Problem fails the challenge, and any other error is
// retried, which suits a lookup that could not be completed.
type TokenAuthorities interface {
	AuthorityCertificate(ctx context.Context, ref TokenAuthorityRef) (*x509.Certificate, error)
}

// Configures Authority Token validation.
type TKAuthOptions struct {
	// Resolves the trusted Token Authority certificate of a token. It is required.
	Authorities TokenAuthorities
	// Tolerates this much clock difference on the exp and nbf claims. Defaults to one minute.
	ClockSkew time.Duration
	// Returns the current time. It defaults to time.Now.
	Now func() time.Time
}

// Validates a tkauth-01 response by checking the Authority Token of RFC 9448 against the
// challenge identifier and the responding account.
type TKAuth01 struct {
	authorities TokenAuthorities
	skew        time.Duration
	now         func() time.Time
}

// Constructs an Authority Token validator with a required trust source.
func NewTKAuth01(options TKAuthOptions) (*TKAuth01, error) {
	if options.Authorities == nil || options.ClockSkew < 0 {
		return nil, errors.New("challenge: token authorities are required and the clock skew must not be negative")
	}
	if options.ClockSkew == 0 {
		options.ClockSkew = time.Minute
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &TKAuth01{authorities: options.Authorities, skew: options.ClockSkew, now: options.Now}, nil
}

// Checks the response and discards what it authorizes.
func (v *TKAuth01) Validate(ctx context.Context, request acmeserver.ValidationRequest) error {
	_, err := v.ValidateGrant(ctx, request)
	return err
}

// Performs the token checks an ACME server owns at response time, that is steps 1 to 8 of
// RFC 9448 section 6. The CA basic constraint of step 9 is compared with the certificate request
// at finalization, and the token expiry bounds the validity of the issued certificate.
func (v *TKAuth01) ValidateGrant(ctx context.Context,
	request acmeserver.ValidationRequest) (acmeserver.ValidationGrant, error) {
	none := acmeserver.ValidationGrant{}
	id, err := checkTKAuthRequest(request)
	if err != nil {
		return none, err
	}
	token, err := jws.ParseCompact(request.AuthorityToken)
	if err != nil {
		return none, incorrect("authority token is not a supported JWT")
	}
	claims, err := parseAuthorityToken(token.Payload)
	if err != nil {
		return none, err
	}
	ref, err := authorityRef(token.Header, claims.Issuer)
	if err != nil {
		return none, err
	}
	certificate, err := v.authorities.AuthorityCertificate(ctx, ref)
	if err != nil {
		return none, err
	}
	if certificate == nil {
		return none, errors.New("challenge: the token authority source returned no certificate")
	}
	now := v.now()
	if now.Before(certificate.NotBefore) || now.After(certificate.NotAfter) {
		return none, incorrect("the token authority certificate is not valid at this time")
	}
	if err := token.Verify(certificate.PublicKey); err != nil {
		return none, incorrect("authority token signature is invalid")
	}
	if err := v.checkClaims(claims, id, request.AccountKeyThumbprint, now); err != nil {
		return none, err
	}
	return acmeserver.ValidationGrant{CACertificate: claims.ATC.CA, Expires: time.Unix(*claims.Expires, 0)}, nil
}

// Checks the claims of a verified token against the challenge identifier and the account key.
func (v *TKAuth01) checkClaims(claims *authorityTokenJSON, id acmeserver.Identifier,
	thumbprint string, now time.Time) error {
	switch {
	// RFC 9448 section 5.4 spells the type TNAuthList while the RFC 9447 example writes TnAuthList.
	// Token Authorities built from either text must interoperate, so the comparison ignores case.
	case !strings.EqualFold(claims.ATC.TokenType, string(acmeserver.IdentifierTNAuthList)):
		return incorrect("the authority token attests another identifier type")
	case !sameAuthorityList(claims.ATC.TokenValue, id.Value):
		return incorrect("the authority token attests another authority list")
	case now.After(time.Unix(*claims.Expires, 0).Add(v.skew)):
		return incorrect("the authority token has expired")
	case claims.NotBefore != nil && now.Before(time.Unix(*claims.NotBefore, 0).Add(-v.skew)):
		return incorrect("the authority token is not valid yet")
	case !matchesAccountKey(claims.ATC.Fingerprint, thumbprint):
		return incorrect("the authority token is bound to another account key")
	}
	return nil
}

// Checks identifier scope and the captured proof before the token is parsed.
func checkTKAuthRequest(req acmeserver.ValidationRequest) (acmeserver.Identifier, error) {
	id, err := req.Identifier.Normalize()
	if err != nil {
		return acmeserver.Identifier{}, err
	}
	if req.Challenge.Type != acmeserver.ChallengeTKAuth01 || id.Type != acmeserver.IdentifierTNAuthList ||
		req.Wildcard {
		return acmeserver.Identifier{}, incorrect("identifier does not support this challenge")
	}
	if len(req.Challenge.Token) < 22 || len(req.Challenge.Token) > 256 || !base64URL(req.Challenge.Token) ||
		len(req.AccountKeyThumbprint) != 43 || !base64URL(req.AccountKeyThumbprint) ||
		req.KeyAuthorization != req.Challenge.Token+"."+req.AccountKeyThumbprint {
		return acmeserver.Identifier{}, incorrect("invalid captured key authorization")
	}
	if req.AuthorityToken == "" || len(req.AuthorityToken) > maxAuthorityTokenLength {
		return acmeserver.Identifier{}, incorrect("the authority token is missing or too large")
	}
	return id, nil
}

// The Authority Token payload of RFC 9448 section 5.
type authorityTokenJSON struct {
	Issuer    string        `json:"iss"`
	Expires   *int64        `json:"exp"`
	NotBefore *int64        `json:"nbf"`
	TokenID   string        `json:"jti"`
	ATC       *atcClaimJSON `json:"atc"`
}

// The atc claim of RFC 9447 section 4.
type atcClaimJSON struct {
	TokenType   string `json:"tktype"`
	TokenValue  string `json:"tkvalue"`
	CA          bool   `json:"ca"`
	Fingerprint string `json:"fingerprint"`
}

// Decodes the token payload and checks that the mandatory claims are present and well formed.
func parseAuthorityToken(payload []byte) (*authorityTokenJSON, error) {
	var claims authorityTokenJSON
	if err := jws.UnmarshalStrict(payload, &claims); err != nil {
		return nil, incorrect("the authority token payload is not a valid claim set")
	}
	switch {
	case claims.Expires == nil:
		return nil, incorrect("the authority token has no exp claim")
	case claims.TokenID == "":
		return nil, incorrect("the authority token has no jti claim")
	case claims.ATC == nil:
		return nil, incorrect("the authority token has no atc claim")
	case claims.ATC.TokenType == "" || claims.ATC.TokenValue == "" || claims.ATC.Fingerprint == "":
		return nil, incorrect("the atc claim is missing a mandatory key")
	}
	return &claims, nil
}

// Builds the Token Authority reference of a token and rejects a header that names none.
func authorityRef(header jws.CompactHeader, issuer string) (TokenAuthorityRef, error) {
	ref := TokenAuthorityRef{Issuer: issuer, KeyID: header.KeyID}
	switch {
	case header.X5U != "":
		target, err := url.Parse(header.X5U)
		if err != nil || target.Scheme != "https" || target.Host == "" || target.User != nil {
			return TokenAuthorityRef{}, incorrect("the authority token x5u is not an https URL")
		}
		ref.URL = header.X5U
	case len(header.X5C) != 0:
		ref.Chain = header.X5C
	default:
		return TokenAuthorityRef{}, incorrect("the authority token names no token authority certificate")
	}
	return ref, nil
}

// Reports whether two base64 encodings carry the same authority list. Padded values are accepted
// because the encoding of a token is not the encoding of the ACME identifier.
func sameAuthorityList(tkvalue, identifier string) bool {
	want, err := base64.RawURLEncoding.Strict().DecodeString(identifier)
	if err != nil {
		return false
	}
	got, ok := decodeAuthorityList(tkvalue)
	return ok && bytes.Equal(got, want)
}

// Decodes an authority list from any of the base64 forms a Token Authority may emit.
func decodeAuthorityList(value string) ([]byte, bool) {
	for _, encoding := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.StdEncoding} {
		if der, err := encoding.Strict().DecodeString(value); err == nil {
			return der, true
		}
	}
	return nil, false
}

// Reports whether an atc fingerprint identifies the account key. RFC 9448 section 5.4 refers to
// the RFC 8555 thumbprint while its example uses the hex form of the same digest, so both spellings
// are accepted.
func matchesAccountKey(fingerprint, thumbprint string) bool {
	if subtle.ConstantTimeCompare([]byte(fingerprint), []byte(thumbprint)) == 1 {
		return true
	}
	digest, err := base64.RawURLEncoding.Strict().DecodeString(thumbprint)
	if err != nil {
		return false
	}
	algorithm, value, found := strings.Cut(fingerprint, " ")
	if !found || !strings.EqualFold(algorithm, "SHA256") {
		return false
	}
	got, err := hex.DecodeString(strings.ReplaceAll(strings.TrimSpace(value), ":", ""))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, digest) == 1
}

// Accepts tokens signed by a fixed set of Token Authority certificates without any network access.
// Hosts whose ecosystem publishes a trust list implement TokenAuthorities themselves.
type StaticTokenAuthorities struct {
	// Certificates indexed by the exact x5u URL that may reference them.
	ByURL map[string]*x509.Certificate
	// Certificates accepted as the leaf of an x5c chain.
	Certificates []*x509.Certificate
}

// Returns the configured certificate that a token reference names.
func (a StaticTokenAuthorities) AuthorityCertificate(_ context.Context,
	ref TokenAuthorityRef) (*x509.Certificate, error) {
	if ref.URL != "" {
		if certificate, ok := a.ByURL[ref.URL]; ok && certificate != nil {
			return certificate, nil
		}
		return nil, incorrect("the token authority URL is not trusted")
	}
	for _, certificate := range a.Certificates {
		if len(ref.Chain) != 0 && bytes.Equal(certificate.Raw, ref.Chain[0]) {
			return certificate, nil
		}
	}
	return nil, incorrect("the token authority certificate is not trusted")
}
