package acmeserver

import (
	"context"
	"crypto/x509"
	"time"
)

// What the host CA receives when an order is ready for issuance. The same OperationID is
// presented on every attempt for one order, so the issuer can deduplicate retries.
type IssueRequest struct {
	OperationID string
	AccountID   string
	AccountURL  string
	OrderID     string
	// The parsed certificate request and its DER encoding. The signature and the identifier
	// set were already checked against the order. CSR.PublicKey is nil for a composite ML-DSA
	// key. Read that key with compositex509.ParsePKIXPublicKey from CSR.RawSubjectPublicKeyInfo
	// and certify it with compositex509.CreateCertificate.
	CSR    *x509.CertificateRequest
	CSRDER []byte
	// The normalized identifiers the order covers.
	Identifiers []Identifier
	// The requested validity. Zero values mean the host decides. An authority token expiry
	// narrows NotAfter. The issuer may return a shorter validity, but the leaf must fit inside
	// the requested window and must be valid already unless NotBefore is in the future.
	NotBefore time.Time
	NotAfter  time.Time
	// How each identifier was validated.
	Validations []Validation
	// The earliest order, authorization or authority token expiry, after which new signing is
	// forbidden.
	Deadline time.Time
	// Allows only recovery of an existing result, never a new signing operation.
	RecoveryOnly bool
	// The Order.Profile name the certificate is issued under. It is empty when the server offered
	// no profiles when the order was created.
	Profile string
}

// The outcome of an issuance attempt. Exactly one of Chain, Pending and Rejected is set.
type IssueResult struct {
	// The DER leaf certificate followed by the DER issuer chain.
	Chain [][]byte
	// An opaque host CA reference retained with issued or unpublished results.
	CAReference string
	// Reports that the CA has not decided yet. The worker asks again after RetryAfter.
	Pending    bool
	RetryAfter time.Duration
	// A final refusal that becomes the order error.
	Rejected *Problem
}

// Issues or recovers one durable result per operation ID, enforcing Deadline and RecoveryOnly for new signing.
type Issuer interface {
	Issue(ctx context.Context, req IssueRequest) (IssueResult, error)
}

// Reviews current policy before the first durable issuance dispatch.
type IssuancePolicy interface {
	AuthorizeIssuance(ctx context.Context, req IssueRequest) error
}

// What the host CA receives for a revocation.
type RevokeRequest struct {
	// Stable across retries until the CA accepts or refuses the revocation. It is stored before the
	// first call and discarded when Revoke returns a *Problem.
	OperationID string
	Certificate *x509.Certificate
	DER         []byte
	// The CRL reason code recorded with the operation. A retry keeps the recorded reason.
	Reason int
	// The account that requested the revocation. Empty when the certificate key signed the request.
	AccountID string
}

// Revokes certificates. Revoke returns nil only after the CA recorded the revocation durably.
// A returned *Problem is a final refusal sent to the client. Any other error is reported as
// serverInternal and the next request repeats the same operation.
// The CA must deduplicate by OperationID because a client retries after an uncertain answer.
type Revoker interface {
	Revoke(ctx context.Context, req RevokeRequest) error
}

// What a validator receives for one challenge.
type ValidationRequest struct {
	Challenge  Challenge
	Identifier Identifier
	// Marks a wildcard authorization. Identifier then holds the base name.
	Wildcard bool
	// The token joined with the account key thumbprint, see RFC 8555 section 8.1.
	KeyAuthorization string
	// The RFC 7638 thumbprint of the account key captured when the client responded.
	AccountKeyThumbprint string
	// The Authority Token of a tkauth-01 response, empty for every other challenge type.
	AuthorityToken string
}

// What a successful challenge response authorizes beyond control of the identifier.
type ValidationGrant struct {
	// Allows the order to be finalized with a certificate request that asks for a CA
	// certificate, see RFC 9448 section 6.
	CACertificate bool
	// Bounds the validity of certificates issued on this proof, see RFC 9447 section 7. The zero
	// value leaves the validity to the order and the issuer.
	Expires time.Time
	// Further names the certificate may carry on this proof, such as the sans of a 3GPP NF
	// Certificate Authority Token. Each is a normalized dns, ip or uri identifier.
	Names []Identifier
	// The RFC 9310 network function type the proof attests, empty when it attests none.
	NFType string
}

// Checks a challenge response. A nil result marks the challenge valid, a returned *Problem
// marks it invalid and any other error is retried until the attempt limit.
type Validator interface {
	Validate(ctx context.Context, req ValidationRequest) error
}

// Reports what a response authorizes in addition to checking it. A validator that only proves
// control of an identifier implements Validator alone, and the server then grants nothing.
type GrantingValidator interface {
	Validator
	ValidateGrant(ctx context.Context, req ValidationRequest) (ValidationGrant, error)
}

// Supplies the MAC keys that verify external account bindings, see RFC 8555 section 7.3.4.
type ExternalAccountKeys interface {
	// Returns the MAC key for the key identifier or ErrNotFound.
	MACKey(ctx context.Context, keyID string) ([]byte, error)
}

// Reviews requests before the server stores their result. A returned *Problem is sent to the
// client, any other error is reported as serverInternal. Nil methods are not allowed, embed
// AllowAll to accept everything.
type Policy interface {
	// Reviews a new account. The key, contacts and external account identity are set.
	NewAccount(ctx context.Context, account *Account) error
	// Reviews a new order after identifier normalization. The policy may change NotBefore and
	// NotAfter. Any other change, or a NotAfter no later than NotBefore, fails the request with
	// serverInternal.
	NewOrder(ctx context.Context, account *Account, order *Order) error
}

// An optional extension of Policy that authorizes identifiers without a challenge, for example
// names an administrator approved in advance for an external account binding. Their
// authorizations start valid with no challenges and expire with the order. An order whose
// identifiers are all pre-approved starts ready.
type PreApprover interface {
	// Returns the identifiers of a new order that need no challenge. It runs after NewOrder has
	// accepted the order, which it must not change. Each returned identifier must be one of
	// order.Identifiers, wildcard names included. A returned *Problem refuses the order and any
	// other error, or an identifier the order does not contain, is reported as serverInternal.
	PreApprove(ctx context.Context, account *Account, order *Order) ([]Identifier, error)
}

// A Policy that accepts every request.
type AllowAll struct{}

// Accepts the account.
func (AllowAll) NewAccount(context.Context, *Account) error { return nil }

// Accepts the order.
func (AllowAll) NewOrder(context.Context, *Account, *Order) error { return nil }
