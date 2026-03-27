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
	OrderID     string
	// The parsed certificate request and its DER encoding. The signature and the identifier
	// set were already checked against the order.
	CSR    *x509.CertificateRequest
	CSRDER []byte
	// The normalized identifiers the order covers.
	Identifiers []Identifier
	// The requested validity. Zero values mean the host decides.
	NotBefore time.Time
	NotAfter  time.Time
	// How each identifier was validated.
	Validations []Validation
	// The time after which the order expires. Deferred signing must not complete after it.
	Deadline time.Time
}

// The outcome of an issuance attempt. Exactly one of Chain, Pending and Rejected is set.
type IssueResult struct {
	// The DER leaf certificate followed by the DER issuer chain.
	Chain [][]byte
	// Reports that the CA has not decided yet. The worker asks again after RetryAfter.
	Pending    bool
	RetryAfter time.Duration
	// A final refusal that becomes the order error.
	Rejected *Problem
}

// Issues certificates for finalized orders. Errors report transport or infrastructure failure
// and lead to a retry with the same OperationID.
type Issuer interface {
	Issue(ctx context.Context, req IssueRequest) (IssueResult, error)
}

// What the host CA receives for a revocation.
type RevokeRequest struct {
	Certificate *x509.Certificate
	DER         []byte
	// The CRL reason code the client supplied.
	Reason int
	// The account that requested the revocation. Empty when the certificate key signed the request.
	AccountID string
}

// Revokes certificates. Revoke returns nil only after the CA recorded the revocation durably.
// A returned *Problem is sent to the client, any other error is reported as serverInternal.
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
}

// Checks a challenge response. A nil result marks the challenge valid, a returned *Problem
// marks it invalid and any other error is retried until the attempt limit.
type Validator interface {
	Validate(ctx context.Context, req ValidationRequest) error
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
	// NotAfter but not the identifiers.
	NewOrder(ctx context.Context, account *Account, order *Order) error
}

// A Policy that accepts every request.
type AllowAll struct{}

// Accepts the account.
func (AllowAll) NewAccount(context.Context, *Account) error { return nil }

// Accepts the order.
func (AllowAll) NewOrder(context.Context, *Account, *Order) error { return nil }
