package acmeserver

import (
	"crypto"
	"time"
)

// Names a challenge mechanism registered with IANA.
type ChallengeType string

// Challenge types from RFC 8555 section 8, RFC 8737 and RFC 9447.
const (
	ChallengeHTTP01    ChallengeType = "http-01"
	ChallengeDNS01     ChallengeType = "dns-01"
	ChallengeTLSALPN01 ChallengeType = "tls-alpn-01"
	// Answered with an Authority Token instead of a network proof.
	ChallengeTKAuth01 ChallengeType = "tkauth-01"
)

// The only Authority Token subtype this server offers, see RFC 9447 section 4.
const TKAuthTypeATC = "atc"

// A stored ACME account. Its ID is opaque and appears only in the account URL.
type Account struct {
	ID     string
	Status AccountStatus
	// The account key. KeyThumbprint is its RFC 7638 thumbprint, unique among accounts.
	Key                  crypto.PublicKey
	KeyThumbprint        string
	Contact              []string
	TermsOfServiceAgreed bool
	// The identity the host derived from a verified external account binding.
	ExternalAccountID string
	// The single-use claim on that binding, set when Config.SingleUseExternalAccounts is on.
	// Stores keep non-empty claims unique among accounts.
	ExternalAccountClaim string
	CreatedAt            time.Time
	// Increases on every successful update and guards concurrent modification.
	Revision uint64
}

// A stored order resource.
type Order struct {
	ID          string
	AccountID   string
	Status      OrderStatus
	Expires     time.Time
	Identifiers []Identifier
	// The requested validity. Zero values mean unset.
	NotBefore        time.Time
	NotAfter         time.Time
	AuthorizationIDs []string
	// Records why the order became invalid.
	Error *Problem
	// The DER request accepted at finalization. It never changes once set.
	CSR           []byte
	CertificateID string
	// The durable authorization decision made before the first CA call.
	Issuance *IssuanceState
	// A CA result withheld from clients and retained for host reconciliation.
	UnpublishedResult *IssueResult
	// The RFC 9773 identifier of the certificate this order replaces, set when the client sent
	// replaces and Config.RenewalInfo is enabled. Stores mark that certificate replaced by this
	// order when the order is created.
	Replaces  string
	CreatedAt time.Time
	Revision  uint64
}

// Returns the status clients see at now, treating an expired pending or ready order as invalid.
func (o *Order) StatusAt(now time.Time) OrderStatus {
	if (o.Status == OrderPending || o.Status == OrderReady) && !o.Expires.After(now) {
		return OrderInvalid
	}
	return o.Status
}

// A stored authorization resource. Each authorization belongs to exactly one order.
type Authorization struct {
	ID         string
	AccountID  string
	OrderID    string
	Identifier Identifier
	Status     AuthorizationStatus
	Expires    time.Time
	// Marks a wildcard authorization. Identifier then holds the base name.
	Wildcard     bool
	ChallengeIDs []string
	// Records that the successful challenge also authorized a CA certificate for the identifier.
	CACertificate bool
	// The time after which the proof no longer covers a certificate, zero when unbounded.
	GrantExpires time.Time
	CreatedAt    time.Time
	Revision     uint64
}

// A stored challenge resource.
type Challenge struct {
	ID              string
	AuthorizationID string
	AccountID       string
	Type            ChallengeType
	Status          ChallengeStatus
	Token           string
	// The Authority Token a tkauth-01 response carried, see RFC 9448 section 4.
	AuthorityToken string
	// The account key thumbprint captured at response time, so a key rollover
	// does not change an in-flight validation.
	KeyThumbprint string
	Validated     time.Time
	// Records why validation failed.
	Error    *Problem
	Revision uint64
}

// A stored issued certificate together with its chain.
type Certificate struct {
	// The base64url SHA-256 digest of the DER leaf, which names the certificate resource.
	ID        string
	AccountID string
	OrderID   string
	// The opaque reference returned by the host CA.
	CAReference string
	// Holds the DER leaf certificate followed by the DER issuer chain the client receives.
	Chain     [][]byte
	NotBefore time.Time
	NotAfter  time.Time
	Revoked   bool
	RevokedAt time.Time
	// The CRL reason code recorded at revocation.
	RevocationReason int
	// Identifies the revocation the host CA receives. It is committed with the reason before the
	// first CA call and reused by every retry, so the CA can deduplicate.
	RevocationOperationID string
	// When the revocation was recorded, before the CA call. RevokedAt is set after the CA succeeded.
	RevocationRequestedAt time.Time
	// The RFC 9773 identifier built from the leaf's authority key identifier and serial number.
	// It is empty when the leaf has no authority key identifier. Stores keep non-empty values
	// unique among certificates.
	RenewalID string
	// The order that claimed this certificate as its predecessor through replaces.
	ReplacedByOrderID string
	// The validation evidence the issuer received, kept for host audit needs.
	Validations []Validation
	CreatedAt   time.Time
	Revision    uint64
}

// Preserves the authorization deadline and evidence across uncertain issuance attempts.
type IssuanceState struct {
	OperationID  string
	AuthorizedAt time.Time
	Deadline     time.Time
	Validations  []Validation
}

// Records how one identifier of an order was validated.
type Validation struct {
	Identifier Identifier
	Type       ChallengeType
	Validated  time.Time
	// Reports that the validation authorized a CA certificate rather than an end-entity one.
	CACertificate bool
	// The latest acceptable certificate expiry under this proof, zero when unbounded.
	GrantExpires time.Time
}
