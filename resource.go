package acmeserver

import (
	"crypto"
	"time"
)

// Names a challenge mechanism registered with IANA.
type ChallengeType string

// Challenge types from RFC 8555 section 8 and RFC 8737.
const (
	ChallengeHTTP01    ChallengeType = "http-01"
	ChallengeDNS01     ChallengeType = "dns-01"
	ChallengeTLSALPN01 ChallengeType = "tls-alpn-01"
)

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
	// The selected certificate profile when the host enables that extension.
	Profile string
	// The RFC 9773 identifier of the certificate this order renews.
	Replaces  string
	CreatedAt time.Time
	Revision  uint64
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
	RevocationRequestedAt time.Time
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
}
