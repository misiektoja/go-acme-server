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
	CreatedAt         time.Time
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
	// The selected certificate profile when the host enables that extension.
	Profile string
	// The RFC 9773 identifier of the certificate this order renews.
	Replaces  string
	CreatedAt time.Time
	Revision  uint64
}

// A stored authorization resource.
type Authorization struct {
	ID         string
	AccountID  string
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
	// Holds the DER leaf certificate followed by the DER issuer chain the client receives.
	Chain     [][]byte
	NotBefore time.Time
	NotAfter  time.Time
	Revoked   bool
	RevokedAt time.Time
	// The CRL reason code recorded at revocation.
	RevocationReason int
	CreatedAt        time.Time
	Revision         uint64
}
