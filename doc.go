// Package acmeserver provides the ACME protocol layer for embedding an ACME server into CA and PKI
// applications. Certificate issuance, persistence and policy decisions are supplied by the host
// application through interfaces, so the package depends on no particular CA, database or deployment.
//
// # Embedding
//
// New validates a Config and returns a Server that implements http.Handler. Mount it at the path
// of Config.BaseURL behind the HTTPS origin that URL names, because signed request URLs must match
// it exactly. Run processes the persisted validation and issuance work and must run in this or
// another process on the same Store, otherwise challenges are never validated and orders are never
// issued. Ready reports work that has waited too long for a worker. The package example shows a
// complete host.
//
// # Host interfaces
//
// A Store persists accounts, orders, authorizations, challenges, certificates and background
// tasks. Its operations are atomic and guarded by resource revisions and task fences, which is
// what lets several workers share one store. The memstore package is the in-memory implementation
// for tests and examples and the storetest package checks a host adapter against the contract.
//
// An Issuer signs certificates and a Revoker revokes them. Both receive a durable OperationID
// that is stored before the first call and repeated on every retry, so the host CA deduplicates.
// An Issuer must enforce IssueRequest.Deadline and RecoveryOnly. A chain that fails publication
// checks is kept in Order.UnpublishedResult for host reconciliation.
//
// A Validator checks one challenge type. The challenge package implements HTTP-01, DNS-01,
// TLS-ALPN-01 and tkauth-01. A GrantingValidator reports what a proof authorizes beyond control
// of the identifier, which tkauth-01 uses for CA certificates and validity bounds.
//
// Policy reviews new accounts and orders, IssuancePolicy reviews the first issuance dispatch and
// ExternalAccountKeys verifies external account bindings.
//
// # Extensions
//
// RFC 8738 IP identifiers, RFC 9448 TNAuthList identifiers with the RFC 9447 tkauth-01 challenge
// and RFC 9773 renewal information are off until the matching Config field enables them.
package acmeserver
