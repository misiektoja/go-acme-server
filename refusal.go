package acmeserver

import (
	"context"
	"slices"
	"strconv"
	"strings"
)

// Names the request a Refusal answered.
type RefusalKind string

// The requests whose refusals reach a RefusalRecorder.
const (
	// A finalize request whose CSR or order state the server refused.
	RefusalFinalize RefusalKind = "finalize"
	// A revokeCert request the server or the Revoker refused.
	RefusalRevocation RefusalKind = "revocation"
)

// Describes an authenticated finalize or revokeCert request that was answered with a problem. The
// server refuses these requests itself, so without a recorder the host never learns about them.
type Refusal struct {
	Kind RefusalKind
	// The requesting account. It is empty for a revocation signed with the certificate key.
	AccountID string
	// The order a finalize request was for and the identifiers it covers.
	OrderID     string
	Identifiers []Identifier
	// The DER certificate request of a finalize request, when it was valid base64url.
	CSR []byte
	// The DER certificate of a revocation request, when it was valid base64url, and the reason
	// code it asked for.
	Certificate []byte
	Reason      int
	// The answer the client receives. The recorder must not change it.
	Problem *Problem
}

// Learns about refused finalize and revokeCert requests, for example to keep an audit trail of
// why a client got no certificate. Requests that fail authentication and server faults are not
// reported. RecordRefusal runs before the answer is sent, detached from the client request so a
// disconnect does not cancel it. A returned error is logged and does not change the answer.
type RefusalRecorder interface {
	RecordRefusal(ctx context.Context, refusal Refusal) error
}

// Tells the RefusalRecorder about a refused request. A serverInternal problem is left to the log,
// because it describes the server rather than the request.
func (s *Server) recordRefusal(parent context.Context, refusal Refusal, p *Problem) {
	if s.refusals == nil || p.Type == ErrorServerInternal {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), s.detachedWrite)
	defer cancel()
	refusal.Problem = p
	if err := s.refusals.RecordRefusal(ctx, refusal); err != nil {
		s.logError(ctx, "refusal could not be recorded", err)
	}
}

// The reason codes clients may request when Config.RevocationReasons is empty, see RFC 5280
// section 5.3.1.
var defaultRevocationReasons = []int{0, 1, 3, 4, 5}

// The RFC 5280 names of the reason codes a server may allow. certificateHold (6) is missing
// because an ACME revocation is final. Code 7 is unassigned and removeFromCRL (8) only appears in
// delta CRLs.
var revocationReasonNames = map[int]string{
	0:  "unspecified",
	1:  "keyCompromise",
	2:  "cACompromise",
	3:  "affiliationChanged",
	4:  "superseded",
	5:  "cessationOfOperation",
	9:  "privilegeWithdrawn",
	10: "aACompromise",
}

// Checks the configured reason codes.
func validateRevocationReasons(reasons []int) error {
	for _, reason := range reasons {
		if _, ok := revocationReasonNames[reason]; !ok {
			return errorf("Config.RevocationReasons has " + strconv.Itoa(reason) + ". Only 0 to 5, 9 and 10 " +
				"are allowed, because an ACME revocation is final")
		}
	}
	return nil
}

// Returns the allowed reason codes in ascending order without repeats, the defaults when none are
// configured.
func revocationReasons(configured []int) []int {
	if len(configured) == 0 {
		return defaultRevocationReasons
	}
	reasons := slices.Clone(configured)
	slices.Sort(reasons)
	return slices.Compact(reasons)
}

// Lists the allowed reason codes by name for the badRevocationReason detail, so a client operator
// can pick one that works.
func revocationReasonsText(reasons []int) string {
	names := make([]string, len(reasons))
	for i, reason := range reasons {
		names[i] = revocationReasonNames[reason] + " (" + strconv.Itoa(reason) + ")"
	}
	if len(names) == 1 {
		return "The allowed reason is " + names[0]
	}
	return "The allowed reasons are " + strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}
