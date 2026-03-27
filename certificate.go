package acmeserver

import (
	"encoding/pem"
	"net/http"
)

// Returns the certificate chain as PEM, see RFC 8555 section 7.4.2 and erratum 5983.
func (s *Server) serveCertificate(w http.ResponseWriter, r *http.Request, id string) {
	ctx := r.Context()
	req, p := s.readSignedRequest(r, certPathPrefix+id, keyModeAccount)
	if p != nil {
		s.writeProblem(ctx, w, p)
		return
	}
	cert, err := s.store.Certificate(ctx, id)
	if err != nil {
		s.writeProblem(ctx, w, s.storeProblem(ctx, err, "certificate"))
		return
	}
	if cert.AccountID != req.Account.ID {
		s.writeProblem(ctx, w, NewProblem(ErrorUnauthorized, "the signing account does not own this certificate"))
		return
	}
	if p := requireEmptyPayload(req); p != nil {
		s.writeProblem(ctx, w, p)
		return
	}
	s.setCommonHeaders(w)
	s.addNonce(ctx, w)
	w.Header().Set("Content-Type", contentTypePEMChain)
	w.WriteHeader(http.StatusOK)
	// PEM text under a non-HTML media type is not an injection vector.
	if _, err := w.Write(pemChain(cert.Chain)); err != nil { //nolint:gosec // see above
		s.logError(ctx, "certificate response failed", err)
	}
}

// Encodes DER certificates as a PEM chain with one newline after each block.
func pemChain(chain [][]byte) []byte {
	out := make([]byte, 0, len(chain)*2048)
	for _, der := range chain {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return out
}
