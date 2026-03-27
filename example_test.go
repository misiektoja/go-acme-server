package acmeserver_test

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"

	acmeserver "github.com/misiektoja/go-acme-server"
	"github.com/misiektoja/go-acme-server/memstore"
	"github.com/misiektoja/go-acme-server/nonce"
)

// A placeholder for the host CA. Real hosts sign with their own CA and deduplicate by OperationID.
type exampleCA struct{}

// Refuses every request in this example.
func (exampleCA) Issue(context.Context, acmeserver.IssueRequest) (acmeserver.IssueResult, error) {
	return acmeserver.IssueResult{Rejected: acmeserver.NewProblem(acmeserver.ErrorServerInternal, "not implemented")}, nil
}

// Refuses every request in this example.
func (exampleCA) Revoke(context.Context, acmeserver.RevokeRequest) error {
	return errors.New("not implemented")
}

// A placeholder for a challenge validator. Validators for the standard challenge types are a
// separate concern of the host or a later package.
type exampleValidator struct{}

// Refuses every challenge in this example.
func (exampleValidator) Validate(context.Context, acmeserver.ValidationRequest) error {
	return acmeserver.NewProblem(acmeserver.ErrorIncorrectResponse, "not implemented")
}

// Shows how a host mounts the handler and runs the worker. Both are required.
func Example() {
	srv, err := acmeserver.New(acmeserver.Config{
		BaseURL: "https://ca.example.com/acme/",
		Store:   memstore.New(),
		Nonces:  nonce.New(nonce.Options{}),
		Issuer:  exampleCA{},
		Revoker: exampleCA{},
		Validators: map[acmeserver.ChallengeType]acmeserver.Validator{
			acmeserver.ChallengeHTTP01: exampleValidator{},
		},
		Meta: acmeserver.DirectoryMeta{Website: "https://ca.example.com"},
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	go func() {
		if err := srv.Run(ctx); err != nil {
			log.Print(err)
		}
	}()
	mux := http.NewServeMux()
	mux.Handle("/acme/", srv)
	// http.ListenAndServeTLS(":443", "cert.pem", "key.pem", mux) would serve the directory at
	// https://ca.example.com/acme/directory.
	_ = mux
	// Output:
}
