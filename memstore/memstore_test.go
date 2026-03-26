package memstore

import (
	"testing"

	acmeserver "github.com/misiektoja/go-acme-server"
	"github.com/misiektoja/go-acme-server/storetest"
)

func TestStoreContract(t *testing.T) {
	storetest.Run(t, func(t *testing.T) acmeserver.Store { return New() })
}

func TestCreateAccountRequiresIDAndKey(t *testing.T) {
	s := New()
	account := storetest.NewAccount(t, "")
	if err := s.CreateAccount(t.Context(), account); err == nil {
		t.Fatal("CreateAccount without ID succeeded")
	}
	account = storetest.NewAccount(t, "acct-1")
	account.KeyThumbprint = ""
	if err := s.CreateAccount(t.Context(), account); err == nil {
		t.Fatal("CreateAccount without thumbprint succeeded")
	}
}
