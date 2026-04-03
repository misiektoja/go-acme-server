// Package testutil provides isolated artifact directories for interoperability evidence.
package testutil

import (
	"os"
	"testing"
)

// Creates a retained test directory below the explicitly configured scratch root.
func Scratch(t *testing.T) string {
	t.Helper()
	root := os.Getenv("ACME_TEST_SCRATCH")
	if root == "" {
		t.Fatal("ACME_TEST_SCRATCH must name an existing scratch directory")
	}
	directory, err := os.MkdirTemp(root, "acme-")
	if err != nil {
		t.Fatal(err)
	}
	return directory
}
