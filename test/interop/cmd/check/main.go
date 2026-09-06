// Runs the required interoperability suite and emits only allowlisted result metadata.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"time"
)

// Records test outcomes without client payloads, certificates or private keys.
type event struct {
	Action  string
	Package string
	Test    string  `json:",omitempty"`
	Elapsed float64 `json:",omitempty"`
}

// Names the scenarios whose absence or skip must fail the pull-request gate.
var required = map[string]string{
	"github.com/misiektoja/go-acme-server/test/interop/TestAcmezHTTP01":                         "",
	"github.com/misiektoja/go-acme-server/test/interop/TestAcmezRejectsWrongProof":              "",
	"github.com/misiektoja/go-acme-server/test/interop/TestAcmezDNS01Wildcard":                  "",
	"github.com/misiektoja/go-acme-server/test/interop/TestAcmezRejectsWrongDNSProof":           "",
	"github.com/misiektoja/go-acme-server/test/interop/TestAcmezTLSALPN01":                      "",
	"github.com/misiektoja/go-acme-server/test/interop/TestAcmezRejectsWrongALPNProof":          "",
	"github.com/misiektoja/go-acme-server/test/interop/TestGoJoseAccounts":                      "",
	"github.com/misiektoja/go-acme-server/test/interop/TestGoJoseRejectedRequests":              "",
	"github.com/misiektoja/go-acme-server/test/interop/TestLostResponseAccountCreation":         "",
	"github.com/misiektoja/go-acme-server/test/interop/TestLostResponseChallengeAndFinalize":    "",
	"github.com/misiektoja/go-acme-server/test/interop/TestCompetingFinalizations":              "",
	"github.com/misiektoja/go-acme-server/test/interop/TestSimultaneousKeyRollover":             "",
	"github.com/misiektoja/go-acme-server/test/interop/TestConcurrentNonceReuse":                "",
	"github.com/misiektoja/go-acme-server/test/interop/TestConcurrentAuthorizationsAndWorkers":  "",
	"github.com/misiektoja/go-acme-server/test/interop/TestCertbotHTTP01":                       "",
	"github.com/misiektoja/go-acme-server/test/interop/TestCertbotDNS01Wildcard":                "",
	"github.com/misiektoja/go-acme-server/test/interop/TestLegoHTTP01Revocation":                "",
	"github.com/misiektoja/go-acme-server/test/interop/TestLegoDNS01Wildcard":                   "",
	"github.com/misiektoja/go-acme-server/test/interop/TestLegoDelayedIssuance":                 "",
	"github.com/misiektoja/go-acme-server/test/interop/TestLegoTLSALPN01":                       "",
	"github.com/misiektoja/go-acme-server/test/interop/TestAcmezRenewalInfo":                    "",
	"github.com/misiektoja/go-acme-server/test/interop/TestLegoRenewalInfo":                     "",
	"github.com/misiektoja/go-acme-server/test/interop/TestCertbotDelayedIssuance":              "",
	"github.com/misiektoja/go-acme-server/test/interop/TestCryptoACMEAccountAndKeyRevocation":   "",
	"github.com/misiektoja/go-acme-server/test/interop/TestTKAuth01Issuance":                    "",
	"github.com/misiektoja/go-acme-server/test/interop/TestTKAuth01RejectsForeignToken":         "",
	"github.com/misiektoja/go-acme-server/test/interop/TestCrashAfterIssuance":                  "",
	"github.com/misiektoja/go-acme-server/test/interop/sqlitestore/TestStoreContract":           "",
	"github.com/misiektoja/go-acme-server/test/interop/sqlitestore/TestTwoProcessLeaseAndFence": "",
}

// Returns a failing exit status when execution, evidence writing or required coverage fails.
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// Streams normal diagnostics locally and saves a sanitized summary even when tests fail.
func run() error {
	root := os.Getenv("ACME_TEST_SCRATCH")
	if root == "" {
		return fmt.Errorf("ACME_TEST_SCRATCH is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "test", "-race", "-count=1", "-timeout=2m", "-json", "./...")
	output, err := command.StdoutPipe()
	if err != nil {
		return err
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		return err
	}
	scanner := bufio.NewScanner(output)
	scanner.Buffer(make([]byte, 4096), 4<<20)
	var results []event
	for scanner.Scan() {
		var message struct {
			event
			Output string
		}
		if err := json.Unmarshal(scanner.Bytes(), &message); err != nil {
			continue
		}
		if message.Output != "" {
			fmt.Print(message.Output)
		}
		if message.Action != "pass" && message.Action != "fail" && message.Action != "skip" {
			continue
		}
		results = append(results, message.event)
		key := message.Package + "/" + message.Test
		if _, ok := required[key]; ok {
			required[key] = message.Action
		}
	}
	if scanner.Err() != nil {
		_ = command.Process.Kill()
	}
	runErr := command.Wait()
	report := struct {
		Go, OS, Arch string
		Results      []event
	}{runtime.Version(), runtime.GOOS, runtime.GOARCH, results}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	directory, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	if err := directory.WriteFile("interop-summary.json", append(data, '\n'), 0600); err != nil {
		return err
	}
	if scanner.Err() != nil {
		return scanner.Err()
	}
	if runErr != nil {
		return runErr
	}
	for name, outcome := range required {
		if outcome != "pass" {
			return fmt.Errorf("required scenario %s did not pass: %q", name, outcome)
		}
	}
	return nil
}
