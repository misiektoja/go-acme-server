# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

# GO_VERSION is the go directive in go.mod. Every recipe runs with exactly that toolchain, which is the
# one CI installs through go-version-file, so a newer local Go cannot change what the checks see.
# golangci-lint analyses the standard library of the toolchain in use, and a toolchain newer than the
# linter understands makes it crash rather than report a finding.
GO_VERSION := $(shell awk '$$1 == "go" && $$2 ~ /^[0-9]/ { print $$2; exit }' go.mod)
export GOTOOLCHAIN := go$(GO_VERSION)

.PHONY: all
all: test

##@ General

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: fmt
fmt: ## Format the Go sources.
	go fmt ./...

.PHONY: fmt-check
fmt-check: ## Fail when a tracked Go file is not gofmt formatted.
	@files=$$(git ls-files '*.go'); \
	if [ -z "$$files" ]; then echo "no Go files are tracked"; exit 1; fi; \
	unformatted=$$(gofmt -l $$files); \
	if [ -n "$$unformatted" ]; then echo "not gofmt formatted:"; echo "$$unformatted"; exit 1; fi

.PHONY: vet
vet: ## Run go vet.
	go vet ./...

.PHONY: tidy-check
tidy-check: ## Fail when go.mod or go.sum is not tidy.
	go mod tidy -diff
	cd test/interop && go mod tidy -diff

ACME_TEST_SCRATCH ?= $(CURDIR)/.cache/acme-tests
export ACME_TEST_SCRATCH

.PHONY: test-scratch
test-scratch:
	mkdir -p "$(ACME_TEST_SCRATCH)"

.PHONY: test
test: vet test-scratch ## Run the tests under the race detector.
	go test -race -count=1 -coverprofile "$(ACME_TEST_SCRATCH)/root-cover.out" ./...

.PHONY: test-interop
test-interop: test-scratch ## Require acmez, Certbot, durable storage and process recovery tests.
	cd test/interop && go vet ./...
	cd test/interop && go run ./cmd/check

.PHONY: test-recovery
test-recovery: test-scratch ## Exercise two-process fencing and recovery after a killed worker.
	cd test/interop && go test -race -count=1 -timeout=2m -run 'Test(CrashAfterIssuance|TwoProcessLeaseAndFence)$$' ./...

# FUZZ_TIME bounds each target. go test fuzzes one target per invocation, so the targets run in turn.
FUZZ_TIME ?= 20s
FUZZ_TARGETS := ./internal/jws:FuzzParse ./internal/jws:FuzzParseProfiles ./internal/jws:FuzzParseJWK ./internal/jws:FuzzUnmarshalStrict \
	.:FuzzIdentifierNormalize ./challenge:FuzzDNSResponse ./challenge:FuzzALPNProof

.PHONY: fuzz
fuzz: ## Fuzz every parsing target for FUZZ_TIME each. Failing inputs are saved under testdata.
	@for target in $(FUZZ_TARGETS); do \
		pkg="$${target%%:*}"; name="$${target##*:}"; \
		go test -list "^$$name$$" "$$pkg" | grep -x "$$name" >/dev/null || { echo "fuzz target $$name is missing from $$pkg"; exit 1; }; \
		echo "fuzzing $$name in $$pkg for $(FUZZ_TIME)"; \
		go test -run "^$$" -fuzz "^$$name$$" -fuzztime "$(FUZZ_TIME)" "$$pkg"; \
	done

##@ Checks

.PHONY: lint
lint: golangci-lint ## Run golangci-lint.
	"$(GOLANGCI_LINT)" run
	cd test/interop && "$(GOLANGCI_LINT)" run

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint and apply the fixes it offers.
	"$(GOLANGCI_LINT)" run --fix

.PHONY: lint-config
lint-config: golangci-lint ## Verify the golangci-lint configuration.
	"$(GOLANGCI_LINT)" config verify

.PHONY: actionlint
actionlint: actionlint-tool ## Lint the GitHub Actions workflows.
	"$(ACTIONLINT)"

.PHONY: govulncheck
govulncheck: govulncheck-tool ## Report known vulnerabilities that reach the module or its dependencies.
	"$(GOVULNCHECK)" ./...
	cd test/interop && "$(GOVULNCHECK)" -test ./...

# GITLEAKS_LOG_OPTS selects the history the commit scan walks.
GITLEAKS_LOG_OPTS ?= --full-history --all

.PHONY: gitleaks
gitleaks: gitleaks-tool ## Scan the working tree and the commit history for leaked credentials.
# Excluded artifact paths must not contain tracked files.
	@test -z "$$(git ls-files local .cache)" || { echo "error: tracked files are excluded from the gitleaks scan by .gitleaks.toml"; exit 1; }
	"$(GITLEAKS)" dir . --config .gitleaks.toml --redact --no-banner
	"$(GITLEAKS)" git . --config .gitleaks.toml --redact --no-banner --log-opts="$(GITLEAKS_LOG_OPTS)"

##@ Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p "$(LOCALBIN)"

## Tool Binaries
GOLANGCI_LINT ?= $(LOCALBIN)/golangci-lint
GOVULNCHECK ?= $(LOCALBIN)/govulncheck
GITLEAKS ?= $(LOCALBIN)/gitleaks
ACTIONLINT ?= $(LOCALBIN)/actionlint

## Tool Versions
GOLANGCI_LINT_VERSION ?= v2.11.4
GOVULNCHECK_VERSION ?= v1.1.4
GITLEAKS_VERSION ?= v8.30.1
ACTIONLINT_VERSION ?= v1.7.11

.PHONY: golangci-lint
golangci-lint: | $(LOCALBIN) ## Download golangci-lint locally if necessary.
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/v2/cmd/golangci-lint,$(GOLANGCI_LINT_VERSION))

.PHONY: govulncheck-tool
govulncheck-tool: | $(LOCALBIN) ## Download govulncheck locally if necessary.
	$(call go-install-tool,$(GOVULNCHECK),golang.org/x/vuln/cmd/govulncheck,$(GOVULNCHECK_VERSION))

.PHONY: gitleaks-tool
gitleaks-tool: | $(LOCALBIN) ## Download gitleaks locally if necessary.
	$(call go-install-tool,$(GITLEAKS),github.com/zricethezav/gitleaks/v8,$(GITLEAKS_VERSION))

.PHONY: actionlint-tool
actionlint-tool: | $(LOCALBIN) ## Download actionlint locally if necessary.
	$(call go-install-tool,$(ACTIONLINT),github.com/rhysd/actionlint/cmd/actionlint,$(ACTIONLINT_VERSION))

# go-install-tool installs a package at a pinned version under a versioned directory and points the
# unversioned tool path at it, so a version bump installs the new tool instead of keeping the old one.
# $1 - tool path, $2 - package path, $3 - version
define go-install-tool
@dir="$(LOCALBIN)/.tools/$(notdir $(1))@$(3)"; \
if [ ! -x "$$dir/$(notdir $(1))" ]; then \
	echo "Downloading $(2)@$(3)"; \
	mkdir -p "$$dir"; \
	GOBIN="$$dir" go install "$(2)@$(3)"; \
fi; \
ln -sfn "$$dir/$(notdir $(1))" "$(1)"
endef
