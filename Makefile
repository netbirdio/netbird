.PHONY: lint lint-all lint-install setup-hooks test-unit test-privileged
GOLANGCI_LINT := $(shell pwd)/bin/golangci-lint

# Install golangci-lint locally if needed
$(GOLANGCI_LINT):
	@echo "Installing golangci-lint..."
	@mkdir -p ./bin
	@GOBIN=$(shell pwd)/bin go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest

# Lint only changed files (fast, for pre-push)
lint: $(GOLANGCI_LINT)
	@echo "Running lint on changed files..."
	@$(GOLANGCI_LINT) run --new-from-rev=origin/main --timeout=2m

# Lint entire codebase (slow, matches CI)
lint-all: $(GOLANGCI_LINT)
	@echo "Running lint on all files..."
	@$(GOLANGCI_LINT) run --timeout=12m

# Just install the linter
lint-install: $(GOLANGCI_LINT)

# Setup git hooks for all developers
setup-hooks:
	@git config core.hooksPath .githooks
	@chmod +x .githooks/pre-push
	@echo "✅ Git hooks configured! Pre-push will now run 'make lint'"

# Host-safe unit tests: excludes the privileged-tagged tests (root / system-mutating).
# Runs as a normal user with no sudo and leaves host networking untouched.
test-unit:
	@go test -tags devcert -timeout 10m ./...

# Privileged suite: runs the `privileged`-tagged tests inside a --privileged
# --cap-add=NET_ADMIN container via the ory/dockertest harness. Requires Docker.
# Narrow the run with env vars, e.g.:
#   PRIV_RUN=TestNftablesManager PRIV_PKGS=./client/firewall/nftables/... make test-privileged
test-privileged:
	@go test -tags 'devcert privileged' -timeout 30m -run TestRunPrivilegedSuiteInDocker -v ./client/testutil/privileged/...
