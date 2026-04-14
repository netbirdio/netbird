.PHONY: lint lint-all lint-install setup-hooks
GOLANGCI_LINT := $(shell pwd)/bin/golangci-lint

# Install golangci-lint locally if needed
$(GOLANGCI_LINT):
	@echo "Installing golangci-lint..."
	@mkdir -p ./bin
	@GOBIN=$(shell pwd)/bin go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

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

MANAGEMENT_DEV_IMAGE ?= netbird/management:tpm-dev

# Build management Docker image from source for local testing with netbird-stand.
# Uses management/Dockerfile.multistage which does a full Go build.
.PHONY: docker-management-dev
docker-management-dev:
	@echo "Building $(MANAGEMENT_DEV_IMAGE) from feature/tpm-cert-auth..."
	docker build -f management/Dockerfile.multistage -t $(MANAGEMENT_DEV_IMAGE) .
	@echo ""
	@echo "Image ready: $(MANAGEMENT_DEV_IMAGE)"
	@echo "Next: cd /path/to/netbird-stand && bash scripts/up-device-auth.sh"
