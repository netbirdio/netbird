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
	@chmod +x .githooks/pre-push .githooks/pre-commit
	@echo "Git hooks configured:"
	@echo "  - pre-commit: gofmt check, secrets detection"
	@echo "  - pre-push: make lint"

# ==========================================
# Machine Tunnel Fork - Build Targets
# ==========================================

.PHONY: build-windows build-windows-nocgo build-linux build-all clean

# Output directory
DIST_DIR := dist

# Version from git tag or default
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -X main.version=$(VERSION)

# Windows Cross-Compile with CGO (required for CNG Cert Store)
# Requires: mingw-w64 (dnf install mingw64-gcc / apt install gcc-mingw-w64-x86-64)
build-windows:
	@echo "Building Windows binary (with CGO for CNG support)..."
	@mkdir -p $(DIST_DIR)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc \
		go build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/netbird-machine.exe ./client/cmd/

# Windows Cross-Compile without CGO (faster, but no CNG support)
build-windows-nocgo:
	@echo "Building Windows binary (no CGO - faster but limited)..."
	@mkdir -p $(DIST_DIR)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
		go build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/netbird-machine-nocgo.exe ./client/cmd/

# Linux Build
build-linux:
	@echo "Building Linux binary..."
	@mkdir -p $(DIST_DIR)
	go build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/netbird-machine ./client/cmd/

# Build all platforms
build-all: build-linux build-windows-nocgo
	@echo "Built all platforms in $(DIST_DIR)/"

# Clean build artifacts
clean:
	@rm -rf $(DIST_DIR)
	@echo "Cleaned build artifacts"

# Quick test build (no CGO, fast feedback)
build-quick: build-windows-nocgo
	@echo "Quick build complete: $(DIST_DIR)/netbird-machine-nocgo.exe"
