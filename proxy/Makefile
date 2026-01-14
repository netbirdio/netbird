.PHONY: build clean run test help version proto

# Build variables
BINARY_NAME=proxy
BUILD_DIR=bin

# Version variables (can be overridden)
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE ?= $(shell date -u '+%Y-%m-%d_%H:%M:%S')

# Go linker flags for version injection
LDFLAGS=-ldflags "-X github.com/netbirdio/netbird/proxy/pkg/version.Version=$(VERSION) \
	-X github.com/netbirdio/netbird/proxy/pkg/version.Commit=$(COMMIT) \
	-X github.com/netbirdio/netbird/proxy/pkg/version.BuildDate=$(BUILD_DATE)"

# Build the binary
build:
	@echo "Building $(BINARY_NAME)..."
	@echo "Version: $(VERSION)"
	@echo "Commit: $(COMMIT)"
	@echo "BuildDate: $(BUILD_DATE)"
	@mkdir -p $(BUILD_DIR)
	GOWORK=off go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) .
	@echo "Build complete: $(BUILD_DIR)/$(BINARY_NAME)"

# Show version information
version:
	@echo "Version: $(VERSION)"
	@echo "Commit: $(COMMIT)"
	@echo "BuildDate: $(BUILD_DATE)"

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)
	@go clean
	@echo "Clean complete"

# Run the application (requires NB_PROXY_TARGET_URL to be set)
run: build
	@./$(BUILD_DIR)/$(BINARY_NAME)

# Run tests
test:
	GOWORK=off go test -v ./...

# Install dependencies
deps:
	@echo "Installing dependencies..."
	GOWORK=off go mod download
	GOWORK=off go mod tidy
	@echo "Dependencies installed"

# Format code
fmt:
	@echo "Formatting code..."
	@go fmt ./...
	@echo "Format complete"

# Lint code
lint:
	@echo "Linting code..."
	@golangci-lint run
	@echo "Lint complete"

# Generate protobuf files
proto:
	@echo "Generating protobuf files..."
	@./scripts/generate-proto.sh

# Show help
help:
	@echo "Available targets:"
	@echo "  build   - Build the binary"
	@echo "  clean   - Remove build artifacts"
	@echo "  run     - Build and run the application"
	@echo "  test    - Run tests"
	@echo "  proto   - Generate protobuf files"
	@echo "  deps    - Install dependencies"
	@echo "  fmt     - Format code"
	@echo "  lint    - Lint code"
	@echo "  help    - Show this help message"