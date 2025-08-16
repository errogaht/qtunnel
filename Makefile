# QTunnel Makefile

# Version
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT_HASH ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME ?= $(shell date -u '+%Y-%m-%d_%H:%M:%S')

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Build flags
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -X main.CommitHash=$(COMMIT_HASH) -X main.BuildTime=$(BUILD_TIME) -w -s"

# Binary names
SERVER_BINARY=qtunnel-server
CLIENT_BINARY=qtunnel-client
CLIENT_SIMPLE=qtunnel

# Build directory
BUILD_DIR=build

# Platforms for cross-compilation
PLATFORMS=linux/amd64 linux/arm64 linux/arm darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

.PHONY: all build clean test deps docker-build docker-run help

# Default target
all: clean deps test build

# Build both server and client
build: build-server build-client

# Build server
build-server:
	@echo "Building server..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(SERVER_BINARY) ./server

# Build client
build-client:
	@echo "Building client..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(CLIENT_SIMPLE) ./client

# Build for all platforms
build-all: clean deps
	@echo "Building for all platforms..."
	@mkdir -p $(BUILD_DIR)
	@for platform in $(PLATFORMS); do \
		os=$$(echo $$platform | cut -d'/' -f1); \
		arch=$$(echo $$platform | cut -d'/' -f2); \
		echo "Building for $$os/$$arch..."; \
		if [ "$$os" = "windows" ]; then \
			CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(CLIENT_SIMPLE)-$$os-$$arch.exe ./client; \
			CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(SERVER_BINARY)-$$os-$$arch.exe ./server; \
		else \
			CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(CLIENT_SIMPLE)-$$os-$$arch ./client; \
			CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(SERVER_BINARY)-$$os-$$arch ./server; \
		fi; \
	done

# Install client locally
install: build-client
	@echo "Installing client to /usr/local/bin..."
	sudo cp $(BUILD_DIR)/$(CLIENT_SIMPLE) /usr/local/bin/$(CLIENT_SIMPLE)
	sudo chmod +x /usr/local/bin/$(CLIENT_SIMPLE)
	@echo "✓ QTunnel client installed successfully!"

# Uninstall client
uninstall:
	@echo "Removing client from /usr/local/bin..."
	sudo rm -f /usr/local/bin/$(CLIENT_SIMPLE)
	@echo "✓ QTunnel client uninstalled successfully!"

# Download dependencies
deps:
	@echo "Downloading dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy

# Run tests
test:
	@echo "Running tests..."
	$(GOTEST) -v -race -timeout 30s ./...

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	$(GOTEST) -v -race -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Clean build artifacts
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html

# Run server locally
run-server: build-server
	@echo "Starting server..."
	QTUNNEL_AUTH_TOKEN=dev-token QTUNNEL_DOMAIN=localhost ./$(BUILD_DIR)/$(SERVER_BINARY)

# Run client locally (requires server to be running)
run-client: build-client
	@echo "Starting client on port 8080..."
	./$(BUILD_DIR)/$(CLIENT_SIMPLE) --server ws://localhost:8080/ws --token dev-token 8080

# Docker build
docker-build:
	@echo "Building Docker image..."
	docker build -t qtunnel-server:$(VERSION) .
	docker tag qtunnel-server:$(VERSION) qtunnel-server:latest

# Docker run
docker-run: docker-build
	@echo "Running Docker container..."
	docker run --rm -p 8080:8080 -p 8081:8081 \
		-e QTUNNEL_AUTH_TOKEN=dev-token \
		-e QTUNNEL_DOMAIN=localhost \
		qtunnel-server:latest

# Create release archives
release: build-all
	@echo "Creating release archives..."
	@mkdir -p $(BUILD_DIR)/releases
	@for platform in $(PLATFORMS); do \
		os=$$(echo $$platform | cut -d'/' -f1); \
		arch=$$(echo $$platform | cut -d'/' -f2); \
		if [ "$$os" = "windows" ]; then \
			zip -j $(BUILD_DIR)/releases/qtunnel-$$os-$$arch.zip $(BUILD_DIR)/$(CLIENT_SIMPLE)-$$os-$$arch.exe $(BUILD_DIR)/$(SERVER_BINARY)-$$os-$$arch.exe; \
		else \
			tar -czf $(BUILD_DIR)/releases/qtunnel-$$os-$$arch.tar.gz -C $(BUILD_DIR) $(CLIENT_SIMPLE)-$$os-$$arch $(SERVER_BINARY)-$$os-$$arch; \
		fi; \
	done
	@echo "✓ Release archives created in $(BUILD_DIR)/releases/"

# Format code
fmt:
	@echo "Formatting code..."
	$(GOCMD) fmt ./...

# Lint code (requires golangci-lint)
lint:
	@echo "Linting code..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed. Install with: curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b \$$(go env GOPATH)/bin v1.54.2"; \
	fi

# Security scan (requires gosec)
security:
	@echo "Running security scan..."
	@if command -v gosec >/dev/null 2>&1; then \
		gosec ./...; \
	else \
		echo "gosec not installed. Install with: go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest"; \
	fi

# Development setup
dev-setup:
	@echo "Setting up development environment..."
	$(GOGET) -u github.com/golangci/golangci-lint/cmd/golangci-lint
	$(GOGET) -u github.com/securecodewarrior/gosec/v2/cmd/gosec
	@echo "✓ Development tools installed"

# Generate version info
version:
	@echo "Version: $(VERSION)"
	@echo "Commit: $(COMMIT_HASH)"
	@echo "Build Time: $(BUILD_TIME)"

# Show help
help:
	@echo "QTunnel Makefile Commands:"
	@echo ""
	@echo "Building:"
	@echo "  make build          - Build both server and client"
	@echo "  make build-server   - Build server only"
	@echo "  make build-client   - Build client only"
	@echo "  make build-all      - Build for all platforms"
	@echo ""
	@echo "Installation:"
	@echo "  make install        - Install client to /usr/local/bin"
	@echo "  make uninstall      - Remove client from /usr/local/bin"
	@echo ""
	@echo "Development:"
	@echo "  make deps           - Download dependencies"
	@echo "  make test           - Run tests"
	@echo "  make test-coverage  - Run tests with coverage"
	@echo "  make run-server     - Run server locally"
	@echo "  make run-client     - Run client locally"
	@echo "  make fmt            - Format code"
	@echo "  make lint           - Lint code"
	@echo "  make security       - Security scan"
	@echo "  make dev-setup      - Install development tools"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-build   - Build Docker image"
	@echo "  make docker-run     - Run Docker container"
	@echo ""
	@echo "Release:"
	@echo "  make release        - Create release archives"
	@echo "  make version        - Show version info"
	@echo ""
	@echo "Maintenance:"
	@echo "  make clean          - Clean build artifacts"
	@echo "  make help           - Show this help"