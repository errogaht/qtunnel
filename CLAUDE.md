# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

QTunnel is a secure HTTP tunneling solution built in Go that allows exposing local development servers to the internet through encrypted WebSocket tunnels with automatically generated random subdomains and HTTPS certificates.

## Architecture

The project consists of two main components:

### Server (`server/main.go`)
- WebSocket server that manages tunnel connections from clients
- HTTP proxy server that routes incoming requests to appropriate tunnels
- Tunnel management with automatic cleanup of stale connections
- Traefik integration for dynamic HTTPS certificate generation
- Thread-safe tunnel registry with mutex-protected operations

### Client (`client/main.go`)
- WebSocket client that connects to the server
- HTTP request/response proxying to local development servers
- Automatic reconnection with exponential backoff
- Command-line argument and environment variable configuration
- Ping/pong keepalive mechanism

## Key Communication Flow

1. Client establishes WebSocket connection to server with auth token
2. Server generates random tunnel ID and subdomain (`<id>-tun.domain.com`)
3. Server creates Traefik configuration for HTTPS routing
4. Incoming HTTP requests are converted to WebSocket messages
5. Client receives requests, forwards to local server, returns responses
6. Server proxies responses back to original requesters

## Development Commands

### Build Commands
```bash
make build              # Build both server and client
make build-server       # Build server only  
make build-client       # Build client only
make build-all          # Cross-compile for all platforms
```

### Testing and Quality
```bash
make test               # Run tests with race detection
make test-coverage      # Generate coverage report
make fmt                # Format code
make lint               # Lint code (requires golangci-lint)
make security           # Security scan (requires gosec)
```

### Local Development
```bash
make run-server         # Run server with dev config
make run-client         # Run client connecting to localhost
make dev-setup          # Install development tools
```

### Installation
```bash
make install            # Install client to /usr/local/bin
make uninstall          # Remove client from /usr/local/bin
```

## Configuration

### Server Environment Variables
- `QTUNNEL_AUTH_TOKEN`: Authentication token (default: "default-secret-token")
- `QTUNNEL_DOMAIN`: Base domain for tunnels (default: "localhost")
- `QTUNNEL_LISTEN`: WebSocket server address (default: ":8080")
- `QTUNNEL_PROXY`: HTTP proxy address (default: ":8081")
- `QTUNNEL_TRAEFIK_DIR`: Traefik config directory (default: "/etc/traefik/dynamic")

### Client Configuration
- Command-line flags: `--server`, `--token`
- Environment variables: `QTUNNEL_SERVER`, `QTUNNEL_AUTH_TOKEN`
- Command-line arguments take precedence over environment variables

## Key Implementation Details

### WebSocket Message Types
- `tunnel_created`: Server sends tunnel info to client
- `http_request`: Server forwards HTTP requests to client  
- `http_response`: Client sends HTTP responses back to server
- `ping`/`pong`: Keepalive mechanism

### Security Features
- Bearer token authentication for WebSocket connections
- Request/response isolation per tunnel
- Automatic cleanup of stale tunnels (2-minute timeout)
- Random tunnel IDs to prevent subdomain guessing

### Concurrency Patterns
- `sync.RWMutex` for tunnel registry access
- Goroutines for concurrent request handling
- Channels for request/response correlation
- Background cleanup routines with tickers

## Dependencies

- `github.com/gorilla/websocket` for WebSocket communication
- Go 1.21+ required
- Standard library only (no additional runtime dependencies)