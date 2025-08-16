# QTunnel - Secure HTTP Tunneling Solution

QTunnel is a fast, secure, and easy-to-use HTTP tunneling solution built in Go. It allows you to expose your local development servers to the internet through encrypted tunnels with automatically generated random subdomains and HTTPS certificates.

## Features

- 🚀 **Fast**: Built in Go with efficient WebSocket communication
- 🔒 **Secure**: Encrypted tunnels with authentication tokens
- 🌐 **HTTPS Ready**: Automatic SSL certificates via Traefik integration
- 🎲 **Random Domains**: Auto-generated random subdomains like `abc123def-tun.yourdomain.com`
- 📦 **Easy Setup**: Simple server deployment and single-command client usage
- 🔧 **Self-Hosted**: Complete control over your tunneling infrastructure
- 🛠️ **Flexible**: Command-line arguments and environment variable support

## Quick Start

### Client Usage (Connect to existing QTunnel server)

1. **Download the client:**
```bash
# Using installation script (recommended)
curl -fsSL https://raw.githubusercontent.com/errogaht/qtunnel/main/install.sh | bash

# Or download manually
curl -L https://github.com/errogaht/qtunnel/releases/latest/download/qtunnel-linux-amd64.tar.gz -o qtunnel.tar.gz
tar -xzf qtunnel.tar.gz
chmod +x qtunnel-linux-amd64
sudo mv qtunnel-linux-amd64 /usr/local/bin/qtunnel

# Or build from source
git clone https://github.com/errogaht/qtunnel.git
cd qtunnel
go build -o qtunnel ./client
```

2. **Start tunneling:**
```bash
# Using command line arguments
./qtunnel --server wss://qtunnel.example.com/ws --token your-auth-token 3000

# Or using environment variables
export QTUNNEL_SERVER="wss://qtunnel.example.com/ws"
export QTUNNEL_AUTH_TOKEN="your-auth-token"
./qtunnel 3000

# Output:
# 🎉 Tunnel created!
# 📡 Local port: 3000
# 🌐 Public URL: https://d9566b476362bf8a-tun.example.com
# ⏱️  Tunnel active... (Ctrl+C to stop)
```

That's it! Your local server is now accessible via the generated HTTPS URL.

## Client Options

```bash
Usage: qtunnel [options] <local_port>

Options:
  --server string    QTunnel server WebSocket URL (e.g., wss://qtunnel.example.com/ws)
  --token string     Authentication token for the server
  -h, --help        Show help message
  -v, --version     Show version information

Environment Variables (used as defaults):
  QTUNNEL_SERVER     WebSocket server URL
  QTUNNEL_AUTH_TOKEN Authentication token

Examples:
  qtunnel 3000
  qtunnel --server wss://tunnel.example.com/ws --token abc123 8080
  QTUNNEL_SERVER=wss://tunnel.example.com/ws qtunnel 3000
```

## Server Installation

### Prerequisites

- Linux server with Docker installed
- Domain name with DNS pointing to your server
- Traefik reverse proxy (or similar) for HTTPS termination

### Option 1: Docker Compose (Recommended)

1. **Create docker-compose.yml:**
```yaml
version: '3.8'

services:
  qtunnel-server:
    image: qtunnel-server:latest
    build: .
    container_name: qtunnel-server
    restart: unless-stopped
    environment:
      - QTUNNEL_AUTH_TOKEN=your-secure-random-token-here
      - QTUNNEL_DOMAIN=yourdomain.com
      - QTUNNEL_LISTEN=:8080
      - QTUNNEL_PROXY=:8081
      - QTUNNEL_TRAEFIK_DIR=/traefik-dynamic
    ports:
      - "8092:8080"  # WebSocket port
      - "8093:8081"  # HTTP proxy port
    volumes:
      - ./traefik-dynamic:/traefik-dynamic
    networks:
      - traefik_network
    labels:
      - "traefik.enable=true"
      
      # WebSocket endpoint for clients
      - "traefik.http.routers.qtunnel-ws.rule=Host(`qtunnel.yourdomain.com`)"
      - "traefik.http.routers.qtunnel-ws.tls=true"
      - "traefik.http.routers.qtunnel-ws.tls.certresolver=cloudflare"
      - "traefik.http.routers.qtunnel-ws.service=qtunnel-ws"
      - "traefik.http.services.qtunnel-ws.loadbalancer.server.port=8080"
      
      # Wildcard proxy for tunnels
      - "traefik.http.routers.qtunnel-proxy.rule=HostRegexp(`{subdomain:[a-zA-Z0-9-]+}-tun.yourdomain.com`)"
      - "traefik.http.routers.qtunnel-proxy.tls=true"
      - "traefik.http.routers.qtunnel-proxy.tls.certresolver=cloudflare"
      - "traefik.http.routers.qtunnel-proxy.service=qtunnel-proxy"
      - "traefik.http.services.qtunnel-proxy.loadbalancer.server.port=8081"

networks:
  traefik_network:
    external: true
```

2. **Set up DNS records:**
```
qtunnel.yourdomain.com   A   YOUR_SERVER_IP
*.yourdomain.com         A   YOUR_SERVER_IP  # Wildcard for tunnels
```

3. **Generate auth token:**
```bash
openssl rand -hex 32
```

4. **Deploy:**
```bash
docker-compose up -d
```

### Option 2: Manual Installation

1. **Build the server:**
```bash
git clone https://github.com/errogaht/qtunnel.git
cd qtunnel
go build -o qtunnel-server ./server
```

2. **Create systemd service:**
```bash
sudo tee /etc/systemd/system/qtunnel.service > /dev/null <<EOF
[Unit]
Description=QTunnel Server
After=network.target

[Service]
Type=simple
User=qtunnel
WorkingDirectory=/opt/qtunnel
ExecStart=/opt/qtunnel/qtunnel-server
Environment=QTUNNEL_AUTH_TOKEN=your-token-here
Environment=QTUNNEL_DOMAIN=yourdomain.com
Environment=QTUNNEL_LISTEN=:8080
Environment=QTUNNEL_PROXY=:8081
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
```

3. **Start service:**
```bash
sudo systemctl daemon-reload
sudo systemctl enable qtunnel
sudo systemctl start qtunnel
```

## Configuration

### Server Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `QTUNNEL_AUTH_TOKEN` | Authentication token for clients | `default-secret-token` |
| `QTUNNEL_DOMAIN` | Base domain for tunnels | `localhost` |
| `QTUNNEL_LISTEN` | WebSocket server listen address | `:8080` |
| `QTUNNEL_PROXY` | HTTP proxy listen address | `:8081` |
| `QTUNNEL_TRAEFIK_DIR` | Directory for Traefik dynamic configs | `/etc/traefik/dynamic` |

### Client Configuration

The client supports both command-line arguments and environment variables:

**Command-line arguments take precedence over environment variables.**

| CLI Flag | Environment Variable | Description |
|----------|---------------------|-------------|
| `--server` | `QTUNNEL_SERVER` | WebSocket server URL |
| `--token` | `QTUNNEL_AUTH_TOKEN` | Authentication token |

## Architecture

```
┌─────────────────┐    WebSocket     ┌─────────────────┐
│                 │ ◄──────────────► │                 │
│  QTunnel Client │                  │ QTunnel Server  │
│                 │                  │                 │
└─────────────────┘                  └─────────────────┘
         │                                     │
         │                                     │
         ▼                                     ▼
┌─────────────────┐                  ┌─────────────────┐
│                 │                  │                 │
│ Local Server    │                  │ Traefik Proxy   │
│ (localhost:3000)│                  │ (HTTPS/SSL)     │
│                 │                  │                 │
└─────────────────┘                  └─────────────────┘
                                               │
                                               ▼
                                    ┌─────────────────┐
                                    │                 │
                                    │ Internet Users  │
                                    │                 │
                                    └─────────────────┘
```

## Security

- All tunnel communication is encrypted via WebSocket Secure (WSS)
- Authentication tokens are required for client connections
- Each tunnel gets a unique, unpredictable subdomain
- Tunnels are automatically cleaned up when clients disconnect
- No data is stored on the server - everything is proxied in real-time

## Building from Source

### Prerequisites
- Go 1.21 or later
- Git

### Build Commands

```bash
# Clone repository
git clone https://github.com/yourusername/qtunnel.git
cd qtunnel

# Build server
go build -o qtunnel-server ./server

# Build client
go build -o qtunnel-client ./client

# Build both with cross-compilation
make build-all
```

### Docker Build

```bash
# Build Docker image
docker build -t qtunnel-server:latest .

# Or using docker-compose
docker-compose build
```

## Installation Script

For easy installation on client machines:

```bash
# Linux/macOS installation script
curl -fsSL https://raw.githubusercontent.com/errogaht/qtunnel/main/install.sh | bash
```

## Examples

### Expose Local Web Server
```bash
# Start your local development server
npm run dev  # Running on localhost:3000

# In another terminal, start tunnel
qtunnel --server wss://qtunnel.example.com/ws --token your-token 3000
# Get: https://abc123def-tun.example.com
```

### Expose API Server
```bash
# Start your API server
python -m http.server 8000

# Tunnel it
qtunnel --server wss://qtunnel.example.com/ws --token your-token 8000
# Share API at: https://xyz789ghi-tun.example.com
```

### Using Environment Variables
```bash
# Set once
export QTUNNEL_SERVER="wss://qtunnel.example.com/ws"
export QTUNNEL_AUTH_TOKEN="your-secure-token"

# Use multiple times
qtunnel 3000   # Web app
qtunnel 8000   # API server
qtunnel 8080   # Another service
```

## Health Check

The server provides a health check endpoint:

```bash
curl https://qtunnel.yourdomain.com/health
# Response: {"status":"healthy","tunnels":2}
```

## Troubleshooting

### Common Issues

**1. Connection Refused**
```bash
# Check if server is running
curl -I https://qtunnel.yourdomain.com

# Check WebSocket endpoint
curl -I https://qtunnel.yourdomain.com/ws
```

**2. Authentication Failed**
```bash
# Verify your auth token matches server configuration
echo $QTUNNEL_AUTH_TOKEN
```

**3. Missing Server/Token Parameters**
```bash
# The client will show helpful error messages:
qtunnel 3000
# Error: You must specify server URL and auth token
# Either use command line arguments:
#   qtunnel --server wss://qtunnel.example.com/ws --token your-token 3000
# Or set environment variables:
#   export QTUNNEL_SERVER="wss://qtunnel.example.com/ws"
#   export QTUNNEL_AUTH_TOKEN="your-token"
#   qtunnel 3000
```

**4. Tunnel Not Accessible**
```bash
# Check DNS wildcard record
nslookup random123-tun.yourdomain.com

# Test direct server connection
curl -I http://your-server-ip:8093
```

**5. Local Server Not Responding**
```bash
# Verify local server is running
curl http://localhost:YOUR_PORT

# Check tunnel logs for errors
qtunnel --server wss://qtunnel.example.com/ws --token your-token YOUR_PORT
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- 📝 [GitHub Issues](https://github.com/errogaht/qtunnel/issues)
- 💬 [Discussions](https://github.com/errogaht/qtunnel/discussions)
- 📖 [Wiki](https://github.com/errogaht/qtunnel/wiki)

## Acknowledgments

- Built with [Gorilla WebSocket](https://github.com/gorilla/websocket)
- Inspired by ngrok and similar tunneling solutions
- Designed for self-hosted infrastructure