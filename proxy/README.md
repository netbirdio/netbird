# Netbird Reverse Proxy

A lightweight, configurable reverse proxy server with graceful shutdown support.

## Features

- Simple reverse proxy with customizable headers
- Configuration via environment variables or JSON file
- Graceful shutdown with configurable timeout
- Structured logging with logrus
- Configurable timeouts (read, write, idle)
- Health monitoring support

## Building

```bash
# Build the binary
GOWORK=off go build -o bin/proxy ./cmd/proxy

# Or use make if available
make build
```

## Configuration

The proxy can be configured using either environment variables or a JSON configuration file. Environment variables take precedence over file-based configuration.

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NB_PROXY_LISTEN_ADDRESS` | Address to listen on | `:8080` |
| `NB_PROXY_TARGET_URL` | Target URL to proxy requests to | **(required)** |
| `NB_PROXY_READ_TIMEOUT` | Read timeout duration | `30s` |
| `NB_PROXY_WRITE_TIMEOUT` | Write timeout duration | `30s` |
| `NB_PROXY_IDLE_TIMEOUT` | Idle timeout duration | `60s` |
| `NB_PROXY_SHUTDOWN_TIMEOUT` | Graceful shutdown timeout | `10s` |
| `NB_PROXY_LOG_LEVEL` | Log level (debug, info, warn, error) | `info` |

### Configuration File

Create a JSON configuration file:

```json
{
  "listen_address": ":8080",
  "target_url": "http://localhost:3000",
  "read_timeout": "30s",
  "write_timeout": "30s",
  "idle_timeout": "60s",
  "shutdown_timeout": "10s",
  "log_level": "info"
}
```

## Usage

### Using Environment Variables

```bash
export NB_PROXY_TARGET_URL=http://localhost:3000
export NB_PROXY_LOG_LEVEL=debug
./bin/proxy
```

### Using Configuration File

```bash
./bin/proxy -config config.json
```

### Combining Both

Environment variables override file configuration:

```bash
export NB_PROXY_LOG_LEVEL=debug
./bin/proxy -config config.json
```

### Docker Example

```bash
docker run -e NB_PROXY_TARGET_URL=http://backend:3000 \
           -e NB_PROXY_LISTEN_ADDRESS=:8080 \
           -p 8080:8080 \
           netbird-proxy
```

## Architecture

The application follows a clean architecture with clear separation of concerns:

```
proxy/
├── cmd/
│   └── proxy/
│       └── main.go          # Entry point, CLI handling, signal management
├── config.go                # Configuration loading and validation
├── server.go                # Server lifecycle (Start/Stop)
├── go.mod                   # Module dependencies
└── README.md
```

### Key Components

- **config.go**: Handles configuration loading from environment variables and files using the `github.com/caarlos0/env/v11` library
- **server.go**: Encapsulates the HTTP server and reverse proxy logic with proper lifecycle management
- **cmd/proxy/main.go**: Entry point that orchestrates startup, graceful shutdown, and signal handling

## Graceful Shutdown

The server handles SIGINT and SIGTERM signals for graceful shutdown:

1. Signal received (Ctrl+C or kill command)
2. Server stops accepting new connections
3. Existing connections are allowed to complete within the shutdown timeout
4. Server exits cleanly

Press `Ctrl+C` to trigger graceful shutdown:

```bash
^C2026-01-13 22:40:00 INFO Received signal: interrupt
2026-01-13 22:40:00 INFO Shutting down server gracefully...
2026-01-13 22:40:00 INFO Server stopped successfully
2026-01-13 22:40:00 INFO Server exited successfully
```

## Headers

The proxy automatically sets the following headers on proxied requests:

- `X-Forwarded-Host`: Original request host
- `X-Origin-Host`: Target backend host
- `X-Real-IP`: Client's remote address

## Error Handling

- Invalid backend connections return `502 Bad Gateway`
- All proxy errors are logged with details
- Configuration errors are reported at startup

## Development

### Prerequisites

- Go 1.25 or higher
- Access to `github.com/sirupsen/logrus`
- Access to `github.com/caarlos0/env/v11`

### Testing Locally

Start a test backend:

```bash
# Terminal 1: Start a simple backend
python3 -m http.server 3000
```

Start the proxy:

```bash
# Terminal 2: Start the proxy
export NB_PROXY_TARGET_URL=http://localhost:3000
./bin/proxy
```

Test the proxy:

```bash
# Terminal 3: Make requests
curl http://localhost:8080
```

## License

Part of the Netbird project.