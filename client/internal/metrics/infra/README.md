# Client Metrics

Internal documentation for the NetBird client metrics system.

## Overview

Client metrics track connection performance and sync durations using InfluxDB line protocol (`influxdb.go`). Each event is pushed once then cleared.

Metrics are:
- Disabled by default (opt-in via `NB_METRICS_ENABLED=true`)
- Managed at daemon layer (survives engine restarts)

## Architecture

### Layer Separation

```
Daemon Layer (connect.go)
  ├─ Creates ClientMetrics instance once
  ├─ Starts/stops push lifecycle
  └─ Updates AgentInfo on profile switch
      │
      ▼
Engine Layer (engine.go)
  └─ Records metrics via ClientMetrics methods
```

### Ingest Server

Clients do not talk to InfluxDB directly. An ingest server sits between clients and InfluxDB:

```
Client ──POST──▶ Ingest Server (:8087) ──▶ InfluxDB (internal)
                  │
                  ├─ Validates line protocol
                  ├─ Whitelists measurements & fields
                  ├─ Rejects out-of-bound values
                  └─ Serves remote config at /config
```

- **No client-side auth required** — the ingest server holds the InfluxDB token server-side
- **InfluxDB is not exposed** — only accessible within the docker network
- Source: `ingest/main.go`

## Metrics Collected

### Connection Stage Timing

Measurement: `netbird_peer_connection`

| Field | Timestamps | Description |
|-------|-----------|-------------|
| `signaling_to_connection_seconds` | `SignalingReceived → ConnectionReady` | ICE/relay negotiation time after the first signal is received from the remote peer |
| `connection_to_wg_handshake_seconds` | `ConnectionReady → WgHandshakeSuccess` | WireGuard cryptographic handshake latency once the transport layer is ready |
| `total_seconds` | `SignalingReceived → WgHandshakeSuccess` | End-to-end connection time anchored at the first received signal |

Tags:
- `deployment_type`: "cloud" | "selfhosted" | "unknown"
- `connection_type`: "ice" | "relay"
- `attempt_type`: "initial" | "reconnection"
- `version`: NetBird version string
- `os`: Operating system (linux, darwin, windows, android, ios, etc.)

**Note:** `SignalingReceived` is set when the first offer or answer arrives from the remote peer (in both initial and reconnection paths). It excludes the potentially unbounded wait for the remote peer to come online.

### Sync Duration

Measurement: `netbird_sync`

| Field | Description |
|-------|-------------|
| `duration_seconds` | Time to process a sync message from management server |

Tags:
- `deployment_type`: "cloud" | "selfhosted" | "unknown"
- `version`: NetBird version string
- `os`: Operating system (linux, darwin, windows, android, ios, etc.)

## Buffer Limits

The InfluxDB backend limits in-memory sample storage to prevent unbounded growth when pushes fail:
- **Max age:** Samples older than 5 days are dropped
- **Max size:** Estimated buffer size capped at 5 MB (~20k samples)

## Configuration

### Client Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NB_METRICS_ENABLED` | `false` | Enable metrics push |
| `NB_METRICS_SERVER_URL` | *(from remote config)* | Ingest server URL (e.g., `https://ingest.npeer.io`) |
| `NB_METRICS_INTERVAL` | *(from remote config)* | Push interval (e.g., "1m", "30m", "4h") |
| `NB_METRICS_FORCE_SENDING` | `false` | Skip remote config, push unconditionally |
| `NB_METRICS_CONFIG_URL` | `https://api.netbird.io/client-metrics-config.json` | Remote push config URL |

### Ingest Server Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `INGEST_LISTEN_ADDR` | `:8087` | Listen address |
| `INFLUXDB_URL` | `http://influxdb:8086/api/v2/write?org=netbird&bucket=metrics&precision=ns` | InfluxDB write endpoint |
| `INFLUXDB_TOKEN` | *(required)* | InfluxDB auth token (server-side only) |
| `CONFIG_METRICS_SERVER_URL` | *(empty — disables /config)* | `server_url` in the remote config JSON (the URL clients push metrics to) |
| `CONFIG_VERSION_SINCE` | `0.0.0` | Minimum client version to push metrics |
| `CONFIG_VERSION_UNTIL` | `99.99.99` | Maximum client version to push metrics |
| `CONFIG_PERIOD_MINUTES` | `5` | Push interval in minutes |

The ingest server serves a remote config JSON at `GET /config` when `CONFIG_METRICS_SERVER_URL` is set. Clients can use `NB_METRICS_CONFIG_URL=http://<ingest>/config` to fetch it.

### Configuration Precedence

For URL and Interval, the precedence is:
1. **Environment variable** - `NB_METRICS_SERVER_URL` / `NB_METRICS_INTERVAL`
2. **Remote config** - fetched from `NB_METRICS_CONFIG_URL`
3. **Default** - 5 minute interval, URL from remote config

## Push Behavior

1. `StartPush()` spawns background goroutine with timer
2. First push happens immediately on startup
3. Periodically: `push()` → `Export()` → HTTP POST to ingest server
4. On failure: log error, continue (non-blocking)
5. On success: `Reset()` clears pushed samples
6. `StopPush()` cancels context and waits for goroutine

Samples are collected with exact timestamps, pushed once, then cleared. No data is resent.

## Local Development Setup

### 1. Configure and Start Services

```bash
# From this directory (client/internal/metrics/infra)
cp .env.example .env
# Edit .env — set INFLUXDB_ADMIN_PASSWORD, INFLUXDB_ADMIN_TOKEN
docker compose up -d
```

This starts:
- **Ingest server** on http://localhost:8087 — accepts client metrics (no auth needed)
- **InfluxDB** — internal only, not exposed to host
- **Grafana** on http://localhost:3001

### 2. Configure Client

```bash
export NB_METRICS_ENABLED=true
export NB_METRICS_FORCE_SENDING=true
export NB_METRICS_SERVER_URL=http://localhost:8087
export NB_METRICS_INTERVAL=1m
```

### 3. Run Client

```bash
cd ../../../..
go run ./client/ up
```

### 4. View in Grafana

- **InfluxDB dashboard:** http://localhost:3001/d/netbird-influxdb-metrics

### 5. Verify Data

```bash
# Query via InfluxDB (using admin token from .env)
docker compose exec influxdb influx query \
  'from(bucket: "metrics") |> range(start: -1h)' \
  --org netbird

# Check ingest server health
curl http://localhost:8087/health
```