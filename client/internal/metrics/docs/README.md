# Client Metrics

Internal documentation for the NetBird client metrics system.

## Overview

Client metrics track connection performance and sync durations. Two backend implementations are available:

- **InfluxDB** (`influxdb.go`): Timestamped samples in InfluxDB line protocol. Best for sparse one-shot events (connections, syncs). Each event is pushed once then cleared.
- **VictoriaMetrics** (`victoria.go`): Prometheus-style cumulative histograms. Better for continuous/high-frequency metrics.

Select the implementation in `metrics_default.go`:
- `newInfluxDBMetrics()` — InfluxDB line protocol
- `newVictoriaMetrics()` — Prometheus format

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

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NB_METRICS_ENABLED` | `false` | Enable metrics push |
| `NB_METRICS_SERVER_URL` | `https://api.netbird.io:8086/api/v2/write?org=netbird&bucket=metrics&precision=ns` | Metrics endpoint URL |
| `NB_METRICS_INTERVAL` | | Push interval (e.g., "1m", "30m", "4h"). When set, bypasses remote config. |
| `NB_METRICS_TOKEN` | | Optional auth token for the metrics server |
| `NB_METRICS_CONFIG_URL` | `https://api.netbird.io/client-metrics-config.json` | Remote push config URL |

### Backend-specific URLs

| Backend | URL |
|---------|-----|
| **InfluxDB** | `http://<host>:8086/api/v2/write?org=netbird&bucket=metrics&precision=ns` |
| **VictoriaMetrics** | `http://<host>:8428/api/v1/import/prometheus` |

### Configuration Precedence

For URL and Interval, the precedence is:
1. **Config parameter** - Explicitly passed to `StartPush()`
2. **Environment variable** - `NB_METRICS_SERVER_URL` / `NB_METRICS_INTERVAL`
3. **Default value** - From `metrics.DefaultPushConfig`

## Push Behavior

1. `StartPush()` spawns background goroutine with timer
2. First push happens immediately on startup
3. Periodically: `push()` → `Export()` → HTTP POST
4. On failure: log error, continue (non-blocking)
5. On success: `Reset()` clears pushed samples, log debug message
6. `StopPush()` cancels context and waits for goroutine

**InfluxDB mode:** Samples are collected with exact timestamps, pushed once, then cleared. No data is resent.

**VictoriaMetrics mode:** Cumulative histograms accumulate in memory. After successful push, metrics are unregistered. Use `rate(sum)/rate(count)` for averages.

## Local Development Setup

### 1. Start Services

```bash
# From this directory
docker compose -f docker-compose.victoria.yml up -d
```

**Access:**
- Grafana: http://localhost:3001 (admin/admin)
- InfluxDB: http://localhost:8086
- VictoriaMetrics: http://localhost:8428

### 2. Configure Client (InfluxDB)

```bash
export NB_METRICS_ENABLED=true
export NB_METRICS_SERVER_URL='http://localhost:8086/api/v2/write?org=netbird&bucket=metrics&precision=ns'
export NB_METRICS_TOKEN=netbird-metrics-token
export NB_METRICS_INTERVAL=1m
```

Make sure `metrics_default.go` uses `newInfluxDBMetrics()`.

### 3. Configure Client (VictoriaMetrics)

```bash
export NB_METRICS_ENABLED=true
export NB_METRICS_SERVER_URL=http://localhost:8428/api/v1/import/prometheus
export NB_METRICS_INTERVAL=1m
```

Make sure `metrics_default.go` uses `newVictoriaMetrics()`.

### 4. Run Client

```bash
cd ../../../..
go run ./client/ up
```

### 5. View in Grafana

- **InfluxDB dashboard:** http://localhost:3001/d/netbird-influxdb-metrics
- **VictoriaMetrics dashboard:** http://localhost:3001/d/netbird-connection-metrics

### 6. Verify Data

```bash
# InfluxDB - query data
curl -H "Authorization: Token netbird-metrics-token" \
  'http://localhost:8086/api/v2/query?org=netbird' \
  --data-urlencode 'q=from(bucket:"metrics") |> range(start: -1h)'

# VictoriaMetrics - list metrics
curl http://localhost:8428/api/v1/label/__name__/values

# VictoriaMetrics - delete all data
curl -s http://localhost:8428/api/v1/admin/tsdb/delete_series --data-urlencode 'match[]={__name__=~".+"}'
```