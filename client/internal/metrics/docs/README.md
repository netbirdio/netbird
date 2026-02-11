# Client Metrics

Internal documentation for the NetBird client metrics system.

## Overview

Client metrics track connection performance and sync durations. Metrics are:
- Collected in-memory using VictoriaMetrics histograms
- Pushed periodically to a VictoriaMetrics server
- Disabled by default (opt-in via environment variable)
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

### Data Flow

```
NetBird Client
  ├─ Records metrics in memory (histograms)
  ├─ Push to VictoriaMetrics via HTTP POST
  └─ Metrics endpoint: /api/v1/import/prometheus
      │
      ▼
VictoriaMetrics (port 8428)
  ├─ Stores time-series data
  ├─ 12 month retention
  └─ Prometheus-compatible query API
      │
      ▼
Grafana (port 3000)
  └─ Pre-configured dashboard
```

## Metrics Collected

### Connection Stage Timing

1. `netbird_peer_connection_stage_creation_to_semaphore`
2. `netbird_peer_connection_stage_semaphore_to_signaling`
3. `netbird_peer_connection_stage_signaling_to_connection`
4. `netbird_peer_connection_stage_connection_to_handshake`
5. `netbird_peer_connection_total_creation_to_handshake`

Labels:
- `deployment_type`: "cloud" | "selfhosted" | "unknown"
- `connection_type`: "ice" | "relay"
- `attempt_type`: "initial" | "reconnection"
- `version`: NetBird version string
- `os`: Operating system (linux, darwin, windows, android, ios, etc.)

### Sync Duration

Tracks time to process sync messages from management server:

1. `netbird_sync_duration_seconds`

Labels:
- `deployment_type`: "cloud" | "selfhosted" | "unknown"
- `version`: NetBird version string
- `os`: Operating system (linux, darwin, windows, android, ios, etc.)

## Configuration

### Environment Variables

| Variable | Default | Description                             |
|----------|---------|-----------------------------------------|
| `NB_METRICS_ENABLED` | `false` | Enable metrics push                     |
| `NB_METRICS_SERVER_URL` | `https://api.netbird.io:8428/api/v1/import/prometheus` | VictoriaMetrics endpoint                |
| `NB_METRICS_INTERVAL` |  | Push interval (e.g., "1m", "30m", "4h") |

t### Configuration Precedence

For URL and Interval, the precedence is:
1. **Config parameter** - Explicitly passed to `StartPush()`
2. **Environment variable** - `NB_METRICS_SERVER_URL` / `NB_METRICS_INTERVAL`
3. **Default value** - From `metrics.DefaultPushConfig` (4h interval)

## Push Behavior

1. `StartPush()` spawns background goroutine with ticker (4h)
2. First push happens immediately on startup
3. Every 4 hours: `push()` → `Export()` → HTTP POST
4. On failure: log error, continue (non-blocking)
5. On success: log debug message
6. `StopPush()` cancels context and waits for goroutine

**Important:**
- Metrics **accumulate** in memory (cumulative histograms)
- Metrics are **NOT reset** after push (correct Prometheus behavior)
- VictoriaMetrics calculates rates from deltas between pushes
- Each push sends **all** accumulated metrics
- Metrics only reset on process restart

## Local Development Setup

### 1. Start VictoriaMetrics

```bash
# From this directory
docker-compose -f docker-compose.victoria.yml up -d

# View logs
docker-compose -f docker-compose.victoria.yml logs -f
```

**Access:**
- VictoriaMetrics UI: http://localhost:8428
- Grafana: http://localhost:3001 (admin/admin)

### 2. Configure Client

```bash
export NB_METRICS_ENABLED=true
export NB_METRICS_SERVER_URL=http://localhost:8428/api/v1/import/prometheus
export NB_METRICS_INTERVAL=1h  # Optional: push every hour instead of default 4h

# Run client
cd ../../../..
go run main.go up
```

### 3. Verify Metrics

```bash
# Watch client logs
go run main.go up 2>&1 | grep -i metric

# List all available metric names
curl http://localhost:8428/api/v1/label/__name__/values

# Query specific metric
curl 'http://localhost:8428/api/v1/query?query=netbird_peer_connection_total_creation_to_handshake_count'
```

### 4. View in Grafana

Open http://localhost:3001/d/netbird-connection-metrics

Dashboard JSON location:
```
grafana/provisioning/dashboards/json/netbird-connection-metrics.json
```

Export modified dashboards from Grafana UI and replace this file.

## Querying Metrics

### VictoriaMetrics UI

Open http://localhost:8428/vmui

```promql
# P95 connection time
histogram_quantile(0.95, netbird_peer_connection_total_creation_to_handshake)

# Connection rate
rate(netbird_peer_connection_total_creation_to_handshake_count[5m])

# Average sync duration
rate(netbird_sync_duration_seconds_sum[5m]) / rate(netbird_sync_duration_seconds_count[5m])
```

### API Queries

```bash
curl 'http://localhost:8428/api/v1/query?query=netbird_peer_connection_total_creation_to_handshake_count'
```
