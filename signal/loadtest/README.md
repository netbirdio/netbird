# Signal Server Load Test

Load testing tool for the NetBird signal server.

## Features

- **Rate-based peer pair creation**: Spawn peer pairs at configurable rates (e.g., 10, 20 pairs/sec)
- **Two exchange modes**:
  - **Single message**: Each pair exchanges one message for validation
  - **Continuous exchange**: Pairs continuously exchange messages for a specified duration (e.g., 30 seconds, 10 minutes)
- **TLS/HTTPS support**: Connect to TLS-enabled signal servers with optional certificate verification
- **Automatic reconnection**: Optional automatic reconnection with exponential backoff on connection loss
- **Configurable message interval**: Control message send rate in continuous mode
- **Message exchange validation**: Validates encrypted body size > 0
- **Comprehensive metrics**: Tracks throughput, success/failure rates, latency statistics, and reconnection counts
- **Local server testing**: Tests include embedded signal server for easy development
- **Worker pool pattern**: Efficient concurrent execution
- **Graceful shutdown**: Context-based cancellation

## Usage

### Standalone Binary

Build and run the load test as a standalone binary:

```bash
# Build the binary
cd signal/loadtest/cmd/signal-loadtest
go build -o signal-loadtest

# Single message exchange
./signal-loadtest \
  -server http://localhost:10000 \
  -pairs-per-sec 10 \
  -total-pairs 100 \
  -message-size 100

# Continuous exchange for 30 seconds
./signal-loadtest \
  -server http://localhost:10000 \
  -pairs-per-sec 10 \
  -total-pairs 20 \
  -message-size 200 \
  -exchange-duration 30s \
  -message-interval 200ms

# Long-running test (10 minutes)
./signal-loadtest \
  -server http://localhost:10000 \
  -pairs-per-sec 20 \
  -total-pairs 50 \
  -message-size 500 \
  -exchange-duration 10m \
  -message-interval 100ms \
  -test-duration 15m \
  -log-level debug

# TLS server with valid certificate
./signal-loadtest \
  -server https://signal.example.com:443 \
  -pairs-per-sec 10 \
  -total-pairs 50 \
  -message-size 100

# TLS server with self-signed certificate
./signal-loadtest \
  -server https://localhost:443 \
  -pairs-per-sec 5 \
  -total-pairs 10 \
  -insecure-skip-verify \
  -log-level debug

# High load test with custom worker pool
./signal-loadtest \
  -server http://localhost:10000 \
  -pairs-per-sec 100 \
  -total-pairs 1000 \
  -worker-pool-size 500 \
  -channel-buffer-size 1000 \
  -exchange-duration 60s \
  -log-level info

# Progress reporting - report every 5000 messages
./signal-loadtest \
  -server http://localhost:10000 \
  -pairs-per-sec 50 \
  -total-pairs 100 \
  -exchange-duration 5m \
  -report-interval 5000 \
  -log-level info

# With automatic reconnection
./signal-loadtest \
  -server http://localhost:10000 \
  -pairs-per-sec 10 \
  -total-pairs 50 \
  -exchange-duration 5m \
  -enable-reconnect \
  -initial-retry-delay 100ms \
  -max-reconnect-delay 30s \
  -log-level debug

# Show help
./signal-loadtest -h
```

**Graceful Shutdown:**

The load test supports graceful shutdown via Ctrl+C (SIGINT/SIGTERM):
- Press Ctrl+C to interrupt the test at any time
- All active clients will be closed gracefully
- A final aggregated report will be printed showing metrics up to the point of interruption
- Shutdown timeout: 5 seconds (after which the process will force exit)

**Available Flags:**
- `-server`: Signal server URL (http:// or https://) (default: `http://localhost:10000`)
- `-pairs-per-sec`: Peer pairs created per second (default: 10)
- `-total-pairs`: Total number of peer pairs (default: 100)
- `-message-size`: Message size in bytes (default: 100)
- `-test-duration`: Maximum test duration, 0 = unlimited (default: 0)
- `-exchange-duration`: Continuous exchange duration per pair, 0 = single message (default: 0)
- `-message-interval`: Interval between messages in continuous mode (default: 100ms)
- `-worker-pool-size`: Number of concurrent workers, 0 = auto (pairs-per-sec × 2) (default: 0)
- `-channel-buffer-size`: Work queue buffer size, 0 = auto (pairs-per-sec × 4) (default: 0)
- `-report-interval`: Report progress every N messages, 0 = no periodic reports (default: 10000)
- `-enable-reconnect`: Enable automatic reconnection on connection loss (default: false)
- `-initial-retry-delay`: Initial delay before first reconnection attempt (default: 100ms)
- `-max-reconnect-delay`: Maximum delay between reconnection attempts (default: 30s)
- `-insecure-skip-verify`: Skip TLS certificate verification for self-signed certificates (default: false)
- `-log-level`: Log level: trace, debug, info, warn, error (default: info)

### Running Tests

```bash
# Run all tests (includes load tests)
go test -v -timeout 2m

# Run specific single-message load tests
go test -v -run TestLoadTest_10PairsPerSecond -timeout 40s
go test -v -run TestLoadTest_20PairsPerSecond -timeout 40s
go test -v -run TestLoadTest_SmallBurst -timeout 30s

# Run continuous exchange tests
go test -v -run TestLoadTest_ContinuousExchange_ShortBurst -timeout 30s
go test -v -run TestLoadTest_ContinuousExchange_30Seconds -timeout 2m
go test -v -run TestLoadTest_ContinuousExchange_10Minutes -timeout 15m

# Skip long-running tests in quick runs
go test -short
```

### Programmatic Usage

#### Single Message Exchange
```go
package main

import (
    "github.com/netbirdio/netbird/signal/loadtest"
    "time"
)

func main() {
    config := loadtest.LoadTestConfig{
        ServerURL:      "http://localhost:10000",
        PairsPerSecond: 10,
        TotalPairs:     100,
        MessageSize:    100,
        TestDuration:   30 * time.Second,
    }

    lt := loadtest.NewLoadTest(config)
    if err := lt.Run(); err != nil {
        panic(err)
    }

    metrics := lt.GetMetrics()
    metrics.PrintReport()
}
```

#### Continuous Message Exchange
```go
package main

import (
    "github.com/netbirdio/netbird/signal/loadtest"
    "time"
)

func main() {
    config := loadtest.LoadTestConfig{
        ServerURL:        "http://localhost:10000",
        PairsPerSecond:   10,
        TotalPairs:       20,
        MessageSize:      200,
        ExchangeDuration: 10 * time.Minute,  // Each pair exchanges messages for 10 minutes
        MessageInterval:  200 * time.Millisecond,  // Send message every 200ms
        TestDuration:     15 * time.Minute,  // Overall test timeout
    }

    lt := loadtest.NewLoadTest(config)
    if err := lt.Run(); err != nil {
        panic(err)
    }

    metrics := lt.GetMetrics()
    metrics.PrintReport()
}
```

## Configuration Options

- **ServerURL**: Signal server URL (e.g., `http://localhost:10000` or `https://signal.example.com:443`)
- **PairsPerSecond**: Rate at which peer pairs are created (e.g., 10, 20)
- **TotalPairs**: Total number of peer pairs to create
- **MessageSize**: Size of test message payload in bytes
- **TestDuration**: Maximum test duration (optional, 0 = no limit)
- **ExchangeDuration**: Duration for continuous message exchange per pair (0 = single message)
- **MessageInterval**: Interval between messages in continuous mode (default: 100ms)
- **WorkerPoolSize**: Number of concurrent worker goroutines (0 = auto: pairs-per-sec × 2)
- **ChannelBufferSize**: Work queue buffer size (0 = auto: pairs-per-sec × 4)
- **ReportInterval**: Report progress every N messages (0 = no periodic reports, default: 10000)
- **EnableReconnect**: Enable automatic reconnection on connection loss (default: false)
- **InitialRetryDelay**: Initial delay before first reconnection attempt (default: 100ms)
- **MaxReconnectDelay**: Maximum delay between reconnection attempts (default: 30s)
- **InsecureSkipVerify**: Skip TLS certificate verification (for self-signed certificates)
- **RampUpDuration**: Gradual ramp-up period (not yet implemented)

### Reconnection Handling

The load test supports automatic reconnection on connection loss:

- **Disabled by default**: Connections will fail on any network interruption
- **When enabled**: Clients automatically reconnect with exponential backoff
- **Exponential backoff**: Starts at `InitialRetryDelay`, doubles on each failure, caps at `MaxReconnectDelay`
- **Transparent reconnection**: Message exchange continues after successful reconnection
- **Metrics tracking**: Total reconnection count is reported

**Use cases:**
- Testing resilience to network interruptions
- Validating server restart behavior
- Simulating flaky network conditions
- Long-running stability tests

**Example with reconnection:**
```go
config := loadtest.LoadTestConfig{
    ServerURL:         "http://localhost:10000",
    PairsPerSecond:    10,
    TotalPairs:        20,
    ExchangeDuration:  10 * time.Minute,
    EnableReconnect:   true,
    InitialRetryDelay: 100 * time.Millisecond,
    MaxReconnectDelay: 30 * time.Second,
}
```

### Performance Tuning

When running high-load tests, you may need to adjust the worker pool and buffer sizes:

- **Default sizing**: Auto-configured based on `PairsPerSecond`
  - Worker pool: `PairsPerSecond × 2`
  - Channel buffer: `PairsPerSecond × 4`
- **For continuous exchange**: Increase worker pool size (e.g., `PairsPerSecond × 5`)
- **For high pair rates** (>50/sec): Increase both worker pool and buffer proportionally
- **Signs you need more workers**: Log warnings about "Worker pool saturated"

Example for 100 pairs/sec with continuous exchange:
```go
config := LoadTestConfig{
    PairsPerSecond:    100,
    WorkerPoolSize:    500,  // 5x pairs/sec
    ChannelBufferSize: 1000, // 10x pairs/sec
}
```

## Metrics

The load test collects and reports:

- **Total Pairs Sent**: Number of peer pairs attempted
- **Successful Exchanges**: Completed message exchanges
- **Failed Exchanges**: Failed message exchanges
- **Total Messages Exchanged**: Count of successfully exchanged messages
- **Total Errors**: Cumulative error count
- **Total Reconnections**: Number of automatic reconnections (if enabled)
- **Throughput**: Pairs per second (actual)
- **Latency Statistics**: Min, Max, Avg message exchange latency

## Graceful Shutdown Example

You can interrupt a long-running test at any time with Ctrl+C:

```
./signal-loadtest -server http://localhost:10000 -pairs-per-sec 10 -total-pairs 100 -exchange-duration 10m

# Press Ctrl+C after some time...
^C
WARN[0045]
Received interrupt signal, shutting down gracefully...

=== Load Test Report ===
Test Duration: 45.234s
Total Pairs Sent: 75
Successful Exchanges: 75
Failed Exchanges: 0
Total Messages Exchanged: 22500
Total Errors: 0
Throughput: 1.66 pairs/sec
...
========================
```

## Test Results

Example output from a 20 pairs/sec test:

```
=== Load Test Report ===
Test Duration: 5.055249917s
Total Pairs Sent: 100
Successful Exchanges: 100
Failed Exchanges: 0
Total Messages Exchanged: 100
Total Errors: 0
Throughput: 19.78 pairs/sec

Latency Statistics:
  Min: 170.375µs
  Max: 5.176916ms
  Avg: 441.566µs
========================
```

## Architecture

### Client (`client.go`)
- Manages gRPC connection to signal server
- Establishes bidirectional stream for receiving messages
- Sends messages via `Send` RPC method
- Handles message reception asynchronously

### Load Test Engine (`rate_loadtest.go`)
- Worker pool pattern for concurrent peer pairs
- Rate-limited pair creation using ticker
- Atomic counters for thread-safe metrics collection
- Graceful shutdown on context cancellation

### Test Suite
- `loadtest_test.go`: Single pair validation test
- `rate_loadtest_test.go`: Multiple rate-based load tests and benchmarks

## Implementation Details

### Message Flow
1. Create sender and receiver clients with unique IDs
2. Both clients connect to signal server via bidirectional stream
3. Sender sends encrypted message using `Send` RPC
4. Signal server forwards message to receiver's stream
5. Receiver reads message from stream
6. Validate encrypted body size > 0
7. Record latency and success metrics

### Concurrency
- Worker pool size = `PairsPerSecond`
- Each worker handles multiple peer pairs sequentially
- Atomic operations for metrics to avoid lock contention
- Channel-based work distribution

## Future Enhancements

- [x] TLS/HTTPS support for production servers
- [x] Automatic reconnection with exponential backoff
- [ ] Ramp-up period implementation
- [ ] Percentile latency metrics (p50, p95, p99)
- [ ] Connection reuse for multiple messages per pair
- [ ] Support for custom message payloads
- [ ] CSV/JSON metrics export
- [ ] Real-time metrics dashboard
