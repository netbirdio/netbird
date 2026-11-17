package conntrack

import (
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	nblog "github.com/netbirdio/netbird/client/firewall/uspfilter/log"
	nftypes "github.com/netbirdio/netbird/client/internal/netflow/types"
)

// evictSampleSize bounds how many map entries we scan per eviction call.
// Keeps eviction O(1) even at cap under sustained load; the sampled-LRU
// heuristic is good enough for a conntrack table that only overflows under
// abuse.
const evictSampleSize = 8

// envDuration parses an os.Getenv(name) as a time.Duration. Falls back to
// def on empty or invalid; logs a warning on invalid.
func envDuration(logger *nblog.Logger, name string, def time.Duration) time.Duration {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		logger.Warn3("invalid %s=%q: %v, using default", name, v, err)
		return def
	}
	if d <= 0 {
		logger.Warn2("invalid %s=%q: must be positive, using default", name, v)
		return def
	}
	return d
}

// envInt parses an os.Getenv(name) as an int. Falls back to def on empty,
// invalid, or non-positive. Logs a warning on invalid input.
func envInt(logger *nblog.Logger, name string, def int) int {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	switch {
	case err != nil:
		logger.Warn3("invalid %s=%q: %v, using default", name, v, err)
		return def
	case n <= 0:
		logger.Warn2("invalid %s=%q: must be positive, using default", name, v)
		return def
	}
	return n
}

// BaseConnTrack provides common fields and locking for all connection types
type BaseConnTrack struct {
	FlowId    uuid.UUID
	Direction nftypes.Direction
	SourceIP  netip.Addr
	DestIP    netip.Addr
	lastSeen  atomic.Int64
	PacketsTx atomic.Uint64
	PacketsRx atomic.Uint64
	BytesTx   atomic.Uint64
	BytesRx   atomic.Uint64

	DNATOrigPort atomic.Uint32
}

// these small methods will be inlined by the compiler

// UpdateLastSeen safely updates the last seen timestamp
func (b *BaseConnTrack) UpdateLastSeen() {
	b.lastSeen.Store(time.Now().UnixNano())
}

// UpdateCounters safely updates the packet and byte counters
func (b *BaseConnTrack) UpdateCounters(direction nftypes.Direction, bytes int) {
	if direction == nftypes.Egress {
		b.PacketsTx.Add(1)
		b.BytesTx.Add(uint64(bytes))
	} else {
		b.PacketsRx.Add(1)
		b.BytesRx.Add(uint64(bytes))
	}
}

// GetLastSeen safely gets the last seen timestamp
func (b *BaseConnTrack) GetLastSeen() time.Time {
	return time.Unix(0, b.lastSeen.Load())
}

// timeoutExceeded checks if the connection has exceeded the given timeout
func (b *BaseConnTrack) timeoutExceeded(timeout time.Duration) bool {
	lastSeen := time.Unix(0, b.lastSeen.Load())
	return time.Since(lastSeen) > timeout
}

// ConnKey uniquely identifies a connection
type ConnKey struct {
	SrcIP   netip.Addr
	DstIP   netip.Addr
	SrcPort uint16
	DstPort uint16
}

func (c ConnKey) String() string {
	return net.JoinHostPort(c.SrcIP.Unmap().String(), strconv.Itoa(int(c.SrcPort))) +
		" → " +
		net.JoinHostPort(c.DstIP.Unmap().String(), strconv.Itoa(int(c.DstPort)))
}
