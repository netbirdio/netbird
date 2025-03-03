package conntrack

import (
	"fmt"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	nftypes "github.com/netbirdio/netbird/client/internal/netflow/types"
)

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
	return fmt.Sprintf("%s:%d -> %s:%d", c.SrcIP.Unmap(), c.SrcPort, c.DstIP.Unmap(), c.DstPort)
}
