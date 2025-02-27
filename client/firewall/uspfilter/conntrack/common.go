package conntrack

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/netbirdio/netbird/client/internal/netflow/types"
)

// BaseConnTrack provides common fields and locking for all connection types
type BaseConnTrack struct {
	FlowId     uuid.UUID
	Direction  types.Direction
	SourceIP   net.IP
	DestIP     net.IP
	SourcePort uint16
	DestPort   uint16
	lastSeen   atomic.Int64
}

// these small methods will be inlined by the compiler

// UpdateLastSeen safely updates the last seen timestamp
func (b *BaseConnTrack) UpdateLastSeen() {
	b.lastSeen.Store(time.Now().UnixNano())
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
	return fmt.Sprintf("%s:%d -> %s:%d", c.SrcIP, c.SrcPort, c.DstIP, c.DstPort)
}

// makeConnKey creates a connection key
func makeConnKey(srcIP net.IP, dstIP net.IP, srcPort uint16, dstPort uint16) ConnKey {
	srcAddr, _ := netip.AddrFromSlice(srcIP)
	dstAddr, _ := netip.AddrFromSlice(dstIP)

	return ConnKey{
		SrcIP:   srcAddr,
		DstIP:   dstAddr,
		SrcPort: srcPort,
		DstPort: dstPort,
	}
}

// ValidateIPs checks if IPs match
func ValidateIPs(connIP netip.Addr, pktIP net.IP) bool {
	pktAddr, ok := netip.AddrFromSlice(pktIP)
	if !ok {
		return false
	}
	return connIP == pktAddr
}

// PreallocatedIPs is a pool of IP byte slices to reduce allocations
type PreallocatedIPs struct {
	sync.Pool
}

// NewPreallocatedIPs creates a new IP pool
func NewPreallocatedIPs() *PreallocatedIPs {
	return &PreallocatedIPs{
		Pool: sync.Pool{
			New: func() interface{} {
				ip := make(net.IP, 16)
				return &ip
			},
		},
	}
}

// Get retrieves an IP from the pool
func (p *PreallocatedIPs) Get() net.IP {
	return *p.Pool.Get().(*net.IP)
}

// Put returns an IP to the pool
func (p *PreallocatedIPs) Put(ip net.IP) {
	p.Pool.Put(&ip)
}
