// common.go
package conntrack

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// BaseConnTrack provides common fields and locking for all connection types
type BaseConnTrack struct {
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

// IPAddr is a fixed-size IP address to avoid allocations
type IPAddr [16]byte

// String returns a string representation of the IP address
func (ip IPAddr) String() string {
	isIPv4 := true
	for i := 0; i < 12; i++ {
		if ip[i] != 0 {
			isIPv4 = false
			break
		}
	}

	if isIPv4 {
		return fmt.Sprintf("%d.%d.%d.%d", ip[12], ip[13], ip[14], ip[15])
	}

	return fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
		ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7],
		ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15])
}

// MakeIPAddr creates an IPAddr from net.IP
func MakeIPAddr(ip net.IP) (addr IPAddr) {
	if ip4 := ip.To4(); ip4 != nil {
		copy(addr[12:], ip4)
	} else {
		copy(addr[:], ip.To16())
	}
	return addr
}

// ConnKey uniquely identifies a connection
type ConnKey struct {
	SrcIP   IPAddr
	DstIP   IPAddr
	SrcPort uint16
	DstPort uint16
}

func (c *ConnKey) String() string {
	return fmt.Sprintf("%s:%d -> %s:%d", c.SrcIP, c.SrcPort, c.DstIP, c.DstPort)
}

// makeConnKey creates a connection key
func makeConnKey(srcIP net.IP, dstIP net.IP, srcPort uint16, dstPort uint16) *ConnKey {
	return &ConnKey{
		SrcIP:   MakeIPAddr(srcIP),
		DstIP:   MakeIPAddr(dstIP),
		SrcPort: srcPort,
		DstPort: dstPort,
	}
}

// ValidateIPs checks if IPs match without allocation
func ValidateIPs(connIP IPAddr, pktIP net.IP) bool {
	if ip4 := pktIP.To4(); ip4 != nil {
		// Compare IPv4 addresses (last 4 bytes)
		for i := 0; i < 4; i++ {
			if connIP[12+i] != ip4[i] {
				return false
			}
		}
		return true
	}
	// Compare full IPv6 addresses
	ip6 := pktIP.To16()
	for i := 0; i < 16; i++ {
		if connIP[i] != ip6[i] {
			return false
		}
	}
	return true
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

// copyIP copies an IP address efficiently
func copyIP(dst, src net.IP) {
	if len(src) == 16 {
		copy(dst, src)
	} else {
		copy(dst[12:], src.To4())
	}
}
