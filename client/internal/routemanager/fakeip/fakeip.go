package fakeip

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
)

var (
	// 240.0.0.1 - 240.255.255.254, block 240.0.0.0/8 (reserved, RFC 1112)
	v4Base  = netip.AddrFrom4([4]byte{240, 0, 0, 1})
	v4Max   = netip.AddrFrom4([4]byte{240, 255, 255, 254})
	v4Block = netip.PrefixFrom(netip.AddrFrom4([4]byte{240, 0, 0, 0}), 8)

	// 0100::1 - 0100::ffff:ffff:ffff:fffe, block 0100::/64 (discard, RFC 6666)
	v6Base  = netip.AddrFrom16([16]byte{0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01})
	v6Max   = netip.AddrFrom16([16]byte{0x01, 0x00, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe})
	v6Block = netip.PrefixFrom(netip.AddrFrom16([16]byte{0x01, 0x00}), 64)
)

// fakeIPPool holds the allocation state for a single address family.
type fakeIPPool struct {
	nextIP     netip.Addr
	baseIP     netip.Addr
	maxIP      netip.Addr
	block      netip.Prefix
	allocated  map[netip.Addr]netip.Addr // real IP -> fake IP
	fakeToReal map[netip.Addr]netip.Addr // fake IP -> real IP
}

func newPool(base, maxAddr netip.Addr, block netip.Prefix) *fakeIPPool {
	return &fakeIPPool{
		nextIP:     base,
		baseIP:     base,
		maxIP:      maxAddr,
		block:      block,
		allocated:  make(map[netip.Addr]netip.Addr),
		fakeToReal: make(map[netip.Addr]netip.Addr),
	}
}

// allocate allocates a fake IP for the given real IP.
// Returns the existing fake IP if already allocated.
func (p *fakeIPPool) allocate(realIP netip.Addr) (netip.Addr, error) {
	if fakeIP, exists := p.allocated[realIP]; exists {
		return fakeIP, nil
	}

	startIP := p.nextIP
	for {
		currentIP := p.nextIP

		// Advance to next IP, wrapping at boundary
		if p.nextIP.Compare(p.maxIP) >= 0 {
			p.nextIP = p.baseIP
		} else {
			p.nextIP = p.nextIP.Next()
		}

		if _, inUse := p.fakeToReal[currentIP]; !inUse {
			p.allocated[realIP] = currentIP
			p.fakeToReal[currentIP] = realIP
			return currentIP, nil
		}

		if p.nextIP.Compare(startIP) == 0 {
			return netip.Addr{}, fmt.Errorf("no more fake IPs available in %s block", p.block)
		}
	}
}

// Manager manages allocation of fake IPs for dynamic DNS routes.
// IPv4 uses 240.0.0.0/8 (reserved), IPv6 uses 0100::/64 (discard, RFC 6666).
type Manager struct {
	mu sync.Mutex
	v4 *fakeIPPool
	v6 *fakeIPPool
}

// NewManager creates a new fake IP manager.
func NewManager() *Manager {
	return &Manager{
		v4: newPool(v4Base, v4Max, v4Block),
		v6: newPool(v6Base, v6Max, v6Block),
	}
}

func (m *Manager) pool(ip netip.Addr) *fakeIPPool {
	if ip.Is6() {
		return m.v6
	}
	return m.v4
}

// AllocateFakeIP allocates a fake IP for the given real IP.
func (m *Manager) AllocateFakeIP(realIP netip.Addr) (netip.Addr, error) {
	realIP = realIP.Unmap()
	if !realIP.IsValid() {
		return netip.Addr{}, errors.New("invalid IP address")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	return m.pool(realIP).allocate(realIP)
}

// GetFakeIP returns the fake IP for a real IP if it exists.
func (m *Manager) GetFakeIP(realIP netip.Addr) (netip.Addr, bool) {
	realIP = realIP.Unmap()
	if !realIP.IsValid() {
		return netip.Addr{}, false
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	fakeIP, ok := m.pool(realIP).allocated[realIP]
	return fakeIP, ok
}

// GetRealIP returns the real IP for a fake IP if it exists.
func (m *Manager) GetRealIP(fakeIP netip.Addr) (netip.Addr, bool) {
	fakeIP = fakeIP.Unmap()
	if !fakeIP.IsValid() {
		return netip.Addr{}, false
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	realIP, ok := m.pool(fakeIP).fakeToReal[fakeIP]
	return realIP, ok
}

// GetFakeIPBlock returns the v4 fake IP block used by this manager.
func (m *Manager) GetFakeIPBlock() netip.Prefix {
	return m.v4.block
}

// GetFakeIPv6Block returns the v6 fake IP block used by this manager.
func (m *Manager) GetFakeIPv6Block() netip.Prefix {
	return m.v6.block
}
