package fakeip

import (
	"fmt"
	"net/netip"
	"sync"
)

// Manager manages allocation of fake IPs from the 240.0.0.0/8 block
type Manager struct {
	mu         sync.Mutex
	nextIP     netip.Addr                // Next IP to allocate
	allocated  map[netip.Addr]netip.Addr // real IP -> fake IP
	fakeToReal map[netip.Addr]netip.Addr // fake IP -> real IP
	baseIP     netip.Addr                // First usable IP: 240.0.0.1
	maxIP      netip.Addr                // Last usable IP: 240.255.255.254
}

// NewManager creates a new fake IP manager using 240.0.0.0/8 block
func NewManager() *Manager {
	baseIP := netip.AddrFrom4([4]byte{240, 0, 0, 1})
	maxIP := netip.AddrFrom4([4]byte{240, 255, 255, 254})

	return &Manager{
		nextIP:     baseIP,
		allocated:  make(map[netip.Addr]netip.Addr),
		fakeToReal: make(map[netip.Addr]netip.Addr),
		baseIP:     baseIP,
		maxIP:      maxIP,
	}
}

// AllocateFakeIP allocates a fake IP for the given real IP
// Returns the fake IP, or existing fake IP if already allocated
func (m *Manager) AllocateFakeIP(realIP netip.Addr) (netip.Addr, error) {
	if !realIP.Is4() {
		return netip.Addr{}, fmt.Errorf("only IPv4 addresses supported")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if fakeIP, exists := m.allocated[realIP]; exists {
		return fakeIP, nil
	}

	startIP := m.nextIP
	for {
		currentIP := m.nextIP

		// Advance to next IP, wrapping at boundary
		if m.nextIP.Compare(m.maxIP) >= 0 {
			m.nextIP = m.baseIP
		} else {
			m.nextIP = m.nextIP.Next()
		}

		// Check if current IP is available
		if _, inUse := m.fakeToReal[currentIP]; !inUse {
			m.allocated[realIP] = currentIP
			m.fakeToReal[currentIP] = realIP
			return currentIP, nil
		}

		// Prevent infinite loop if all IPs exhausted
		if m.nextIP.Compare(startIP) == 0 {
			return netip.Addr{}, fmt.Errorf("no more fake IPs available in 240.0.0.0/8 block")
		}
	}
}

// GetFakeIP returns the fake IP for a real IP if it exists
func (m *Manager) GetFakeIP(realIP netip.Addr) (netip.Addr, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	fakeIP, exists := m.allocated[realIP]
	return fakeIP, exists
}

// GetRealIP returns the real IP for a fake IP if it exists, otherwise false
func (m *Manager) GetRealIP(fakeIP netip.Addr) (netip.Addr, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	realIP, exists := m.fakeToReal[fakeIP]
	return realIP, exists
}

// GetFakeIPBlock returns the fake IP block used by this manager
func (m *Manager) GetFakeIPBlock() netip.Prefix {
	return netip.MustParsePrefix("240.0.0.0/8")
}
