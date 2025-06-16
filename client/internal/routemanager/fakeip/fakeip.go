package fakeip

import (
	"fmt"
	"net/netip"
	"sync"
)

// FakeIPManager manages allocation of fake IPs from the 240.0.0.0/8 block
type FakeIPManager struct {
	mu         sync.Mutex
	nextIP     netip.Addr                // Next IP to allocate
	allocated  map[netip.Addr]netip.Addr // real IP -> fake IP
	fakeToReal map[netip.Addr]netip.Addr // fake IP -> real IP
	baseIP     netip.Addr                // First usable IP: 240.0.0.1
	maxIP      netip.Addr                // Last usable IP: 240.255.255.254
}

// NewManager creates a new fake IP manager using 240.0.0.0/8 block
func NewManager() *FakeIPManager {
	baseIP := netip.AddrFrom4([4]byte{240, 0, 0, 1})
	maxIP := netip.AddrFrom4([4]byte{240, 255, 255, 254})

	return &FakeIPManager{
		nextIP:     baseIP,
		allocated:  make(map[netip.Addr]netip.Addr),
		fakeToReal: make(map[netip.Addr]netip.Addr),
		baseIP:     baseIP,
		maxIP:      maxIP,
	}
}

// AllocateFakeIP allocates a fake IP for the given real IP
// Returns the fake IP, or existing fake IP if already allocated
func (f *FakeIPManager) AllocateFakeIP(realIP netip.Addr) (netip.Addr, error) {
	if !realIP.Is4() {
		return netip.Addr{}, fmt.Errorf("only IPv4 addresses supported")
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	if fakeIP, exists := f.allocated[realIP]; exists {
		return fakeIP, nil
	}

	startIP := f.nextIP
	for {
		currentIP := f.nextIP

		// Advance to next IP, wrapping at boundary
		if f.nextIP.Compare(f.maxIP) >= 0 {
			f.nextIP = f.baseIP
		} else {
			f.nextIP = f.nextIP.Next()
		}

		// Check if current IP is available
		if _, inUse := f.fakeToReal[currentIP]; !inUse {
			f.allocated[realIP] = currentIP
			f.fakeToReal[currentIP] = realIP
			return currentIP, nil
		}

		// Prevent infinite loop if all IPs exhausted
		if f.nextIP.Compare(startIP) == 0 {
			return netip.Addr{}, fmt.Errorf("no more fake IPs available in 240.0.0.0/8 block")
		}
	}
}

// GetFakeIP returns the fake IP for a real IP if it exists
func (f *FakeIPManager) GetFakeIP(realIP netip.Addr) (netip.Addr, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	fakeIP, exists := f.allocated[realIP]
	return fakeIP, exists
}

// GetRealIP returns the real IP for a fake IP if it exists, otherwise false
func (f *FakeIPManager) GetRealIP(fakeIP netip.Addr) (netip.Addr, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	realIP, exists := f.fakeToReal[fakeIP]
	return realIP, exists
}

// GetFakeIPBlock returns the fake IP block used by this manager
func (f *FakeIPManager) GetFakeIPBlock() netip.Prefix {
	return netip.MustParsePrefix("240.0.0.0/8")
}
