package fakeip

import (
	"net/netip"
	"sync"
	"testing"
)

func TestNewManager(t *testing.T) {
	manager := NewManager()

	if manager.baseIP.String() != "240.0.0.1" {
		t.Errorf("Expected base IP 240.0.0.1, got %s", manager.baseIP.String())
	}

	if manager.maxIP.String() != "240.255.255.254" {
		t.Errorf("Expected max IP 240.255.255.254, got %s", manager.maxIP.String())
	}

	if manager.nextIP.Compare(manager.baseIP) != 0 {
		t.Errorf("Expected nextIP to start at baseIP")
	}
}

func TestAllocateFakeIP(t *testing.T) {
	manager := NewManager()
	realIP := netip.MustParseAddr("8.8.8.8")

	fakeIP, err := manager.AllocateFakeIP(realIP)
	if err != nil {
		t.Fatalf("Failed to allocate fake IP: %v", err)
	}

	if !fakeIP.Is4() {
		t.Error("Fake IP should be IPv4")
	}

	// Check it's in the correct range
	if fakeIP.As4()[0] != 240 {
		t.Errorf("Fake IP should be in 240.0.0.0/8 range, got %s", fakeIP.String())
	}

	// Should return same fake IP for same real IP
	fakeIP2, err := manager.AllocateFakeIP(realIP)
	if err != nil {
		t.Fatalf("Failed to get existing fake IP: %v", err)
	}

	if fakeIP.Compare(fakeIP2) != 0 {
		t.Errorf("Expected same fake IP for same real IP, got %s and %s", fakeIP.String(), fakeIP2.String())
	}
}

func TestAllocateFakeIPIPv6Rejection(t *testing.T) {
	manager := NewManager()
	realIPv6 := netip.MustParseAddr("2001:db8::1")

	_, err := manager.AllocateFakeIP(realIPv6)
	if err == nil {
		t.Error("Expected error for IPv6 address")
	}
}

func TestGetFakeIP(t *testing.T) {
	manager := NewManager()
	realIP := netip.MustParseAddr("1.1.1.1")

	// Should not exist initially
	_, exists := manager.GetFakeIP(realIP)
	if exists {
		t.Error("Fake IP should not exist before allocation")
	}

	// Allocate and check
	expectedFakeIP, err := manager.AllocateFakeIP(realIP)
	if err != nil {
		t.Fatalf("Failed to allocate: %v", err)
	}

	fakeIP, exists := manager.GetFakeIP(realIP)
	if !exists {
		t.Error("Fake IP should exist after allocation")
	}

	if fakeIP.Compare(expectedFakeIP) != 0 {
		t.Errorf("Expected %s, got %s", expectedFakeIP.String(), fakeIP.String())
	}
}

func TestMultipleAllocations(t *testing.T) {
	manager := NewManager()

	allocations := make(map[netip.Addr]netip.Addr)

	// Allocate multiple IPs
	for i := 1; i <= 100; i++ {
		realIP := netip.AddrFrom4([4]byte{10, 0, byte(i / 256), byte(i % 256)})
		fakeIP, err := manager.AllocateFakeIP(realIP)
		if err != nil {
			t.Fatalf("Failed to allocate fake IP for %s: %v", realIP.String(), err)
		}

		// Check for duplicates
		for _, existingFake := range allocations {
			if fakeIP.Compare(existingFake) == 0 {
				t.Errorf("Duplicate fake IP allocated: %s", fakeIP.String())
			}
		}

		allocations[realIP] = fakeIP
	}

	// Verify all allocations can be retrieved
	for realIP, expectedFake := range allocations {
		actualFake, exists := manager.GetFakeIP(realIP)
		if !exists {
			t.Errorf("Missing allocation for %s", realIP.String())
		}
		if actualFake.Compare(expectedFake) != 0 {
			t.Errorf("Mismatch for %s: expected %s, got %s", realIP.String(), expectedFake.String(), actualFake.String())
		}
	}
}

func TestGetFakeIPBlock(t *testing.T) {
	manager := NewManager()
	block := manager.GetFakeIPBlock()

	expected := "240.0.0.0/8"
	if block.String() != expected {
		t.Errorf("Expected %s, got %s", expected, block.String())
	}
}

func TestConcurrentAccess(t *testing.T) {
	manager := NewManager()

	const numGoroutines = 50
	const allocationsPerGoroutine = 10

	var wg sync.WaitGroup
	results := make(chan netip.Addr, numGoroutines*allocationsPerGoroutine)

	// Concurrent allocations
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for j := 0; j < allocationsPerGoroutine; j++ {
				realIP := netip.AddrFrom4([4]byte{192, 168, byte(goroutineID), byte(j)})
				fakeIP, err := manager.AllocateFakeIP(realIP)
				if err != nil {
					t.Errorf("Failed to allocate in goroutine %d: %v", goroutineID, err)
					return
				}
				results <- fakeIP
			}
		}(i)
	}

	wg.Wait()
	close(results)

	// Check for duplicates
	seen := make(map[netip.Addr]bool)
	count := 0
	for fakeIP := range results {
		if seen[fakeIP] {
			t.Errorf("Duplicate fake IP in concurrent test: %s", fakeIP.String())
		}
		seen[fakeIP] = true
		count++
	}

	if count != numGoroutines*allocationsPerGoroutine {
		t.Errorf("Expected %d allocations, got %d", numGoroutines*allocationsPerGoroutine, count)
	}
}

func TestIPExhaustion(t *testing.T) {
	// Create a manager with limited range for testing
	manager := &Manager{
		nextIP:     netip.AddrFrom4([4]byte{240, 0, 0, 1}),
		allocated:  make(map[netip.Addr]netip.Addr),
		fakeToReal: make(map[netip.Addr]netip.Addr),
		baseIP:     netip.AddrFrom4([4]byte{240, 0, 0, 1}),
		maxIP:      netip.AddrFrom4([4]byte{240, 0, 0, 3}), // Only 3 IPs available
	}

	// Allocate all available IPs
	realIPs := []netip.Addr{
		netip.MustParseAddr("1.0.0.1"),
		netip.MustParseAddr("1.0.0.2"),
		netip.MustParseAddr("1.0.0.3"),
	}

	for _, realIP := range realIPs {
		_, err := manager.AllocateFakeIP(realIP)
		if err != nil {
			t.Fatalf("Failed to allocate fake IP: %v", err)
		}
	}

	// Try to allocate one more - should fail
	_, err := manager.AllocateFakeIP(netip.MustParseAddr("1.0.0.4"))
	if err == nil {
		t.Error("Expected exhaustion error")
	}
}

func TestWrapAround(t *testing.T) {
	// Create manager starting near the end of range
	manager := &Manager{
		nextIP:     netip.AddrFrom4([4]byte{240, 0, 0, 254}),
		allocated:  make(map[netip.Addr]netip.Addr),
		fakeToReal: make(map[netip.Addr]netip.Addr),
		baseIP:     netip.AddrFrom4([4]byte{240, 0, 0, 1}),
		maxIP:      netip.AddrFrom4([4]byte{240, 0, 0, 254}),
	}

	// Allocate the last IP
	fakeIP1, err := manager.AllocateFakeIP(netip.MustParseAddr("1.0.0.1"))
	if err != nil {
		t.Fatalf("Failed to allocate first IP: %v", err)
	}

	if fakeIP1.String() != "240.0.0.254" {
		t.Errorf("Expected 240.0.0.254, got %s", fakeIP1.String())
	}

	// Next allocation should wrap around to the beginning
	fakeIP2, err := manager.AllocateFakeIP(netip.MustParseAddr("1.0.0.2"))
	if err != nil {
		t.Fatalf("Failed to allocate second IP: %v", err)
	}

	if fakeIP2.String() != "240.0.0.1" {
		t.Errorf("Expected 240.0.0.1 after wrap, got %s", fakeIP2.String())
	}
}
