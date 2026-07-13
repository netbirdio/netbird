package fakeip

import (
	"net/netip"
	"sync"
	"testing"
)

func TestNewManager(t *testing.T) {
	manager := NewManager()

	if manager.v4.baseIP.String() != "240.0.0.1" {
		t.Errorf("Expected v4 base IP 240.0.0.1, got %s", manager.v4.baseIP.String())
	}

	if manager.v4.maxIP.String() != "240.255.255.254" {
		t.Errorf("Expected v4 max IP 240.255.255.254, got %s", manager.v4.maxIP.String())
	}

	if manager.v6.baseIP.String() != "100::1" {
		t.Errorf("Expected v6 base IP 100::1, got %s", manager.v6.baseIP.String())
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

func TestAllocateFakeIPv6(t *testing.T) {
	manager := NewManager()
	realIP := netip.MustParseAddr("2001:db8::1")

	fakeIP, err := manager.AllocateFakeIP(realIP)
	if err != nil {
		t.Fatalf("Failed to allocate fake IPv6: %v", err)
	}

	if !fakeIP.Is6() {
		t.Error("Fake IP should be IPv6")
	}

	if !netip.MustParsePrefix("100::/64").Contains(fakeIP) {
		t.Errorf("Fake IP should be in 100::/64 range, got %s", fakeIP.String())
	}

	// Should return same fake IP for same real IP
	fakeIP2, err := manager.AllocateFakeIP(realIP)
	if err != nil {
		t.Fatalf("Failed to get existing fake IPv6: %v", err)
	}

	if fakeIP.Compare(fakeIP2) != 0 {
		t.Errorf("Expected same fake IP, got %s and %s", fakeIP.String(), fakeIP2.String())
	}
}

func TestGetFakeIP(t *testing.T) {
	manager := NewManager()
	realIP := netip.MustParseAddr("1.1.1.1")

	_, exists := manager.GetFakeIP(realIP)
	if exists {
		t.Error("Fake IP should not exist before allocation")
	}

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

func TestGetRealIPv6(t *testing.T) {
	manager := NewManager()
	realIP := netip.MustParseAddr("2001:db8::1")

	fakeIP, err := manager.AllocateFakeIP(realIP)
	if err != nil {
		t.Fatalf("Failed to allocate: %v", err)
	}

	gotReal, exists := manager.GetRealIP(fakeIP)
	if !exists {
		t.Error("Real IP should exist for allocated fake IP")
	}

	if gotReal.Compare(realIP) != 0 {
		t.Errorf("Expected real IP %s, got %s", realIP, gotReal)
	}
}

func TestMultipleAllocations(t *testing.T) {
	manager := NewManager()

	allocations := make(map[netip.Addr]netip.Addr)

	for i := 1; i <= 100; i++ {
		realIP := netip.AddrFrom4([4]byte{10, 0, byte(i / 256), byte(i % 256)})
		fakeIP, err := manager.AllocateFakeIP(realIP)
		if err != nil {
			t.Fatalf("Failed to allocate fake IP for %s: %v", realIP.String(), err)
		}

		for _, existingFake := range allocations {
			if fakeIP.Compare(existingFake) == 0 {
				t.Errorf("Duplicate fake IP allocated: %s", fakeIP.String())
			}
		}

		allocations[realIP] = fakeIP
	}

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

	if block := manager.GetFakeIPBlock(); block.String() != "240.0.0.0/8" {
		t.Errorf("Expected 240.0.0.0/8, got %s", block.String())
	}

	if block := manager.GetFakeIPv6Block(); block.String() != "100::/64" {
		t.Errorf("Expected 100::/64, got %s", block.String())
	}
}

func TestConcurrentAccess(t *testing.T) {
	manager := NewManager()

	const numGoroutines = 50
	const allocationsPerGoroutine = 10

	var wg sync.WaitGroup
	results := make(chan netip.Addr, numGoroutines*allocationsPerGoroutine)

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
	manager := &Manager{
		v4: newPool(
			netip.AddrFrom4([4]byte{240, 0, 0, 1}),
			netip.AddrFrom4([4]byte{240, 0, 0, 3}),
			netip.MustParsePrefix("240.0.0.0/8"),
		),
		v6: newPool(
			netip.MustParseAddr("100::1"),
			netip.MustParseAddr("100::3"),
			netip.MustParsePrefix("100::/64"),
		),
	}

	for _, realIP := range []string{"1.0.0.1", "1.0.0.2", "1.0.0.3"} {
		_, err := manager.AllocateFakeIP(netip.MustParseAddr(realIP))
		if err != nil {
			t.Fatalf("Failed to allocate fake IP: %v", err)
		}
	}

	_, err := manager.AllocateFakeIP(netip.MustParseAddr("1.0.0.4"))
	if err == nil {
		t.Error("Expected v4 exhaustion error")
	}

	// Same for v6
	for _, realIP := range []string{"2001:db8::1", "2001:db8::2", "2001:db8::3"} {
		_, err := manager.AllocateFakeIP(netip.MustParseAddr(realIP))
		if err != nil {
			t.Fatalf("Failed to allocate fake IPv6: %v", err)
		}
	}

	_, err = manager.AllocateFakeIP(netip.MustParseAddr("2001:db8::4"))
	if err == nil {
		t.Error("Expected v6 exhaustion error")
	}
}

func TestWrapAround(t *testing.T) {
	manager := &Manager{
		v4: newPool(
			netip.AddrFrom4([4]byte{240, 0, 0, 1}),
			netip.AddrFrom4([4]byte{240, 0, 0, 254}),
			netip.MustParsePrefix("240.0.0.0/8"),
		),
		v6: newPool(
			netip.MustParseAddr("100::1"),
			netip.MustParseAddr("100::ffff:ffff:ffff:fffe"),
			netip.MustParsePrefix("100::/64"),
		),
	}
	// Start near the end
	manager.v4.nextIP = netip.AddrFrom4([4]byte{240, 0, 0, 254})

	fakeIP1, err := manager.AllocateFakeIP(netip.MustParseAddr("1.0.0.1"))
	if err != nil {
		t.Fatalf("Failed to allocate first IP: %v", err)
	}

	if fakeIP1.String() != "240.0.0.254" {
		t.Errorf("Expected 240.0.0.254, got %s", fakeIP1.String())
	}

	fakeIP2, err := manager.AllocateFakeIP(netip.MustParseAddr("1.0.0.2"))
	if err != nil {
		t.Fatalf("Failed to allocate second IP: %v", err)
	}

	if fakeIP2.String() != "240.0.0.1" {
		t.Errorf("Expected 240.0.0.1 after wrap, got %s", fakeIP2.String())
	}
}

func TestMixedV4V6(t *testing.T) {
	manager := NewManager()

	v4Fake, err := manager.AllocateFakeIP(netip.MustParseAddr("8.8.8.8"))
	if err != nil {
		t.Fatalf("Failed to allocate v4: %v", err)
	}

	v6Fake, err := manager.AllocateFakeIP(netip.MustParseAddr("2001:db8::1"))
	if err != nil {
		t.Fatalf("Failed to allocate v6: %v", err)
	}

	if !v4Fake.Is4() || !v6Fake.Is6() {
		t.Errorf("Wrong families: v4=%s v6=%s", v4Fake, v6Fake)
	}

	// Reverse lookups should work for both
	gotV4, ok := manager.GetRealIP(v4Fake)
	if !ok || gotV4.String() != "8.8.8.8" {
		t.Errorf("v4 reverse lookup failed: got %s, ok=%v", gotV4, ok)
	}

	gotV6, ok := manager.GetRealIP(v6Fake)
	if !ok || gotV6.String() != "2001:db8::1" {
		t.Errorf("v6 reverse lookup failed: got %s, ok=%v", gotV6, ok)
	}
}
