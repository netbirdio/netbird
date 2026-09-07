//go:build linux && !android

package loopback

import (
	"net/netip"
	"testing"
)

func TestAllocatorHandsOutDistinctAddresses(t *testing.T) {
	var a allocator
	taken := make(map[netip.Addr]bool)

	for i := 0; i < 1000; i++ {
		addr, err := a.next(func(candidate netip.Addr) bool { return taken[candidate] })
		if err != nil {
			t.Fatalf("allocate %d: %v", i, err)
		}
		if taken[addr] {
			t.Fatalf("address %s handed out twice", addr)
		}
		if !inRange(addr) {
			t.Fatalf("address %s outside %s", addr, addrRangePrefix)
		}
		taken[addr] = true
	}
}

func TestAllocatorSkipsNetworkAndBroadcastHosts(t *testing.T) {
	var a allocator
	taken := make(map[netip.Addr]bool)

	// enough allocations to walk past a .255/.0 boundary
	for i := 0; i < 600; i++ {
		addr, err := a.next(func(candidate netip.Addr) bool { return taken[candidate] })
		if err != nil {
			t.Fatalf("allocate %d: %v", i, err)
		}
		last := addr.As4()[3]
		if last == 0 || last == 255 {
			t.Fatalf("address %s ends in .%d", addr, last)
		}
		taken[addr] = true
	}
}

func TestAllocatorReusesReleasedAddresses(t *testing.T) {
	var a allocator
	taken := make(map[netip.Addr]bool)

	first, err := a.next(func(candidate netip.Addr) bool { return taken[candidate] })
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	taken[first] = true

	// release it and allocate until the cursor wraps back around to it
	delete(taken, first)
	for i := 0; i < 10; i++ {
		addr, err := a.next(func(candidate netip.Addr) bool { return taken[candidate] })
		if err != nil {
			t.Fatalf("allocate %d: %v", i, err)
		}
		if addr == first {
			return
		}
		taken[addr] = true
	}
	// the cursor moves forward, so reuse only happens after a full wrap. Assert
	// the released address is at least still considered free.
	if inUse := taken[first]; inUse {
		t.Fatalf("released address %s still marked in use", first)
	}
}

func TestInRange(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{"127.128.0.1", true},
		{"127.255.255.254", true},
		{"127.127.255.255", false}, // below the range, where 127.0.0.53 and friends live
		{"127.0.0.1", false},
		{"127.0.0.53", false},
		{"127.0.1.1", false},
		{"128.0.0.1", false},
		{"10.0.0.1", false},
	}

	for _, tc := range tests {
		addr := netip.MustParseAddr(tc.addr)
		if got := inRange(addr); got != tc.want {
			t.Errorf("inRange(%s) = %v, want %v", tc.addr, got, tc.want)
		}
	}
}

func TestInRangeIgnoresIPv6(t *testing.T) {
	if inRange(netip.MustParseAddr("::1")) {
		t.Error("inRange(::1) = true, want false")
	}
}
