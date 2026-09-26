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
	inUse := func(candidate netip.Addr) bool { return taken[candidate] }
	alloc := func() netip.Addr {
		t.Helper()
		addr, err := a.next(inUse)
		if err != nil {
			t.Fatalf("allocate: %v", err)
		}
		taken[addr] = true
		return addr
	}

	first := alloc()
	second := alloc()
	delete(taken, first)

	// The cursor only moves forward, so a released address comes back after a
	// wrap. Park the cursor near the end of the range instead of allocating
	// 2^23 addresses: the next call takes the last usable address, and the one
	// after that wraps past the skipped .255 and .0 hosts to the released one.
	a.cursor = addrRangeSize - 3
	last := alloc()
	if want := netip.MustParseAddr("127.255.255.254"); last != want {
		t.Fatalf("expected the last usable address %s before the wrap, got %s", want, last)
	}

	if reused := alloc(); reused != first {
		t.Fatalf("expected the released address %s after the wrap, got %s", first, reused)
	}

	// second is still held, so the allocator must step over it.
	if next := alloc(); next == second {
		t.Fatalf("allocator handed out %s while it was still in use", second)
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
