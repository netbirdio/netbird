package android

import (
	"context"
	"net/netip"
	"testing"
)

func TestHostResolverFallsBackWhenEmpty(t *testing.T) {
	r := newHostResolver()
	if got := r.current(); len(got) != len(fallbackDNS) || got[0] != fallbackDNS[0] {
		t.Fatalf("current() with no servers = %v, want fallback %v", got, fallbackDNS)
	}
}

func TestHostResolverSetFiltersInvalid(t *testing.T) {
	r := newHostResolver()
	r.set([]netip.AddrPort{
		netip.MustParseAddrPort("192.168.10.1:53"),
		netip.AddrPortFrom(netip.Addr{}, 53),
		netip.AddrPortFrom(netip.MustParseAddr("10.0.0.1"), 0),
	})
	got := r.current()
	if len(got) != 1 || got[0].String() != "192.168.10.1:53" {
		t.Fatalf("current() = %v, want only 192.168.10.1:53", got)
	}
}

func TestHostResolverDialIgnoresGivenAddress(t *testing.T) {
	r := newHostResolver()
	r.set([]netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:1")}) // closed port: udp connect still succeeds
	conn, err := r.dial(context.Background(), "udp", "203.0.113.9:53")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if conn.RemoteAddr().String() != "127.0.0.1:1" {
		t.Fatalf("dialed %s, want the configured host DNS server", conn.RemoteAddr())
	}
}
