package android

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"testing"
)

// fakeDial records the addresses dialed and fails for those in failing.
type fakeDial struct {
	dialed  []string
	failing map[string]bool
}

func (f *fakeDial) dial(_ context.Context, _, address string) (net.Conn, error) {
	f.dialed = append(f.dialed, address)
	if f.failing[address] {
		return nil, errors.New("unreachable")
	}
	c, s := net.Pipe()
	_ = s.Close()
	return c, nil
}

func newTestResolver(f *fakeDial, servers ...string) *hostResolver {
	r := newHostResolver()
	r.dialContext = f.dial
	list := make([]netip.AddrPort, 0, len(servers))
	for _, s := range servers {
		list = append(list, netip.MustParseAddrPort(s))
	}
	r.set(list)
	return r
}

func TestHostResolverFallsBackWhenEmpty(t *testing.T) {
	r := newHostResolver()
	if got := r.current(); !slices.Equal(got, fallbackDNS) {
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
	f := &fakeDial{}
	r := newTestResolver(f, "192.168.10.1:53")
	conn, err := r.dial(context.Background(), "udp", "203.0.113.9:53")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.Close()
	if want := []string{"192.168.10.1:53"}; !slices.Equal(f.dialed, want) {
		t.Fatalf("dialed %v, want %v", f.dialed, want)
	}
}

func TestHostResolverDialRotatesServers(t *testing.T) {
	f := &fakeDial{}
	r := newTestResolver(f, "192.168.10.1:53", "[2001:db8::1]:53")
	for i := 0; i < 3; i++ {
		conn, err := r.dial(context.Background(), "udp", "ignored:53")
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		_ = conn.Close()
	}
	want := []string{"192.168.10.1:53", "[2001:db8::1]:53", "192.168.10.1:53"}
	if !slices.Equal(f.dialed, want) {
		t.Fatalf("dialed %v, want %v", f.dialed, want)
	}
}

func TestHostResolverDialSkipsUnreachableServer(t *testing.T) {
	f := &fakeDial{failing: map[string]bool{"192.168.10.1:53": true}}
	r := newTestResolver(f, "192.168.10.1:53", "192.168.10.2:53")
	conn, err := r.dial(context.Background(), "udp", "ignored:53")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.Close()
	want := []string{"192.168.10.1:53", "192.168.10.2:53"}
	if !slices.Equal(f.dialed, want) {
		t.Fatalf("dialed %v, want %v", f.dialed, want)
	}
}

func TestHostResolverDialAllUnreachable(t *testing.T) {
	f := &fakeDial{failing: map[string]bool{"192.168.10.1:53": true, "192.168.10.2:53": true}}
	r := newTestResolver(f, "192.168.10.1:53", "192.168.10.2:53")
	if _, err := r.dial(context.Background(), "udp", "ignored:53"); err == nil {
		t.Fatal("dial succeeded, want error when every server fails")
	}
}
