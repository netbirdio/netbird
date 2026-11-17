//go:build linux && !android

package sharedsock

import (
	"net"
	"net/netip"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// routeGetSrc is the kernel's answer through netlink, used as the reference.
func routeGetSrc(t *testing.T, dst netip.Addr) (netip.Addr, bool) {
	t.Helper()
	routes, err := netlink.RouteGet(net.IP(dst.AsSlice()))
	if err != nil {
		return netip.Addr{}, false
	}
	for _, r := range routes {
		if src, ok := netip.AddrFromSlice(r.Src); ok {
			return src.Unmap(), true
		}
	}
	return netip.Addr{}, false
}

func newTestProbe(t *testing.T, family int) *srcProbe {
	t.Helper()
	p, err := newSrcProbe(family)
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.close() })
	return p
}

// A reused UDP socket keeps the source address of its first connect. Alternating
// between a loopback and an off-host destination catches a probe that forgets to
// disconnect: the second lookup would report 127.0.0.1 for the off-host address.
func TestSrcProbe_AlternatingDestinationsMatchRouteGet(t *testing.T) {
	loopback := netip.MustParseAddr("127.0.0.1")
	remote := netip.MustParseAddr("192.0.2.1")

	remoteSrc, ok := routeGetSrc(t, remote)
	if !ok {
		t.Skip("no route to an off-host IPv4 destination")
	}
	require.NotEqual(t, loopback, remoteSrc, "off-host destination must not route via loopback")

	p := newTestProbe(t, unix.AF_INET)
	for i := 0; i < 3; i++ {
		src, err := p.resolve(rawSockaddr(loopback, 0))
		require.NoError(t, err)
		assert.Equal(t, loopback, src, "source for loopback, round %d", i)

		src, err = p.resolve(rawSockaddr(remote, 0))
		require.NoError(t, err)
		assert.Equal(t, remoteSrc, src, "source for %s, round %d", remote, i)
	}
}

func TestSrcProbe_IPv6(t *testing.T) {
	loopback := netip.MustParseAddr("::1")
	if _, ok := routeGetSrc(t, loopback); !ok {
		t.Skip("no IPv6 loopback")
	}

	p := newTestProbe(t, unix.AF_INET6)
	src, err := p.resolve(rawSockaddr(loopback, 0))
	require.NoError(t, err)
	assert.Equal(t, loopback, src, "source for ::1")

	remote := netip.MustParseAddr("2001:db8::1")
	remoteSrc, ok := routeGetSrc(t, remote)
	if !ok {
		t.Skipf("no route to %s", remote)
	}
	src, err = p.resolve(rawSockaddr(remote, 0))
	require.NoError(t, err)
	assert.Equal(t, remoteSrc, src, "source for %s", remote)
}

// A route the kernel refuses is an answer, not a broken socket, so the probe keeps
// its socket and the next lookup reuses it.
func TestSrcProbe_RouteErrorKeepsSocket(t *testing.T) {
	p := newTestProbe(t, unix.AF_INET)
	conn := p.conn

	// Connecting to the limited broadcast address without SO_BROADCAST fails.
	_, err := p.resolve(rawSockaddr(netip.MustParseAddr("255.255.255.255"), 0))
	var rErr *routeError
	require.ErrorAs(t, err, &rErr, "lookup for the broadcast address should fail as a route error")
	assert.Same(t, conn, p.conn, "route error should keep the probe socket")

	src, err := p.resolve(rawSockaddr(netip.MustParseAddr("127.0.0.1"), 0))
	require.NoError(t, err)
	assert.Equal(t, netip.MustParseAddr("127.0.0.1"), src, "source after the route error")
	assert.Same(t, conn, p.conn, "lookup after a route error should reuse the socket")
}

// A socket that stops working is dropped, and the next lookup opens a fresh one.
func TestSrcProbe_ReopensAfterSocketError(t *testing.T) {
	p := newTestProbe(t, unix.AF_INET)
	require.NoError(t, p.conn.Close())

	_, err := p.resolve(rawSockaddr(netip.MustParseAddr("127.0.0.1"), 0))
	require.Error(t, err, "lookup on a closed socket should fail")
	assert.Nil(t, p.conn, "socket error should drop the probe socket")

	src, err := p.resolve(rawSockaddr(netip.MustParseAddr("127.0.0.1"), 0))
	require.NoError(t, err)
	assert.Equal(t, netip.MustParseAddr("127.0.0.1"), src, "source after reopening")
	assert.NotNil(t, p.conn, "probe socket should be open again")
}

// A link-local destination is only routable with its scope. The probe must pass the
// scope to the kernel and get the interface's own link-local address back.
func TestSrcProbe_LinkLocalWithZone(t *testing.T) {
	iface, want := linkLocalInterface(t)
	dst := netip.MustParseAddr("fe80::1")

	p := newTestProbe(t, unix.AF_INET6)
	rc, err := p.conn.SyscallConn()
	require.NoError(t, err)

	for _, zone := range []string{iface.Name, strconv.Itoa(iface.Index)} {
		scope, err := zoneIndex(rc, zone)
		require.NoError(t, err, "zone %q", zone)
		assert.Equal(t, uint32(iface.Index), scope, "index for zone %q", zone)

		src, err := p.resolve(rawSockaddr(dst.WithZone(zone), scope))
		require.NoError(t, err, "zone %q", zone)
		assert.Equal(t, want, src, "source for %s%%%s", dst, zone)
	}

	_, err = p.resolve(rawSockaddr(dst, 0))
	var rErr *routeError
	assert.ErrorAs(t, err, &rErr, "link-local destination without a scope should fail as a route error")
}

func TestZoneIndex(t *testing.T) {
	p := newTestProbe(t, unix.AF_INET6)
	rc, err := p.conn.SyscallConn()
	require.NoError(t, err)

	scope, err := zoneIndex(rc, "")
	require.NoError(t, err)
	assert.Zero(t, scope, "empty zone should be index 0")

	_, err = zoneIndex(rc, "nb-no-such-if0")
	assert.Error(t, err, "unknown interface name should fail")
}

// linkLocalInterface returns an up interface and its IPv6 link-local address.
func linkLocalInterface(t *testing.T) (net.Interface, netip.Addr) {
	t.Helper()
	ifaces, err := net.Interfaces()
	require.NoError(t, err)
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			prefix, err := netip.ParsePrefix(a.String())
			if err == nil && prefix.Addr().IsLinkLocalUnicast() {
				return iface, prefix.Addr()
			}
		}
	}
	t.Skip("no interface with an IPv6 link-local address")
	return net.Interface{}, netip.Addr{}
}

func TestSrcProbe_ClosedRejectsLookups(t *testing.T) {
	p, err := newSrcProbe(unix.AF_INET)
	require.NoError(t, err)
	require.NoError(t, p.close())
	require.NoError(t, p.close(), "close must be idempotent")

	_, err = p.resolve(rawSockaddr(netip.MustParseAddr("127.0.0.1"), 0))
	assert.ErrorIs(t, err, errProbeClosed)
	assert.Nil(t, p.conn, "closed probe must not reopen")
}

func BenchmarkSrcProbe(b *testing.B) {
	p, err := newSrcProbe(unix.AF_INET)
	require.NoError(b, err)
	defer p.close()

	dst := netip.MustParseAddr("192.0.2.1")
	if _, err := p.resolve(rawSockaddr(dst, 0)); err != nil {
		b.Skipf("no route to %s: %v", dst, err)
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := p.resolve(rawSockaddr(dst, 0)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSrcRouteGet(b *testing.B) {
	dst := net.ParseIP("192.0.2.1")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := netlink.RouteGetWithOptions(dst, &netlink.RouteGetOptions{}); err != nil {
			b.Skipf("no route to %s: %v", dst, err)
		}
	}
}
