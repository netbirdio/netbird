//go:build linux && !android

package sharedsock

import (
	"net"
	"net/netip"
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
		src, err := p.resolve(loopback)
		require.NoError(t, err)
		assert.Equal(t, loopback, src, "source for loopback, round %d", i)

		src, err = p.resolve(remote)
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
	src, err := p.resolve(loopback)
	require.NoError(t, err)
	assert.Equal(t, loopback, src, "source for ::1")

	remote := netip.MustParseAddr("2001:db8::1")
	remoteSrc, ok := routeGetSrc(t, remote)
	if !ok {
		t.Skipf("no route to %s", remote)
	}
	src, err = p.resolve(remote)
	require.NoError(t, err)
	assert.Equal(t, remoteSrc, src, "source for %s", remote)
}

// A failed lookup must drop the socket so the next lookup starts from a fresh one.
func TestSrcProbe_ReopensAfterError(t *testing.T) {
	p := newTestProbe(t, unix.AF_INET)

	// Connecting to the limited broadcast address without SO_BROADCAST fails.
	_, err := p.resolve(netip.MustParseAddr("255.255.255.255"))
	require.Error(t, err, "lookup for the broadcast address should fail")
	assert.Nil(t, p.sock, "failed lookup should close the probe socket")

	src, err := p.resolve(netip.MustParseAddr("127.0.0.1"))
	require.NoError(t, err)
	assert.Equal(t, netip.MustParseAddr("127.0.0.1"), src, "source after reopening")
	assert.NotNil(t, p.sock, "probe socket should be open again")
}

func TestSrcProbe_ClosedRejectsLookups(t *testing.T) {
	p, err := newSrcProbe(unix.AF_INET)
	require.NoError(t, err)
	require.NoError(t, p.close())
	require.NoError(t, p.close(), "close must be idempotent")

	_, err = p.resolve(netip.MustParseAddr("127.0.0.1"))
	assert.ErrorIs(t, err, errProbeClosed)
	assert.Nil(t, p.sock, "closed probe must not reopen")
}

func BenchmarkSrcProbe(b *testing.B) {
	p, err := newSrcProbe(unix.AF_INET)
	require.NoError(b, err)
	defer p.close()

	dst := netip.MustParseAddr("192.0.2.1")
	if _, err := p.resolve(dst); err != nil {
		b.Skipf("no route to %s: %v", dst, err)
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := p.resolve(dst); err != nil {
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

// Another component closing the probe's fd number and receiving it for its own
// socket must not have that socket disconnected or closed by the probe.
func TestSrcProbe_LeavesReusedFDAlone(t *testing.T) {
	p := newTestProbe(t, unix.AF_INET)
	num := p.sock.fd

	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = peer.Close() })
	peerAddr := peer.LocalAddr().(*net.UDPAddr)

	// Simulate the foreign close and reuse: the probe's number now refers to a
	// connected UDP socket that the probe did not open.
	foreign, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	require.NoError(t, err)
	sa := &unix.SockaddrInet4{Port: peerAddr.Port}
	copy(sa.Addr[:], peerAddr.IP.To4())
	require.NoError(t, unix.Connect(foreign, sa))
	require.NoError(t, unix.Dup3(foreign, num, unix.O_CLOEXEC))
	require.NoError(t, unix.Close(foreign))
	t.Cleanup(func() { _ = unix.Close(num) })

	src, err := p.resolve(netip.MustParseAddr("127.0.0.1"))
	require.NoError(t, err)
	assert.Equal(t, netip.MustParseAddr("127.0.0.1"), src, "source after replacing the probe socket")

	remote, err := unix.Getpeername(num)
	require.NoError(t, err, "foreign socket must stay open and connected")
	assert.Equal(t, peerAddr.Port, remote.(*unix.SockaddrInet4).Port, "foreign socket peer")
}

// A probe fd closed elsewhere is replaced without failing the lookup.
func TestSrcProbe_RecoversFromForeignClose(t *testing.T) {
	p := newTestProbe(t, unix.AF_INET)
	require.NoError(t, unix.Close(p.sock.fd))

	src, err := p.resolve(netip.MustParseAddr("127.0.0.1"))
	require.NoError(t, err)
	assert.Equal(t, netip.MustParseAddr("127.0.0.1"), src, "source after the probe socket was closed elsewhere")
}
