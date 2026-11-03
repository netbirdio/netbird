//go:build privileged

package nftables

import (
	"net/netip"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/netbirdio/netbird/client/firewall/fwtest"
	fw "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

// setDestOpts adds a Destination Options header to every packet of the socket: next header
// (the kernel fills it in), length 0 and one PadN option.
func setDestOpts(_, _ string, c syscall.RawConn) error {
	opts := string([]byte{0, 0, 1, 4, 0, 0, 0, 0})
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = unix.SetsockoptString(int(fd), unix.IPPROTO_IPV6, unix.IPV6_DSTOPTS, opts)
	}); err != nil {
		return err
	}
	return serr
}

// A drop rule for a protocol must also match packets that carry IPv6 extension headers.
// With a wider accept behind it, a protocol match that only looks at the fixed header's
// Next Header field lets such a packet fall through to the accept.
//
// The peer rules only see traffic arriving on the NetBird interface, so the test puts a
// veth named like it in the host namespace and sends from a second namespace.
func TestNftablesManagerPeerDropMatchesBehindExtensionHeader(t *testing.T) {
	if check() != NFTABLES {
		t.Skip("nftables not supported on this system")
	}

	ns := fwtest.NewPeerNamespace(t)
	hostAddr := netip.MustParseAddr(ns.HostAddr)

	mock := &iFaceMock{
		NameFunc: func() string { return ns.IfaceName },
		AddressFunc: func() wgaddr.Address {
			return wgaddr.Address{
				IP:      netip.MustParseAddr("100.96.0.1"),
				Network: netip.MustParsePrefix("100.96.0.0/16"),
				IPv6:    hostAddr,
				IPv6Net: netip.PrefixFrom(hostAddr, 64).Masked(),
			}
		},
	}
	manager, err := Create(mock, iface.DefaultMTU)
	require.NoError(t, err, "create manager")
	require.NoError(t, manager.Init(nil))
	t.Cleanup(func() { assert.NoError(t, manager.Close(nil), "close manager") })

	addr := ns.ListenHost(t)
	port := netip.MustParseAddrPort(addr).Port()

	src := []netip.Prefix{netip.PrefixFrom(netip.MustParseAddr(ns.PeerAddr), 128)}
	_, err = manager.AddFilterRule(nil, src, fw.Network{}, fw.ProtocolALL, nil, nil, fw.ActionAccept)
	require.NoError(t, err, "add accept rule")
	require.NoError(t, manager.Flush())

	ns.WaitDial(t, addr, "control: plain connection with only the accept rule")
	require.NoError(t, ns.DialControl(addr, setDestOpts), "control: connection with a Destination Options header with only the accept rule")

	_, err = manager.AddFilterRule(nil, src, fw.Network{}, fw.ProtocolTCP, nil, &fw.Port{Values: []uint16{port}}, fw.ActionDrop)
	require.NoError(t, err, "add drop rule")
	require.NoError(t, manager.Flush())

	assert.Error(t, ns.Dial(addr), "plain connection must be dropped")
	assert.Error(t, ns.DialControl(addr, setDestOpts), "connection behind an extension header must be dropped too")
}
