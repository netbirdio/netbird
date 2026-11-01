//go:build privileged

package nftables

import (
	"context"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	fw "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

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
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skipf("ip not available: %v", err)
	}
	seedIp6tables(t)

	const (
		ifaceName = "wt-test"
		nsName    = "nbpeer"
		hostAddr  = "fd00::1"
		peerAddr  = "fd00::2"
	)
	run := func(args ...string) {
		t.Helper()
		out, err := exec.Command("ip", args...).CombinedOutput()
		require.NoError(t, err, "ip %v: %s", args, out)
	}
	_ = exec.Command("ip", "netns", "del", nsName).Run()
	run("netns", "add", nsName)
	t.Cleanup(func() {
		_ = exec.Command("ip", "link", "del", ifaceName).Run()
		_ = exec.Command("ip", "netns", "del", nsName).Run()
	})
	run("link", "add", ifaceName, "type", "veth", "peer", "name", "nbpeer0", "netns", nsName)
	run("addr", "add", hostAddr+"/64", "dev", ifaceName, "nodad")
	run("link", "set", ifaceName, "up")
	run("-n", nsName, "addr", "add", peerAddr+"/64", "dev", "nbpeer0", "nodad")
	run("-n", nsName, "link", "set", "nbpeer0", "up")
	run("-n", nsName, "link", "set", "lo", "up")

	mock := &iFaceMock{
		NameFunc: func() string { return ifaceName },
		AddressFunc: func() wgaddr.Address {
			return wgaddr.Address{
				IP:      netip.MustParseAddr("100.96.0.1"),
				Network: netip.MustParsePrefix("100.96.0.0/16"),
				IPv6:    netip.MustParseAddr(hostAddr),
				IPv6Net: netip.MustParsePrefix("fd00::/64"),
			}
		},
	}
	manager, err := Create(mock, iface.DefaultMTU)
	require.NoError(t, err, "create manager")
	require.NoError(t, manager.Init(nil))
	t.Cleanup(func() { require.NoError(t, manager.Close(nil), "close manager") })

	ln, err := net.Listen("tcp6", net.JoinHostPort(hostAddr, "0"))
	require.NoError(t, err, "listen on the interface address")
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	src := []netip.Prefix{netip.MustParsePrefix(peerAddr + "/128")}
	_, err = manager.AddFilterRule(nil, src, fw.Network{}, fw.ProtocolALL, nil, nil, fw.ActionAccept)
	require.NoError(t, err, "add accept rule")
	require.NoError(t, manager.Flush())

	dial := func(extHeader bool) error {
		return dialInNetns(t, nsName, net.JoinHostPort(hostAddr, strconv.Itoa(int(port))), extHeader)
	}

	require.NoError(t, dial(false), "control: plain connection with only the accept rule")
	require.NoError(t, dial(true), "control: connection with a Destination Options header with only the accept rule")

	_, err = manager.AddFilterRule(nil, src, fw.Network{}, fw.ProtocolTCP, nil, &fw.Port{Values: []uint16{port}}, fw.ActionDrop)
	require.NoError(t, err, "add drop rule")
	require.NoError(t, manager.Flush())

	assert.Error(t, dial(false), "plain connection must be dropped")
	assert.Error(t, dial(true), "connection behind an extension header must be dropped too")
}

// dialInNetns opens a TCP connection to addr from inside the named network namespace.
func dialInNetns(t *testing.T, nsName, addr string, extHeader bool) error {
	t.Helper()

	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		// The thread is left locked and discarded with the goroutine instead of being
		// moved back, so no other goroutine can ever run inside the namespace.

		f, err := os.Open("/var/run/netns/" + nsName)
		if err != nil {
			result <- err
			return
		}
		defer f.Close()
		if err := unix.Setns(int(f.Fd()), unix.CLONE_NEWNET); err != nil {
			result <- err
			return
		}

		d := net.Dialer{Timeout: time.Second}
		if extHeader {
			// Destination Options header: next header (kernel fills it in), length 0, one PadN option.
			opts := string([]byte{0, 0, 1, 4, 0, 0, 0, 0})
			d.Control = func(_, _ string, c syscall.RawConn) error {
				var serr error
				if err := c.Control(func(fd uintptr) {
					serr = unix.SetsockoptString(int(fd), unix.IPPROTO_IPV6, unix.IPV6_DSTOPTS, opts)
				}); err != nil {
					return err
				}
				return serr
			}
		}
		conn, err := d.DialContext(context.Background(), "tcp6", addr)
		if err == nil {
			_ = conn.Close()
		}
		result <- err
	}()
	return <-result
}
