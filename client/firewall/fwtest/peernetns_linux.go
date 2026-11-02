// Package fwtest holds helpers for the firewall backends' privileged tests.
package fwtest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

const (
	// HostAddr is the IPv6 address of the interface in the host namespace.
	HostAddr = "fd00::1"
	// PeerAddr is the IPv6 address of the sender in the peer namespace.
	PeerAddr = "fd00::2"
)

// PeerNamespace is a veth pair whose host end is named like the NetBird interface and whose
// other end sits in a namespace of its own, so traffic from the namespace arrives on an
// interface the firewall treats as the overlay.
type PeerNamespace struct {
	// IfaceName is the name of the host end.
	IfaceName string
	nsName    string
}

// NewPeerNamespace creates the namespace and the veth pair, and removes them when the test ends.
// Names are unique to the run so nothing that exists on the host is touched. The test is skipped
// when the ip tool is missing.
func NewPeerNamespace(t *testing.T) *PeerNamespace {
	t.Helper()

	if _, err := exec.LookPath("ip"); err != nil {
		t.Skipf("ip not available: %v", err)
	}

	suffix := make([]byte, 3)
	_, err := rand.Read(suffix)
	require.NoError(t, err, "generate name suffix")
	ns := &PeerNamespace{
		IfaceName: "wt-" + hex.EncodeToString(suffix),
		nsName:    "nbpeer-" + hex.EncodeToString(suffix),
	}

	run := func(args ...string) {
		t.Helper()
		out, err := exec.Command("ip", args...).CombinedOutput()
		require.NoError(t, err, "ip %v: %s", args, out)
	}

	run("netns", "add", ns.nsName)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", ns.nsName).Run() })

	run("link", "add", ns.IfaceName, "type", "veth", "peer", "name", "nbpeer0", "netns", ns.nsName)
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", ns.IfaceName).Run() })

	run("addr", "add", HostAddr+"/64", "dev", ns.IfaceName, "nodad")
	run("link", "set", ns.IfaceName, "up")
	run("-n", ns.nsName, "addr", "add", PeerAddr+"/64", "dev", "nbpeer0", "nodad")
	run("-n", ns.nsName, "link", "set", "nbpeer0", "up")
	run("-n", ns.nsName, "link", "set", "lo", "up")

	return ns
}

// Dial opens a TCP connection to addr from inside the namespace and returns the dial error.
func (ns *PeerNamespace) Dial(t *testing.T, addr string) error {
	t.Helper()

	result := make(chan error, 1)
	go func() {
		// The thread is never unlocked: it ends with the goroutine instead of being moved
		// back, so no other goroutine can run inside the namespace.
		runtime.LockOSThread()

		f, err := os.Open("/var/run/netns/" + ns.nsName)
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
		conn, err := d.DialContext(context.Background(), "tcp6", addr)
		if err == nil {
			_ = conn.Close()
		}
		result <- err
	}()
	return <-result
}

// ListenHost starts a TCP listener on the host end's address and returns its address.
func (ns *PeerNamespace) ListenHost(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp6", net.JoinHostPort(HostAddr, "0"))
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
	return ln.Addr().String()
}
