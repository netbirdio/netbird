// Package fwtest holds helpers for the firewall backends' privileged tests.
package fwtest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// PeerNamespace is a veth pair whose host end is named like the NetBird interface and whose
// other end sits in a network namespace of its own, so traffic from the namespace arrives on
// an interface the firewall treats as the overlay.
//
// The namespace belongs to a locked OS thread. It is gone, with the peer end of the veth, when
// that thread ends at the end of the test, so nothing outlives the test.
type PeerNamespace struct {
	// IfaceName is the name of the host end.
	IfaceName string
	// HostAddr is the IPv6 address of the host end.
	HostAddr string
	// PeerAddr is the IPv6 address of the peer end.
	PeerAddr string

	jobs chan func()
}

type nsReady struct {
	nsFile *os.File
	err    error
}

// NewPeerNamespace creates the namespace and the veth pair, and removes them when the test
// ends. Names and addresses are unique to the run, so nothing that exists on the host is
// touched and concurrent runs do not collide.
func NewPeerNamespace(t *testing.T) *PeerNamespace {
	t.Helper()

	suffix := make([]byte, 3)
	_, err := rand.Read(suffix)
	require.NoError(t, err, "generate name suffix")
	name := hex.EncodeToString(suffix)

	ns := &PeerNamespace{
		IfaceName: "wt-" + name,
		HostAddr:  fmt.Sprintf("fd00:%x:%x::1", suffix[0], suffix[1:]),
		PeerAddr:  fmt.Sprintf("fd00:%x:%x::2", suffix[0], suffix[1:]),
		jobs:      make(chan func()),
	}
	peerName := "np-" + name

	ready := make(chan nsReady, 1)
	go ns.serve(ready)
	r := <-ready
	require.NoError(t, r.err, "create network namespace")
	defer r.nsFile.Close()
	t.Cleanup(func() { close(ns.jobs) })

	require.NoError(t, netlink.LinkAdd(&netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: ns.IfaceName},
		PeerName:  peerName,
	}), "create veth pair")
	t.Cleanup(func() {
		if link, err := netlink.LinkByName(ns.IfaceName); err == nil {
			_ = netlink.LinkDel(link)
		}
	})

	peer, err := netlink.LinkByName(peerName)
	require.NoError(t, err, "find peer end")
	require.NoError(t, netlink.LinkSetNsFd(peer, int(r.nsFile.Fd())), "move peer end into the namespace")

	require.NoError(t, configure(ns.IfaceName, ns.HostAddr), "configure host end")
	var peerErr error
	ns.do(func() {
		if peerErr = configure(peerName, ns.PeerAddr); peerErr != nil {
			return
		}
		peerErr = setUp("lo")
	})
	require.NoError(t, peerErr, "configure peer end")

	return ns
}

// serve runs on a thread of its own that is locked, moved into a new network namespace and
// never unlocked, so the thread ends with the goroutine instead of going back to the pool
// inside the namespace.
func (ns *PeerNamespace) serve(ready chan<- nsReady) {
	runtime.LockOSThread()

	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		ready <- nsReady{err: fmt.Errorf("unshare network namespace: %w", err)}
		return
	}
	f, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		ready <- nsReady{err: fmt.Errorf("open namespace: %w", err)}
		return
	}
	ready <- nsReady{nsFile: f}

	for job := range ns.jobs {
		job()
	}
}

// do runs fn inside the namespace and waits for it.
func (ns *PeerNamespace) do(fn func()) {
	done := make(chan struct{})
	ns.jobs <- func() {
		defer close(done)
		fn()
	}
	<-done
}

func configure(ifaceName, addr string) error {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("find %s: %w", ifaceName, err)
	}

	ip := net.ParseIP(addr)
	if ip == nil {
		return fmt.Errorf("parse %s", addr)
	}
	err = netlink.AddrAdd(link, &netlink.Addr{
		IPNet: &net.IPNet{IP: ip, Mask: net.CIDRMask(64, 128)},
		Flags: unix.IFA_F_NODAD,
	})
	if err != nil {
		return fmt.Errorf("add %s to %s: %w", addr, ifaceName, err)
	}
	return setUp(ifaceName)
}

func setUp(ifaceName string) error {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("find %s: %w", ifaceName, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("bring %s up: %w", ifaceName, err)
	}
	return nil
}

// Dial opens a TCP connection to addr from inside the namespace and returns the dial error.
func (ns *PeerNamespace) Dial(addr string) error {
	return ns.DialControl(addr, nil)
}

// DialControl is Dial with a control function that can set socket options before the
// connection is made.
func (ns *PeerNamespace) DialControl(addr string, control func(network, address string, c syscall.RawConn) error) error {
	var err error
	ns.do(func() {
		d := net.Dialer{Timeout: time.Second, Control: control}
		var conn net.Conn
		conn, err = d.DialContext(context.Background(), "tcp6", addr)
		if err == nil {
			_ = conn.Close()
		}
	})
	return err
}

// WaitDial waits for a connection to addr from the namespace to succeed. Right after the
// veth pair is created, and after a firewall that dropped the peer's neighbor discovery is
// removed, the first attempts can fail while the neighbor entry settles.
func (ns *PeerNamespace) WaitDial(t *testing.T, addr, msg string) {
	t.Helper()
	require.Eventually(t, func() bool { return ns.Dial(addr) == nil }, 10*time.Second, 200*time.Millisecond, msg)
}

// ListenHost starts a TCP listener on the host end's address and returns its address.
func (ns *PeerNamespace) ListenHost(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp6", net.JoinHostPort(ns.HostAddr, "0"))
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
