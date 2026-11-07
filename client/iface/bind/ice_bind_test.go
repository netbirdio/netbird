package bind

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/transport/v3"
	"github.com/pion/transport/v3/stdnet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/iface/wgbackend"
)

func TestICEBind_CreatesReceiverForBothIPv4AndIPv6(t *testing.T) {
	iceBind := setupICEBind(t)

	ipv4Conn, ipv6Conn := createDualStackConns(t)
	defer ipv4Conn.Close()
	defer ipv6Conn.Close()

	rc := receiverCreator{iceBind}
	pool := createMsgPool()

	// Simulate wireguard-go calling CreateReceiverFn for IPv4
	ipv4RecvFn := rc.CreateReceiverFn(ipv4.NewPacketConn(ipv4Conn), ipv4Conn, false, pool)
	require.NotNil(t, ipv4RecvFn)

	iceBind.muUDPMux.Lock()
	assert.NotNil(t, iceBind.ipv4Conn, "should store IPv4 connection")
	assert.Nil(t, iceBind.ipv6Conn, "IPv6 not added yet")
	assert.NotNil(t, iceBind.udpMux, "mux should be created after first connection")
	iceBind.muUDPMux.Unlock()

	// Simulate wireguard-go calling CreateReceiverFn for IPv6
	ipv6RecvFn := rc.CreateReceiverFn(ipv6.NewPacketConn(ipv6Conn), ipv6Conn, false, pool)
	require.NotNil(t, ipv6RecvFn)

	iceBind.muUDPMux.Lock()
	assert.NotNil(t, iceBind.ipv4Conn, "should still have IPv4 connection")
	assert.NotNil(t, iceBind.ipv6Conn, "should now have IPv6 connection")
	assert.NotNil(t, iceBind.udpMux, "mux should still exist")
	iceBind.muUDPMux.Unlock()

	mux, err := iceBind.GetICEMux()
	require.NoError(t, err)
	require.NotNil(t, mux)
}

func TestICEBind_WorksWithIPv4Only(t *testing.T) {
	iceBind := setupICEBind(t)

	ipv4Conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	require.NoError(t, err)
	defer ipv4Conn.Close()

	rc := receiverCreator{iceBind}
	recvFn := rc.CreateReceiverFn(ipv4.NewPacketConn(ipv4Conn), ipv4Conn, false, createMsgPool())
	require.NotNil(t, recvFn)

	iceBind.muUDPMux.Lock()
	assert.NotNil(t, iceBind.ipv4Conn)
	assert.Nil(t, iceBind.ipv6Conn)
	assert.NotNil(t, iceBind.udpMux)
	iceBind.muUDPMux.Unlock()

	mux, err := iceBind.GetICEMux()
	require.NoError(t, err)
	require.NotNil(t, mux)
}

func TestICEBind_WorksWithIPv6Only(t *testing.T) {
	iceBind := setupICEBind(t)

	ipv6Conn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6zero, Port: 0})
	if err != nil {
		t.Skipf("IPv6 not available: %v", err)
	}
	defer ipv6Conn.Close()

	rc := receiverCreator{iceBind}
	recvFn := rc.CreateReceiverFn(ipv6.NewPacketConn(ipv6Conn), ipv6Conn, false, createMsgPool())
	require.NotNil(t, recvFn)

	iceBind.muUDPMux.Lock()
	assert.Nil(t, iceBind.ipv4Conn)
	assert.NotNil(t, iceBind.ipv6Conn)
	assert.NotNil(t, iceBind.udpMux)
	iceBind.muUDPMux.Unlock()

	mux, err := iceBind.GetICEMux()
	require.NoError(t, err)
	require.NotNil(t, mux)
}

// TestICEBind_SendsToIPv4AndIPv6PeersSimultaneously verifies that we can communicate
// with peers on different address families through the same DualStackPacketConn.
func TestICEBind_SendsToIPv4AndIPv6PeersSimultaneously(t *testing.T) {
	// two "remote peers" listening on different address families
	ipv4Peer := listenUDP(t, "udp4", "127.0.0.1:0")
	defer ipv4Peer.Close()

	ipv6Peer, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		t.Skipf("IPv6 not available: %v", err)
	}
	defer ipv6Peer.Close()

	// our local dual-stack connection
	ipv4Local := listenUDP(t, "udp4", "127.0.0.1:0")
	defer ipv4Local.Close()

	ipv6Local := listenUDP(t, "udp6", "[::1]:0")
	defer ipv6Local.Close()

	dualStack := NewDualStackPacketConn(ipv4Local, ipv6Local)

	// send to both peers
	_, err = dualStack.WriteTo([]byte("to-ipv4"), ipv4Peer.LocalAddr())
	require.NoError(t, err)

	_, err = dualStack.WriteTo([]byte("to-ipv6"), ipv6Peer.LocalAddr())
	require.NoError(t, err)

	// verify IPv4 peer got its packet from the IPv4 socket
	buf := make([]byte, 100)
	_ = ipv4Peer.SetReadDeadline(time.Now().Add(time.Second))
	n, addr, err := ipv4Peer.ReadFrom(buf)
	require.NoError(t, err)
	assert.Equal(t, "to-ipv4", string(buf[:n]))
	assert.Equal(t, ipv4Local.LocalAddr().(*net.UDPAddr).Port, addr.(*net.UDPAddr).Port)

	// verify IPv6 peer got its packet from the IPv6 socket
	_ = ipv6Peer.SetReadDeadline(time.Now().Add(time.Second))
	n, addr, err = ipv6Peer.ReadFrom(buf)
	require.NoError(t, err)
	assert.Equal(t, "to-ipv6", string(buf[:n]))
	assert.Equal(t, ipv6Local.LocalAddr().(*net.UDPAddr).Port, addr.(*net.UDPAddr).Port)
}

// TestICEBind_HandlesConcurrentMixedTraffic checks concurrent IPv4 and IPv6 writes
// through the same connection without overflowing either peer's receive buffer.
func TestICEBind_HandlesConcurrentMixedTraffic(t *testing.T) {
	ipv4Peer := listenUDP(t, "udp4", "127.0.0.1:0")
	defer ipv4Peer.Close()

	ipv6Peer, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		t.Skipf("IPv6 not available: %v", err)
	}
	defer ipv6Peer.Close()

	ipv4Local := listenUDP(t, "udp4", "127.0.0.1:0")
	defer ipv4Local.Close()

	ipv6Local := listenUDP(t, "udp6", "[::1]:0")
	defer ipv6Local.Close()

	dualStack := NewDualStackPacketConn(ipv4Local, ipv6Local)
	deadline := time.Now().Add(5 * time.Second)
	require.NoError(t, ipv4Peer.SetReadDeadline(deadline))
	require.NoError(t, ipv6Peer.SetReadDeadline(deadline))

	const packetsPerFamily = 500
	startGate := make(chan struct{})
	exchange := func(prefix string, peer *net.UDPConn) error {
		<-startGate
		buf := make([]byte, 100)
		for i := 0; i < packetsPerFamily; i++ {
			packet := fmt.Sprintf("%s-%04d", prefix, i)
			n, err := dualStack.WriteTo([]byte(packet), peer.LocalAddr())
			if err != nil {
				return fmt.Errorf("%s send packet %d: %w", prefix, i, err)
			}
			if n != len(packet) {
				return fmt.Errorf("%s send packet %d: wrote %d of %d bytes", prefix, i, n, len(packet))
			}

			// Receive each packet before sending another on this family. Both
			// families still write concurrently, without an unbounded UDP burst.
			n, _, err = peer.ReadFrom(buf)
			if err != nil {
				return fmt.Errorf("%s receive packet %d: %w", prefix, i, err)
			}
			if got := string(buf[:n]); got != packet {
				return fmt.Errorf("%s receive packet %d: got %q, want %q", prefix, i, got, packet)
			}
		}
		return nil
	}

	results := make(chan error, 2)
	go func() { results <- exchange("v4", ipv4Peer) }()
	go func() { results <- exchange("v6", ipv6Peer) }()
	close(startGate)

	for range 2 {
		assert.NoError(t, <-results)
	}
}

func TestICEBind_DetectsAddressFamilyFromConnection(t *testing.T) {
	tests := []struct {
		name     string
		network  string
		addr     string
		wantIPv4 bool
	}{
		{"IPv4 any", "udp4", "0.0.0.0:0", true},
		{"IPv4 loopback", "udp4", "127.0.0.1:0", true},
		{"IPv6 any", "udp6", "[::]:0", false},
		{"IPv6 loopback", "udp6", "[::1]:0", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, err := net.ResolveUDPAddr(tt.network, tt.addr)
			require.NoError(t, err)

			conn, err := net.ListenUDP(tt.network, addr)
			if err != nil {
				t.Skipf("%s not available: %v", tt.network, err)
			}
			defer conn.Close()

			localAddr := conn.LocalAddr().(*net.UDPAddr)
			isIPv4 := localAddr.IP.To4() != nil
			assert.Equal(t, tt.wantIPv4, isIPv4)
		})
	}
}

// helpers

func setupICEBind(t *testing.T) *ICEBind {
	t.Helper()
	transportNet, err := stdnet.NewNet()
	require.NoError(t, err)

	address := wgaddr.Address{
		IP:      netip.MustParseAddr("100.64.0.1"),
		Network: netip.MustParsePrefix("100.64.0.0/10"),
	}
	return NewICEBind(transportNet, address, 1280)
}

func createDualStackConns(t *testing.T) (*net.UDPConn, *net.UDPConn) {
	t.Helper()
	ipv4Conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	require.NoError(t, err)

	ipv6Conn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6zero, Port: 0})
	if err != nil {
		ipv4Conn.Close()
		t.Skipf("IPv6 not available: %v", err)
	}
	return ipv4Conn, ipv6Conn
}

func createMsgPool() *sync.Pool {
	return &sync.Pool{
		New: func() any {
			msgs := make([]ipv6.Message, 1)
			for i := range msgs {
				msgs[i].Buffers = make(net.Buffers, 1)
				msgs[i].OOB = make([]byte, 0, 40)
			}
			return &msgs
		},
	}
}

func listenUDP(t *testing.T, network, addr string) *net.UDPConn {
	t.Helper()
	udpAddr, err := net.ResolveUDPAddr(network, addr)
	require.NoError(t, err)
	conn, err := net.ListenUDP(network, udpAddr)
	require.NoError(t, err)
	return conn
}

type countingNet struct {
	transport.Net
	calls  atomic.Int64
	ifaces []*transport.Interface
	before func()
}

func (n *countingNet) Interfaces() ([]*transport.Interface, error) {
	n.calls.Add(1)
	if n.before != nil {
		n.before()
	}
	return n.ifaces, nil
}

func TestICEBind_OpenDoesNotDiscoverInterfaces(t *testing.T) {
	n := newCountingNet()
	iceBind := NewICEBind(n, testAddress(), 1280)

	for i := 0; i < 2; i++ {
		_, port, err := iceBind.Open(0)
		require.NoError(t, err)
		require.NotZero(t, port, "the bind listens on a port")
		assert.Equal(t, int64(0), n.calls.Load(), "opening the bind must not enumerate interfaces, attempt %d", i+1)
		require.NoError(t, iceBind.Close())
	}

	_, _, err := iceBind.Open(0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = iceBind.Close() })

	mux, err := iceBind.GetICEMux()
	require.NoError(t, err)
	assert.NotEmpty(t, mux.SingleSocketUDPMux.GetListenAddresses(), "listen addresses come from the discovered interfaces")
	assert.Equal(t, int64(1), n.calls.Load(), "interfaces are discovered when the listen addresses are asked for")
}

func TestICEBind_DeviceUpDoesNotWaitOnInterfaceDiscovery(t *testing.T) {
	tunDev, _, err := wgbackend.CreateNetTUN([]netip.Addr{netip.MustParseAddr("100.64.0.1")}, nil, 1280)
	require.NoError(t, err)

	var dev *wgbackend.Device
	n := newCountingNet()
	n.before = func() {
		_ = dev.IpcGetOperation(io.Discard)
	}
	iceBind := NewICEBind(n, testAddress(), 1280)
	dev = wgbackend.NewDevice(tunDev, iceBind, wgbackend.NewLogger(wgbackend.LogLevelSilent, ""))

	upDone := make(chan error, 1)
	go func() {
		upDone <- dev.Up()
	}()

	select {
	case err := <-upDone:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("device Up did not return: interface discovery ran under the device lock and waited on the device itself")
	}
	t.Cleanup(dev.Close)

	assert.Equal(t, int64(0), n.calls.Load(), "bringing the device up must not enumerate interfaces")

	mux, err := iceBind.GetICEMux()
	require.NoError(t, err)
	assert.NotEmpty(t, mux.SingleSocketUDPMux.GetListenAddresses(), "discovery that talks to the device succeeds once the device is up")
	assert.Equal(t, int64(1), n.calls.Load(), "interfaces are discovered outside the device lock")
}

func newCountingNet() *countingNet {
	ifc := transport.NewInterface(net.Interface{Index: 1, MTU: 1500, Name: "eth0", Flags: net.FlagUp | net.FlagMulticast})
	ifc.AddAddress(&net.IPNet{IP: net.IPv4(192, 168, 1, 10), Mask: net.CIDRMask(24, 32)})
	return &countingNet{ifaces: []*transport.Interface{ifc}}
}

func testAddress() wgaddr.Address {
	return wgaddr.Address{
		IP:      netip.MustParseAddr("100.64.0.1"),
		Network: netip.MustParsePrefix("100.64.0.0/10"),
	}
}
