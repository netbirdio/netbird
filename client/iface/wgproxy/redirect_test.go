//go:build linux && !android

package wgproxy

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/netbirdio/netbird/client/iface/wgproxy/ebpf"
	"github.com/netbirdio/netbird/client/iface/wgproxy/udp"
)

// compareUDPAddr compares two UDP addresses, ignoring IPv6 zone IDs
// IPv6 link-local addresses include zone IDs (e.g., fe80::1%lo) which we should ignore
func compareUDPAddr(addr1, addr2 net.Addr) bool {
	udpAddr1, ok1 := addr1.(*net.UDPAddr)
	udpAddr2, ok2 := addr2.(*net.UDPAddr)

	if !ok1 || !ok2 {
		return addr1.String() == addr2.String()
	}

	// Compare IP and Port, ignoring zone
	return udpAddr1.IP.Equal(udpAddr2.IP) && udpAddr1.Port == udpAddr2.Port
}

// TestRedirectAs_eBPF_IPv4 tests RedirectAs with eBPF proxy using IPv4 addresses
func TestRedirectAs_eBPF_IPv4(t *testing.T) {
	wgPort := 51850
	ebpfProxy := ebpf.NewWGEBPFProxy(wgPort, 1280)
	if err := ebpfProxy.Listen(); err != nil {
		t.Fatalf("failed to initialize ebpf proxy: %v", err)
	}
	defer func() {
		if err := ebpfProxy.Free(); err != nil {
			t.Errorf("failed to free ebpf proxy: %v", err)
		}
	}()

	proxy := ebpf.NewProxyWrapper(ebpfProxy)

	// NetBird UDP address of the remote peer
	nbAddr := &net.UDPAddr{
		IP:   net.ParseIP("100.108.111.177"),
		Port: 38746,
	}

	p2pEndpoint := &net.UDPAddr{
		IP:   net.ParseIP("192.168.0.56"),
		Port: 51820,
	}

	testRedirectAs(t, proxy, wgPort, nbAddr, p2pEndpoint)
}

// TestRedirectAs_eBPF_IPv6 tests RedirectAs with eBPF proxy using IPv6 addresses
func TestRedirectAs_eBPF_IPv6(t *testing.T) {
	wgPort := 51851
	ebpfProxy := ebpf.NewWGEBPFProxy(wgPort, 1280)
	if err := ebpfProxy.Listen(); err != nil {
		t.Fatalf("failed to initialize ebpf proxy: %v", err)
	}
	defer func() {
		if err := ebpfProxy.Free(); err != nil {
			t.Errorf("failed to free ebpf proxy: %v", err)
		}
	}()

	proxy := ebpf.NewProxyWrapper(ebpfProxy)

	// NetBird UDP address of the remote peer
	nbAddr := &net.UDPAddr{
		IP:   net.ParseIP("100.108.111.177"),
		Port: 38746,
	}

	p2pEndpoint := &net.UDPAddr{
		IP:   net.ParseIP("fe80::56"),
		Port: 51820,
	}

	testRedirectAs(t, proxy, wgPort, nbAddr, p2pEndpoint)
}

// TestRedirectAs_UDP_IPv4 tests RedirectAs with UDP proxy using IPv4 addresses
func TestRedirectAs_UDP_IPv4(t *testing.T) {
	wgPort := 51852
	proxy := udp.NewWGUDPProxy(wgPort, 1280)

	// NetBird UDP address of the remote peer
	nbAddr := &net.UDPAddr{
		IP:   net.ParseIP("100.108.111.177"),
		Port: 38746,
	}

	p2pEndpoint := &net.UDPAddr{
		IP:   net.ParseIP("192.168.0.56"),
		Port: 51820,
	}

	testRedirectAs(t, proxy, wgPort, nbAddr, p2pEndpoint)
}

// TestRedirectAs_UDP_IPv6 tests RedirectAs with UDP proxy using IPv6 addresses
func TestRedirectAs_UDP_IPv6(t *testing.T) {
	wgPort := 51853
	proxy := udp.NewWGUDPProxy(wgPort, 1280)

	// NetBird UDP address of the remote peer
	nbAddr := &net.UDPAddr{
		IP:   net.ParseIP("100.108.111.177"),
		Port: 38746,
	}

	p2pEndpoint := &net.UDPAddr{
		IP:   net.ParseIP("fe80::56"),
		Port: 51820,
	}

	testRedirectAs(t, proxy, wgPort, nbAddr, p2pEndpoint)
}

// testRedirectAs is a helper function that tests the RedirectAs functionality
// It verifies that:
// 1. Initial traffic from relay connection works
// 2. After calling RedirectAs, packets appear to come from the p2p endpoint
// 3. Multiple packets are correctly redirected with the new source address
func testRedirectAs(t *testing.T, proxy Proxy, wgPort int, nbAddr, p2pEndpoint *net.UDPAddr) {
	t.Helper()

	ctx := context.Background()

	// Create WireGuard listeners on both IPv4 and IPv6 to support both P2P connection types
	// In reality, WireGuard binds to a port and receives from both IPv4 and IPv6
	wgListener4, err := net.ListenUDP("udp4", &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: wgPort,
	})
	if err != nil {
		t.Fatalf("failed to create IPv4 WireGuard listener: %v", err)
	}
	defer wgListener4.Close()

	wgListener6, err := net.ListenUDP("udp6", &net.UDPAddr{
		IP:   net.ParseIP("::1"),
		Port: wgPort,
	})
	if err != nil {
		t.Fatalf("failed to create IPv6 WireGuard listener: %v", err)
	}
	defer wgListener6.Close()

	// Determine which listener to use based on the NetBird address IP version
	// (this is where initial traffic will come from before RedirectAs is called)
	var wgListener *net.UDPConn
	if p2pEndpoint.IP.To4() == nil {
		wgListener = wgListener6
	} else {
		wgListener = wgListener4
	}

	// Create relay server and connection
	relayServer, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 0, // Random port
	})
	if err != nil {
		t.Fatalf("failed to create relay server: %v", err)
	}
	defer relayServer.Close()

	relayConn, err := net.Dial("udp", relayServer.LocalAddr().String())
	if err != nil {
		t.Fatalf("failed to create relay connection: %v", err)
	}
	defer relayConn.Close()

	// Add TURN connection to proxy
	if err := proxy.AddTurnConn(ctx, nbAddr, relayConn); err != nil {
		t.Fatalf("failed to add TURN connection: %v", err)
	}
	defer func() {
		if err := proxy.CloseConn(); err != nil {
			t.Errorf("failed to close proxy connection: %v", err)
		}
	}()

	// Start the proxy
	proxy.Work()

	// Phase 1: Test initial relay traffic
	msgFromRelay := []byte("hello from relay")
	if _, err := relayServer.WriteTo(msgFromRelay, relayConn.LocalAddr()); err != nil {
		t.Fatalf("failed to write to relay server: %v", err)
	}

	// Set read deadline to avoid hanging
	if err := wgListener4.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("failed to set read deadline: %v", err)
	}

	buf := make([]byte, 1024)
	n, _, err := wgListener4.ReadFrom(buf)
	if err != nil {
		t.Fatalf("failed to read from WireGuard listener: %v", err)
	}

	if n != len(msgFromRelay) {
		t.Errorf("expected %d bytes, got %d", len(msgFromRelay), n)
	}

	if string(buf[:n]) != string(msgFromRelay) {
		t.Errorf("expected message %q, got %q", msgFromRelay, buf[:n])
	}

	// Phase 2: Redirect to p2p endpoint
	proxy.RedirectAs(p2pEndpoint)

	// Give the proxy a moment to process the redirect
	time.Sleep(100 * time.Millisecond)

	// Phase 3: Test redirected traffic
	redirectedMessages := [][]byte{
		[]byte("redirected message 1"),
		[]byte("redirected message 2"),
		[]byte("redirected message 3"),
	}

	for i, msg := range redirectedMessages {
		if _, err := relayServer.WriteTo(msg, relayConn.LocalAddr()); err != nil {
			t.Fatalf("failed to write redirected message %d: %v", i+1, err)
		}

		if err := wgListener.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("failed to set read deadline: %v", err)
		}

		n, srcAddr, err := wgListener.ReadFrom(buf)
		if err != nil {
			t.Fatalf("failed to read redirected message %d: %v", i+1, err)
		}

		// Verify message content
		if string(buf[:n]) != string(msg) {
			t.Errorf("message %d: expected %q, got %q", i+1, msg, buf[:n])
		}

		// Verify source address matches p2p endpoint (this is the key test)
		// Use compareUDPAddr to ignore IPv6 zone IDs
		if !compareUDPAddr(srcAddr, p2pEndpoint) {
			t.Errorf("message %d: expected source address %s, got %s",
				i+1, p2pEndpoint.String(), srcAddr.String())
		}
	}
}

// TestRedirectAs_Multiple_Switches tests switching between multiple endpoints
func TestRedirectAs_Multiple_Switches(t *testing.T) {
	wgPort := 51856
	ebpfProxy := ebpf.NewWGEBPFProxy(wgPort, 1280)
	if err := ebpfProxy.Listen(); err != nil {
		t.Fatalf("failed to initialize ebpf proxy: %v", err)
	}
	defer func() {
		if err := ebpfProxy.Free(); err != nil {
			t.Errorf("failed to free ebpf proxy: %v", err)
		}
	}()

	proxy := ebpf.NewProxyWrapper(ebpfProxy)

	ctx := context.Background()

	// Create WireGuard listener
	wgListener, err := net.ListenUDP("udp4", &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: wgPort,
	})
	if err != nil {
		t.Fatalf("failed to create WireGuard listener: %v", err)
	}
	defer wgListener.Close()

	// Create relay server and connection
	relayServer, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 0,
	})
	if err != nil {
		t.Fatalf("failed to create relay server: %v", err)
	}
	defer relayServer.Close()

	relayConn, err := net.Dial("udp", relayServer.LocalAddr().String())
	if err != nil {
		t.Fatalf("failed to create relay connection: %v", err)
	}
	defer relayConn.Close()

	nbAddr := &net.UDPAddr{
		IP:   net.ParseIP("100.108.111.177"),
		Port: 38746,
	}

	if err := proxy.AddTurnConn(ctx, nbAddr, relayConn); err != nil {
		t.Fatalf("failed to add TURN connection: %v", err)
	}
	defer func() {
		if err := proxy.CloseConn(); err != nil {
			t.Errorf("failed to close proxy connection: %v", err)
		}
	}()

	proxy.Work()

	// Test switching between multiple endpoints - using addresses in local subnet
	endpoints := []*net.UDPAddr{
		{IP: net.ParseIP("192.168.0.100"), Port: 51820},
		{IP: net.ParseIP("192.168.0.101"), Port: 51821},
		{IP: net.ParseIP("192.168.0.102"), Port: 51822},
	}

	for i, endpoint := range endpoints {
		proxy.RedirectAs(endpoint)
		time.Sleep(100 * time.Millisecond)

		msg := []byte("test message")
		if _, err := relayServer.WriteTo(msg, relayConn.LocalAddr()); err != nil {
			t.Fatalf("failed to write message for endpoint %d: %v", i, err)
		}

		buf := make([]byte, 1024)
		if err := wgListener.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("failed to set read deadline: %v", err)
		}

		n, srcAddr, err := wgListener.ReadFrom(buf)
		if err != nil {
			t.Fatalf("failed to read message for endpoint %d: %v", i, err)
		}

		if string(buf[:n]) != string(msg) {
			t.Errorf("endpoint %d: expected message %q, got %q", i, msg, buf[:n])
		}

		if !compareUDPAddr(srcAddr, endpoint) {
			t.Errorf("endpoint %d: expected source %s, got %s",
				i, endpoint.String(), srcAddr.String())
		}
	}
}
