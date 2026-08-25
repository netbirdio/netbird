//go:build linux && !android && privileged

package loopback

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"
)

const testWGPort = 51862

// relayEnd stands in for a relayed connection: the proxy writes what it read
// from WireGuard into it, and the test reads it back out here.
func relayEnd(t *testing.T) (proxySide net.Conn, testSide *net.UDPConn) {
	t.Helper()

	testSide, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("relay listener: %v", err)
	}
	t.Cleanup(func() {
		if err := testSide.Close(); err != nil {
			t.Logf("close relay listener: %v", err)
		}
	})

	proxySide, err = net.Dial("udp", testSide.LocalAddr().String())
	if err != nil {
		t.Fatalf("relay conn: %v", err)
	}
	t.Cleanup(func() {
		if err := proxySide.Close(); err != nil {
			t.Logf("close relay conn: %v", err)
		}
	})

	return proxySide, testSide
}

// TestProxyDemuxesByDestinationAddress is the core of the design: one socket
// serves every peer, and the destination address decides which relayed
// connection a WireGuard packet belongs to.
func TestProxyDemuxesByDestinationAddress(t *testing.T) {
	proxy := NewProxy(testWGPort, 1280)
	if err := proxy.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() {
		if err := proxy.Free(); err != nil {
			t.Errorf("free proxy: %v", err)
		}
	}()

	const peers = 3
	endpoints := make([]*net.UDPAddr, 0, peers)
	readers := make([]*net.UDPConn, 0, peers)
	for i := 0; i < peers; i++ {
		proxySide, testSide := relayEnd(t)
		endpoint, _, err := proxy.AddRelayedConn(proxySide)
		if err != nil {
			t.Fatalf("add relayed conn %d: %v", i, err)
		}
		if endpoint.Port != proxy.proxyPort {
			t.Errorf("peer %d endpoint port = %d, want the shared proxy port %d", i, endpoint.Port, proxy.proxyPort)
		}
		endpoints = append(endpoints, endpoint)
		readers = append(readers, testSide)
	}

	// every peer must have its own address, otherwise they are indistinguishable
	seen := make(map[string]bool, peers)
	for i, endpoint := range endpoints {
		if seen[endpoint.IP.String()] {
			t.Fatalf("peer %d reuses endpoint address %s", i, endpoint.IP)
		}
		seen[endpoint.IP.String()] = true
	}

	wgSock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: testWGPort})
	if err != nil {
		t.Fatalf("wg socket: %v", err)
	}
	defer func() {
		if err := wgSock.Close(); err != nil {
			t.Logf("close wg socket: %v", err)
		}
	}()

	for i, endpoint := range endpoints {
		payload := []byte{byte(i), 'p', 'k', 't'}
		if _, err := wgSock.WriteTo(payload, endpoint); err != nil {
			t.Fatalf("write to peer %d endpoint %s: %v", i, endpoint, err)
		}

		buf := make([]byte, 1500)
		if err := readers[i].SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("set read deadline: %v", err)
		}
		n, _, err := readers[i].ReadFrom(buf)
		if err != nil {
			t.Fatalf("peer %d did not receive its packet: %v", i, err)
		}
		if string(buf[:n]) != string(payload) {
			t.Errorf("peer %d got %q, want %q", i, buf[:n], payload)
		}

		// no other peer may see it
		for j, other := range readers {
			if j == i {
				continue
			}
			if err := other.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
				t.Fatalf("set read deadline: %v", err)
			}
			if _, _, err := other.ReadFrom(buf); err == nil {
				t.Errorf("packet for peer %d also delivered to peer %d", i, j)
			}
		}
	}
}

// TestProxyDropsPacketsOutsideTheRange guards the wildcard bind: anything that
// is not addressed to a handed-out endpoint must not reach a relayed peer.
func TestProxyDropsPacketsOutsideTheRange(t *testing.T) {
	proxy := NewProxy(testWGPort+1, 1280)
	if err := proxy.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() {
		if err := proxy.Free(); err != nil {
			t.Errorf("free proxy: %v", err)
		}
	}()

	proxySide, testSide := relayEnd(t)
	if _, _, err := proxy.AddRelayedConn(proxySide); err != nil {
		t.Fatalf("add relayed conn: %v", err)
	}

	sender, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(proxy.proxyPort)))
	if err != nil {
		t.Fatalf("sender: %v", err)
	}
	defer func() {
		if err := sender.Close(); err != nil {
			t.Logf("close sender: %v", err)
		}
	}()

	if _, err := sender.Write([]byte("stray")); err != nil {
		t.Fatalf("write stray packet: %v", err)
	}

	buf := make([]byte, 1500)
	if err := testSide.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	if _, _, err := testSide.ReadFrom(buf); err == nil {
		t.Error("packet addressed to 127.0.0.1 was forwarded to a relayed peer")
	}
}

// A wrapper that is closed before it starts forwarding still has to give its
// endpoint address back, otherwise the range leaks an address per attempt.
func TestClosingBeforeWorkReleasesTheAddress(t *testing.T) {
	proxy := NewProxy(testWGPort+2, 1280)
	if err := proxy.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() {
		if err := proxy.Free(); err != nil {
			t.Errorf("free proxy: %v", err)
		}
	}()

	proxySide, _ := relayEnd(t)
	wrapper := NewProxyWrapper(proxy)
	if err := wrapper.AddRelayedConn(context.Background(), nil, proxySide); err != nil {
		t.Fatalf("add relayed conn: %v", err)
	}

	if got := len(proxy.relayedConnStore); got != 1 {
		t.Fatalf("store holds %d entries after adding one conn, want 1", got)
	}

	if err := wrapper.CloseConn(); err != nil {
		t.Fatalf("close conn: %v", err)
	}

	if got := len(proxy.relayedConnStore); got != 0 {
		t.Errorf("store holds %d entries after close, want 0", got)
	}
}
