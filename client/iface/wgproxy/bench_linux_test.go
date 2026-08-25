//go:build linux && !android && privileged

package wgproxy

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netbirdio/netbird/client/iface/wgproxy/loopback"
	"github.com/netbirdio/netbird/client/iface/wgproxy/udp"
)

// Benchmarks the WireGuard -> relay direction: a stand-in WireGuard socket sends
// to each peer's endpoint, the proxy picks the packet up and forwards it to the
// relayed connection. Peer count matters because the kernel proxy shares one
// socket between all peers while the userspace proxy has one per peer.

const (
	benchLoopbackWgPort = 51841
	benchUDPWgPort      = 51842
	benchPktSize        = 1200
)

type benchVariant struct {
	name   string
	wgPort int
	setup  func(peers int) (proxies []Proxy, cleanup func(), err error)
}

func benchVariants() []benchVariant {
	return []benchVariant{
		{
			name:   "loopback",
			wgPort: benchLoopbackWgPort,
			setup: func(peers int) ([]Proxy, func(), error) {
				loopbackProxy := loopback.NewProxy(benchLoopbackWgPort, 1280)
				if err := loopbackProxy.Listen(); err != nil {
					return nil, nil, fmt.Errorf("listen loopback proxy: %w", err)
				}
				proxies := make([]Proxy, 0, peers)
				for i := 0; i < peers; i++ {
					proxies = append(proxies, loopback.NewProxyWrapper(loopbackProxy))
				}
				return proxies, func() { _ = loopbackProxy.Free() }, nil
			},
		},
		{
			name:   "udp",
			wgPort: benchUDPWgPort,
			setup: func(peers int) ([]Proxy, func(), error) {
				proxies := make([]Proxy, 0, peers)
				for i := 0; i < peers; i++ {
					proxies = append(proxies, udp.NewWGUDPProxy(benchUDPWgPort, 1280))
				}
				return proxies, func() {}, nil
			},
		},
	}
}

func BenchmarkProxyForwarding(b *testing.B) {
	for _, peers := range []int{1, 8, 32} {
		for _, v := range benchVariants() {
			b.Run(fmt.Sprintf("%s/peers=%d", v.name, peers), func(b *testing.B) {
				runForwardingBench(b, v, peers)
			})
		}
	}
}

func runForwardingBench(b *testing.B, v benchVariant, peers int) {
	b.Helper()

	relayServer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		b.Fatalf("relay server: %v", err)
	}
	defer relayServer.Close()
	if err := relayServer.SetReadBuffer(8 << 20); err != nil {
		b.Logf("set relay read buffer: %v", err)
	}

	proxies, cleanup, err := v.setup(peers)
	if err != nil {
		b.Skipf("setup %s: %v", v.name, err)
	}
	defer cleanup()

	ctx := context.Background()
	endpoints := make([]*net.UDPAddr, 0, peers)
	for i, p := range proxies {
		relayConn, err := net.Dial("udp", relayServer.LocalAddr().String())
		if err != nil {
			b.Fatalf("relay conn %d: %v", i, err)
		}
		defer relayConn.Close()

		nbAddr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, byte(i+1)), Port: 51820}
		if err := p.AddRelayedConn(ctx, nbAddr, relayConn); err != nil {
			b.Fatalf("add relayed conn %d: %v", i, err)
		}
		p.Work()

		addr := p.EndpointAddr()
		if addr == nil {
			b.Fatalf("proxy %d has no endpoint address", i)
		}
		endpoints = append(endpoints, addr)
	}
	defer func() {
		for _, p := range proxies {
			_ = p.CloseConn()
		}
	}()

	// stand-in for the WireGuard socket: bound to the wg port the proxy expects
	wgSock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: v.wgPort})
	if err != nil {
		b.Fatalf("wg socket: %v", err)
	}
	defer wgSock.Close()
	if err := wgSock.SetWriteBuffer(8 << 20); err != nil {
		b.Logf("set wg write buffer: %v", err)
	}

	var received atomic.Int64
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 65536)
		for {
			select {
			case <-done:
				return
			default:
			}
			if err := relayServer.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
				return
			}
			n, _, err := relayServer.ReadFrom(buf)
			if err != nil {
				continue
			}
			if n > 0 {
				received.Add(1)
			}
		}
	}()

	pkt := make([]byte, benchPktSize)
	// warm up the datapath and the per-peer lookups
	for i := 0; i < 200; i++ {
		if _, err := wgSock.WriteTo(pkt, endpoints[i%len(endpoints)]); err != nil {
			b.Fatalf("warmup write: %v", err)
		}
	}
	time.Sleep(200 * time.Millisecond)
	received.Store(0)

	b.SetBytes(int64(benchPktSize))
	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		if _, err := wgSock.WriteTo(pkt, endpoints[i%len(endpoints)]); err != nil {
			b.Fatalf("write: %v", err)
		}
	}
	sent := b.N
	// let the tail drain
	time.Sleep(300 * time.Millisecond)
	elapsed := time.Since(start)
	b.StopTimer()

	close(done)
	wg.Wait()

	got := received.Load()
	b.ReportMetric(float64(got)/elapsed.Seconds(), "fwd_pps")
	b.ReportMetric(float64(got)/float64(sent)*100, "delivered_%")
}
