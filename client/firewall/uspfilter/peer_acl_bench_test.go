//go:build uspbench

package uspfilter

import (
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/netip"
	"runtime"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	fw "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

// BenchmarkPeerACLMatch measures the per-packet cost of the peer ACL
// matcher (peerACLsBlock) across realistic shapes: M distinct policy
// rules, each with K source peers in its set.
//
// With the reverse-source index, miss cost is independent of M and
// hit cost grows only with the number of rules touching a single
// srcIP, not with total rule count.
func BenchmarkPeerACLMatch(b *testing.B) {
	shapes := []struct{ M, K int }{
		{1, 100}, {10, 100}, {50, 100}, {100, 100}, {100, 1000},
	}
	families := []struct {
		name string
		v6   bool
	}{{"v4", false}, {"v6", true}}

	for _, fam := range families {
		for _, s := range shapes {
			b.Run(fmt.Sprintf("%s/M=%d/K=%d/hit", fam.name, s.M, s.K), func(b *testing.B) {
				runPeerACLBench(b, s.M, s.K, true, fam.v6)
			})
			b.Run(fmt.Sprintf("%s/M=%d/K=%d/miss", fam.name, s.M, s.K), func(b *testing.B) {
				runPeerACLBench(b, s.M, s.K, false, fam.v6)
			})
		}
	}
}

func runPeerACLBench(b *testing.B, m, k int, hit, v6 bool) {
	log.SetOutput(io.Discard) // keep manager logs out of the benchmark output

	// Miss packets are dropped, so they always traverse the full peer
	// ACL matcher (every bucket) without short-circuiting and without
	// touching conntrack. Disable conntrack for the miss case so it
	// measures the matcher, not established-state lookups. The hit case
	// keeps conntrack on: an accepted packet reaches trackInbound, which
	// needs the trackers conntrack creates.
	if !hit {
		b.Setenv("NB_DISABLE_CONNTRACK", "1")
	}

	bits := 32
	genPkt := generatePacket
	addrs := uniqueAddrs
	if v6 {
		bits = 128
		genPkt = generatePacket6
		addrs = uniqueAddrs6
	}

	// dstIP must be a local IP so filterInbound takes the local-traffic
	// path (handleLocalTraffic → peerACLsBlock) we are measuring; an
	// address the manager doesn't own would be treated as routed and
	// short-circuit before the peer matcher.
	dstIP := addrs(1, 2)[0]
	mockAddr := wgaddr.Address{IP: dstIP, Network: netip.PrefixFrom(dstIP, bits)}
	if v6 {
		// The local-IP manager needs a valid v4 address too; expose the v6
		// dst as the interface's IPv6 so IsLocalIP recognizes it.
		mockAddr = wgaddr.Address{
			IP:      netip.MustParseAddr("100.64.0.1"),
			Network: netip.MustParsePrefix("100.64.0.0/16"),
			IPv6:    dstIP,
			IPv6Net: netip.PrefixFrom(dstIP, bits),
		}
	}
	manager, err := Create(Config{
		IFace: &IFaceMock{
			SetFilterFunc: func(device.PacketFilter) error { return nil },
			AddressFunc:   func() wgaddr.Address { return mockAddr },
		},
		FlowLogger: flowLogger, MTU: iface.DefaultMTU})
	require.NoError(b, err)
	b.Cleanup(func() { require.NoError(b, manager.Close(nil)) })

	// Generate M policies × K source peers, all distinct.
	all := addrs(m*k, 1)
	for i := 0; i < m; i++ {
		sources := make([]netip.Prefix, k)
		for j, a := range all[i*k : (i+1)*k] {
			sources[j] = netip.PrefixFrom(a, bits)
		}
		_, err := manager.AddFilterRule(
			nil, sources, fw.Network{}, fw.ProtocolTCP, nil,
			&fw.Port{Values: []uint16{uint16(80 + i)}},
			fw.ActionAccept)
		require.NoError(b, err)
	}

	// Hit: cycle through real sources, picking the matching policy's port.
	// Miss: a source from a disjoint range, port 80 (matches no policy).
	var pktFn func(i int) []byte
	if hit {
		pktFn = func(i int) []byte {
			policy := i % m
			src := all[policy*k+(i%k)]
			return genPkt(b, src.AsSlice(), dstIP.AsSlice(),
				uint16(1024+i%60000), uint16(80+policy), layers.IPProtocolTCP)
		}
	} else {
		miss := addrs(4096, 99)
		pktFn = func(i int) []byte {
			return genPkt(b, miss[i%len(miss)].AsSlice(), dstIP.AsSlice(),
				uint16(1024+i%60000), 80, layers.IPProtocolTCP)
		}
	}

	// Pre-build a pool to avoid allocations dominating the measurement.
	pool := make([][]byte, 1024)
	for i := range pool {
		pool[i] = pktFn(i)
	}

	// Confirm the matcher is actually exercised: a hit packet must be
	// allowed and a miss packet dropped. Without this the benchmark
	// could silently time the routed early-return instead.
	require.Equal(b, !hit, manager.filterInbound(pool[0], 0),
		"benchmark must reach the peer ACL matcher")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager.filterInbound(pool[i%len(pool)], 0)
	}
}

// BenchmarkPeerACLIndexMemory reports the resident memory cost of
// the source-keyed index across realistic deployment shapes. Two
// dimensions matter: (M, K), the number of policies × peers-per-policy,
// and overlap, the fraction of peers shared between policies.
//
// The output uses ReportMetric("bytes/rule") so the cost can be
// compared across shapes directly. Total bytes = bytes/rule * M.
func BenchmarkPeerACLIndexMemory(b *testing.B) {
	cases := []struct {
		name        string
		M, K        int
		overlapFrac float64 // 0 = disjoint per-policy sources, 1 = all share the same pool
	}{
		{"M=10/K=100/disjoint", 10, 100, 0},
		{"M=100/K=100/disjoint", 100, 100, 0},
		{"M=100/K=1000/disjoint", 100, 1000, 0},
		{"M=100/K=1000/overlap=0.5", 100, 1000, 0.5},
		{"M=100/K=1000/overlap=1.0", 100, 1000, 1.0},
		{"M=1000/K=100/overlap=1.0", 1000, 100, 1.0},
	}

	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				mgr, err := Create(Config{
					IFace: &IFaceMock{
						SetFilterFunc: func(device.PacketFilter) error { return nil },
					},
					FlowLogger: flowLogger, MTU: iface.DefaultMTU})
				require.NoError(b, err)

				populateIndexedRules(b, mgr, c.M, c.K, c.overlapFrac)

				runtime.GC()
				var ms runtime.MemStats
				runtime.ReadMemStats(&ms)
				before := ms.HeapAlloc

				// Drop the manager's external roots so we can isolate
				// the index cost. We hold the manager itself live; the
				// index is what we measure on the second pass.
				mgr.incomingAcceptIndex.reset()
				mgr.incomingDenyIndex.reset()
				mgr.incomingAcceptRules = mgr.incomingAcceptRules[:0]
				mgr.incomingDenyRules = mgr.incomingDenyRules[:0]
				runtime.GC()
				runtime.ReadMemStats(&ms)
				after := ms.HeapAlloc

				delta := int64(before) - int64(after)
				if delta < 0 {
					delta = 0
				}
				b.ReportMetric(float64(delta)/float64(c.M), "bytes/rule")
				b.ReportMetric(float64(delta), "bytes/total")

				require.NoError(b, mgr.Close(nil))
			}
		})
	}
}

func populateIndexedRules(b *testing.B, mgr *Manager, m, k int, overlapFrac float64) {
	b.Helper()
	pool := uniqueAddrs(k+m*k, 1) // big enough universe
	sharedLen := int(float64(k) * overlapFrac)
	if sharedLen > k {
		sharedLen = k
	}
	shared := pool[:sharedLen]
	uniquePool := pool[sharedLen:]

	for i := 0; i < m; i++ {
		sources := make([]netip.Prefix, 0, k)
		for _, a := range shared {
			sources = append(sources, netip.PrefixFrom(a, 32))
		}
		// each policy gets (k-sharedLen) addresses unique to it from the unique pool
		unique := uniquePool[i*(k-sharedLen) : (i+1)*(k-sharedLen)]
		for _, a := range unique {
			sources = append(sources, netip.PrefixFrom(a, 32))
		}
		_, err := mgr.AddFilterRule(
			nil, sources, fw.Network{}, fw.ProtocolTCP, nil,
			&fw.Port{Values: []uint16{uint16(80 + i)}},
			fw.ActionAccept)
		require.NoError(b, err)
	}
}

// uniqueAddrs returns n distinct addrs. Seeds 1, 2 are used for
// policy sources / dst; seed 99 puts misses in 10/8.
func uniqueAddrs(n int, seed int64) []netip.Addr {
	out := make([]netip.Addr, 0, n)
	seen := make(map[netip.Addr]struct{}, n)
	r := rand.New(rand.NewSource(seed))
	miss := seed == 99
	for len(out) < n {
		var b [4]byte
		if miss {
			b[0] = 10
			b[1] = byte(r.Intn(256))
		} else {
			b[0] = 100
			b[1] = byte(64 + r.Intn(63))
		}
		b[2] = byte(r.Intn(256))
		b[3] = byte(1 + r.Intn(254))
		a := netip.AddrFrom4(b)
		if _, ok := seen[a]; ok {
			continue
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}
	return out
}

// uniqueAddrs6 mirrors uniqueAddrs for IPv6: sources come from the ULA
// range fd00::/8, the miss set (seed 99) from 2001:db8::/32 so it is
// disjoint from any source.
func uniqueAddrs6(n int, seed int64) []netip.Addr {
	out := make([]netip.Addr, 0, n)
	seen := make(map[netip.Addr]struct{}, n)
	r := rand.New(rand.NewSource(seed))
	miss := seed == 99
	for len(out) < n {
		var b [16]byte
		if miss {
			b[0], b[1], b[2], b[3] = 0x20, 0x01, 0x0d, 0xb8
		} else {
			b[0] = 0xfd
		}
		for x := 8; x < 16; x++ {
			b[x] = byte(r.Intn(256))
		}
		a := netip.AddrFrom16(b)
		if _, ok := seen[a]; ok {
			continue
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}
	return out
}

// generatePacket6 builds an IPv6 TCP/UDP packet, mirroring
// generatePacket for the v4 case.
func generatePacket6(b *testing.B, srcIP, dstIP net.IP, srcPort, dstPort uint16, protocol layers.IPProtocol) []byte {
	b.Helper()

	ipv6 := &layers.IPv6{
		Version:    6,
		HopLimit:   64,
		NextHeader: protocol,
		SrcIP:      srcIP,
		DstIP:      dstIP,
	}

	var transportLayer gopacket.SerializableLayer
	switch protocol {
	case layers.IPProtocolTCP:
		tcp := &layers.TCP{
			SrcPort: layers.TCPPort(srcPort),
			DstPort: layers.TCPPort(dstPort),
			SYN:     true,
		}
		require.NoError(b, tcp.SetNetworkLayerForChecksum(ipv6))
		transportLayer = tcp
	case layers.IPProtocolUDP:
		udp := &layers.UDP{
			SrcPort: layers.UDPPort(srcPort),
			DstPort: layers.UDPPort(dstPort),
		}
		require.NoError(b, udp.SetNetworkLayerForChecksum(ipv6))
		transportLayer = udp
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	require.NoError(b, gopacket.SerializeLayers(buf, opts, ipv6, transportLayer, gopacket.Payload("test")))
	return buf.Bytes()
}
