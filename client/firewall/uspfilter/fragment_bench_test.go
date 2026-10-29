package uspfilter

import (
	"encoding/binary"
	"testing"
)

// benchFilterInbound drives filterInbound over a fixed packet in a tight loop.
// Packets are built once, outside the timed region, so the benchmark measures
// only pipeline cost, which is what an attacker can amplify.
func benchFilterInbound(b *testing.B, pkt []byte) {
	b.Helper()
	b.ReportAllocs()
	b.SetBytes(int64(len(pkt)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m := benchManager
		m.filterInbound(pkt, len(pkt))
	}
}

// benchManager is a package-level manager reused across fragment benchmarks so
// setup cost stays out of the timed region.
var benchManager *Manager

func setupBenchManager(b *testing.B) *Manager {
	b.Helper()
	m := newFragmentTestManager(b)
	allowUDP(b, m, 8080)
	// Disable conntrack so the allowed-first-fragment path measures transport
	// decode + ACL every iteration instead of matching the connection tracked
	// on the first iteration.
	m.stateful = false
	benchManager = m
	return m
}

// BenchmarkInbound_NormalPacket is the baseline: a full, non-fragmented UDP
// packet that passes the ACL. Fragment paths should stay comparable to this.
func BenchmarkInbound_NormalPacket(b *testing.B) {
	setupBenchManager(b)
	pkt := normalUDPPacket(b, 8080, 32)
	benchFilterInbound(b, pkt)
}

// BenchmarkInbound_FirstFragmentAllowed measures the first-fragment path:
// transport decode + ACL evaluation + verdict record.
func BenchmarkInbound_FirstFragmentAllowed(b *testing.B) {
	setupBenchManager(b)
	pkt := firstFragmentUDP(b, 0x2000, 8080, 32)
	benchFilterInbound(b, pkt)
}

// BenchmarkInbound_TrailingFragmentAllowed measures the common trailing-fragment
// path: a single map lookup after the first fragment is on record.
func BenchmarkInbound_TrailingFragmentAllowed(b *testing.B) {
	m := setupBenchManager(b)
	first := firstFragmentUDP(b, 0x3000, 8080, 32)
	m.filterInbound(first, len(first))
	pkt := trailingFragment(b, 0x3000, 5, false, 24)
	benchFilterInbound(b, pkt)
}

// BenchmarkInbound_TrailingFragmentNoFirst is the primary DoS vector: an
// attacker floods trailing fragments with no first fragment on record. Each is
// a map miss and must be cheap.
func BenchmarkInbound_TrailingFragmentNoFirst(b *testing.B) {
	setupBenchManager(b)
	pkt := trailingFragment(b, 0x4000, 185, false, 40)
	benchFilterInbound(b, pkt)
}

// BenchmarkInbound_TinyFirstFragment measures the tiny-fragment drop path: a
// first fragment too small to decode a transport header.
func BenchmarkInbound_TinyFirstFragment(b *testing.B) {
	setupBenchManager(b)
	pkt := trailingFragment(b, 0x5000, 0, true, 4)
	benchFilterInbound(b, pkt)
}

// BenchmarkInbound_TrailingFragmentDistinctIDs is the worst case for the
// verdict table: an attacker varies the datagram id on every packet so no first
// fragment ever matches. Verdict lookups always miss and nothing is recorded,
// so the table cannot grow. Each iteration rewrites the id field in place.
func BenchmarkInbound_TrailingFragmentDistinctIDs(b *testing.B) {
	setupBenchManager(b)
	pkt := trailingFragment(b, 0x6000, 185, false, 40)
	m := benchManager

	b.ReportAllocs()
	b.SetBytes(int64(len(pkt)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// IPv4 identification field is at bytes 4:6.
		binary.BigEndian.PutUint16(pkt[4:6], uint16(i))
		m.filterInbound(pkt, len(pkt))
	}
}

// BenchmarkInbound_FirstFragmentDistinctIDs measures sustained first-fragment
// pressure with distinct ids: transport decode + ACL + verdict insert until the
// table caps, exercising the map growth and capacity guard.
func BenchmarkInbound_FirstFragmentDistinctIDs(b *testing.B) {
	setupBenchManager(b)
	pkt := firstFragmentUDP(b, 0x7000, 8080, 32)
	m := benchManager

	b.ReportAllocs()
	b.SetBytes(int64(len(pkt)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		binary.BigEndian.PutUint16(pkt[4:6], uint16(i))
		m.filterInbound(pkt, len(pkt))
	}
}
