package proxy

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/conn/bindtest"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// These tests state what one account's tunnel Device has to keep doing under
// the proxy's tuning (NB_PROXY_PREALLOCATED_BUFFERS=16 with
// NB_PROXY_MAX_BATCH_SIZE=1). They failed on the wireguard-go fork before
// netbirdio/wireguard-go#22.
//
// Two things drain a sixteen-buffer pool: packets staged for a peer that
// cannot complete its handshake (an offline backend, or a lazy-connection
// placeholder whose activation never succeeds), and a burst of inbound packets
// whose replies the netstack emits synchronously. Once the pool was empty that
// fork parked the TUN reader and the receive goroutines in WaitPool.Get instead
// of dropping, so the whole account stopped, and anything that then waited for
// a peer routine (a peer removal, Device.Close) blocked for good while holding
// the locks the stats and status paths need. Every failure message below names
// the goroutines that are parked at that moment. The fork now drops on an
// exhausted pool and keeps staging for peers without a session to half the
// cap; the recovery steps in the tests exist so a regression cannot hang the
// package.

const (
	// operatorPoolCap and operatorBatchSize mirror the production settings
	// NB_PROXY_PREALLOCATED_BUFFERS=16 and NB_PROXY_MAX_BATCH_SIZE=1.
	operatorPoolCap   = 16
	operatorBatchSize = 1

	wedgeSettleTimeout = 10 * time.Second
	wedgeProbeTimeout  = 5 * time.Second
	// poolSettleTime is how long a flood gets to exhaust the pool before a test
	// carries on regardless.
	poolSettleTime = 2 * time.Second
)

type tunnelPeer struct {
	tun *tuntest.ChannelTUN
	dev *device.Device
	ip  netip.Addr
	key wgtypes.Key
}

// uapiConfig formats alternating key/value pairs the way Device.IpcSet expects.
func uapiConfig(kv ...string) string {
	var sb strings.Builder
	for i, s := range kv {
		sb.WriteString(s)
		if i%2 == 0 {
			sb.WriteByte('=')
		} else {
			sb.WriteByte('\n')
		}
	}
	return sb.String()
}

// newTunnelPair brings up two channel-bound Devices with a completed
// handshake between them. Only dev[0] is created under the given pool cap and
// batch override; dev[1] keeps the upstream defaults so it can never wedge and
// acts as the healthy remote side.
func newTunnelPair(t *testing.T, poolCap, batch uint32) [2]tunnelPeer {
	t.Helper()

	binds := bindtest.NewChannelBinds()
	var pair [2]tunnelPeer
	for i := range pair {
		key, err := wgtypes.GeneratePrivateKey()
		require.NoError(t, err)
		pair[i] = tunnelPeer{
			tun: tuntest.NewChannelTUN(),
			ip:  netip.AddrFrom4([4]byte{1, 0, 0, byte(i + 1)}),
			key: key,
		}
	}

	// bindtest wires the channel binds with fixed endpoints: bind[0] reaches
	// bind[1] through port 1 and bind[1] reaches bind[0] through port 2.
	endpoints := [2]string{"127.0.0.1:1", "127.0.0.1:2"}

	t.Cleanup(func() {
		device.SetPreallocatedBuffersPerPool(0)
		device.SetMaxBatchSizeOverride(0)
	})
	for i := range pair {
		if i == 0 {
			device.SetPreallocatedBuffersPerPool(poolCap)
			device.SetMaxBatchSizeOverride(batch)
		} else {
			device.SetPreallocatedBuffersPerPool(0)
			device.SetMaxBatchSizeOverride(0)
		}
		logger := device.NewLogger(device.LogLevelError, fmt.Sprintf("dev%d: ", i))
		pair[i].dev = device.NewDevice(pair[i].tun.TUN(), binds[i], logger)
		if i == 1 {
			// Pin dev1's endpoint for dev0 to whatever the test configures, so a
			// test can choose which of dev0's receive goroutines a packet hits.
			pair[i].dev.DisableSomeRoamingForBrokenMobileSemantics()
		}

		other := pair[i^1]
		otherPub := other.key.PublicKey()
		cfg := uapiConfig(
			"private_key", hex.EncodeToString(pair[i].key[:]),
			"listen_port", "0",
			"replace_peers", "true",
			"public_key", hex.EncodeToString(otherPub[:]),
			"replace_allowed_ips", "true",
			"allowed_ip", other.ip.String()+"/32",
			"endpoint", endpoints[i],
		)
		require.NoError(t, pair[i].dev.IpcSet(cfg), "configure dev%d", i)
		require.NoError(t, pair[i].dev.Up(), "bring up dev%d", i)
	}
	device.SetPreallocatedBuffersPerPool(0)
	device.SetMaxBatchSizeOverride(0)

	t.Cleanup(func() {
		// Lift the cap before closing: a fork that parks in the pool would wait
		// in Close for those goroutines and hang a failed test forever.
		pair[0].dev.SetPreallocatedBuffersPerPool(0)
		for i := range pair {
			pair[i].dev.Close()
		}
	})

	require.True(t, pingThrough(t, pair, 0, 1, 5*time.Second), "baseline ping dev0 -> dev1 must succeed")
	require.True(t, pingThrough(t, pair, 1, 0, 5*time.Second), "baseline ping dev1 -> dev0 must succeed")
	return pair
}

// pingThrough writes an ICMP echo into pair[from]'s TUN and reports whether it
// comes out of pair[to]'s TUN within timeout.
func pingThrough(t *testing.T, pair [2]tunnelPeer, from, to int, timeout time.Duration) bool {
	t.Helper()
	msg := tuntest.Ping(pair[to].ip, pair[from].ip)
	select {
	case pair[from].tun.Outbound <- msg:
	case <-time.After(timeout):
		t.Logf("dev%d TUN reader did not accept a packet within %s", from, timeout)
		return false
	}
	select {
	case got := <-pair[to].tun.Inbound:
		return string(got) == string(msg)
	case <-time.After(timeout):
		return false
	}
}

// pingEventually keeps pinging until one echo gets through or timeout expires.
// A Device that drops under pressure may lose some attempts; a wedged one
// never lets any through.
func pingEventually(t *testing.T, pair [2]tunnelPeer, from, to int, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if pingThrough(t, pair, from, to, 500*time.Millisecond) {
			return true
		}
	}
	return false
}

// addUnreachablePeer configures a peer on dev whose endpoint no channel bind
// serves, so its handshake never completes and everything routed to it stays
// staged. This is the shape of an offline service backend seen from the proxy.
func addUnreachablePeer(t *testing.T, dev *device.Device) netip.Addr {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	deadIP := netip.MustParseAddr("1.0.0.9")
	deadPub := key.PublicKey()
	require.NoError(t, dev.IpcSet(uapiConfig(
		"public_key", hex.EncodeToString(deadPub[:]),
		"endpoint", "127.0.0.1:9",
		"allowed_ip", deadIP.String()+"/32",
	)))
	return deadIP
}

// floodUnreachablePeer keeps writing packets for deadIP into dev0's TUN until
// the test ends. Each one is staged behind the peer's pending handshake and
// pins a message buffer from dev0's pool.
func floodUnreachablePeer(t *testing.T, pair [2]tunnelPeer, deadIP netip.Addr) {
	t.Helper()
	floodTUN(t, pair[0].tun, tuntest.Ping(deadIP, pair[0].ip))
}

// drainPoolWithUnreachablePeer adds a peer that cannot handshake and floods it.
// A Device that stages without limit exhausts the capped pool within
// milliseconds; one that bounds staging keeps buffers back, so the helper
// returns once the pool refuses a TryGet or once the flood has run for a while.
func drainPoolWithUnreachablePeer(t *testing.T, pair [2]tunnelPeer) {
	t.Helper()
	deadIP := addUnreachablePeer(t, pair[0].dev)
	floodUnreachablePeer(t, pair, deadIP)
	settlePool(t, pair[0].dev)
}

// afterDeviceClose returns a channel that is closed only after the Devices of
// a pair created later in the test have been closed. Helpers that drain a TUN
// must keep running through Device.Close: a receiver that finds nobody reading
// its TUN fills the peer queues, the other Device's sender then blocks inside
// bind.Send holding the bind lock, and Close never gets it.
func afterDeviceClose(t *testing.T) <-chan struct{} {
	t.Helper()
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	return stop
}

// floodTUN keeps writing pkt into tun until the returned stop function is
// called or the test ends. The feed always stops before the Devices close: a
// sender still pushing into a closed peer's channel bind would hold the bind
// lock and block its own Close.
func floodTUN(t *testing.T, tun *tuntest.ChannelTUN, pkt []byte) (stop func()) {
	t.Helper()
	ch := make(chan struct{})
	done := make(chan struct{})
	var once sync.Once
	stop = func() {
		once.Do(func() { close(ch) })
		<-done
	}
	t.Cleanup(stop)
	go func() {
		defer close(done)
		for {
			select {
			case tun.Outbound <- pkt:
			case <-ch:
				return
			}
		}
	}()
	return stop
}

// waitQuiescent returns once counter has stopped changing. The channel binds
// queue up to 8192 packets per direction and a Device whose pool was capped
// lets that queue fill; closing a Device while its sender still drains into a
// peer that is already gone deadlocks its Close, so tests settle first.
func waitQuiescent(t *testing.T, counter *atomic.Int64) {
	t.Helper()
	deadline := time.Now().Add(wedgeSettleTimeout)
	for time.Now().Before(deadline) {
		before := counter.Load()
		time.Sleep(300 * time.Millisecond)
		if counter.Load() == before {
			return
		}
	}
	t.Fatal("traffic did not settle before the Devices close")
}

// waitSendersIdle returns once no sequential sender is blocked inside the
// channel bind, so a Device can close without a peer that is already gone
// holding its bind lock.
func waitSendersIdle(t *testing.T) {
	t.Helper()
	idle := 0
	require.Eventually(t, func() bool {
		if goroutineIn("RoutineSequentialSender", "(*ChannelBind).Send") {
			idle = 0
			return false
		}
		idle++
		return idle >= 3
	}, wedgeSettleTimeout, 100*time.Millisecond, "a sequential sender stayed blocked inside the channel bind")
}

// startReplyingStack stands in for gVisor on dev0's TUN: it answers every
// packet the tunnel delivers with one packet back to dev1 before it accepts
// the next one, the way the netstack emits an ACK or a RST synchronously
// inside the receiver's Write. It returns the number of packets answered.
func startReplyingStack(t *testing.T, pair [2]tunnelPeer, stop <-chan struct{}) *atomic.Int64 {
	t.Helper()
	var answered atomic.Int64
	go func() {
		reply := tuntest.Ping(pair[1].ip, pair[0].ip)
		for {
			select {
			case _, ok := <-pair[0].tun.Inbound:
				if !ok {
					return
				}
			case <-stop:
				return
			}
			select {
			case pair[0].tun.Outbound <- reply:
				answered.Add(1)
			case <-stop:
				return
			}
		}
	}()
	return &answered
}

// drainTUN discards everything that arrives at tun so its Device's receiver
// never blocks on the test, and counts the packets.
func drainTUN(t *testing.T, tun *tuntest.ChannelTUN, stop <-chan struct{}) *atomic.Int64 {
	t.Helper()
	var received atomic.Int64
	go func() {
		for {
			select {
			case _, ok := <-tun.Inbound:
				if !ok {
					return
				}
				received.Add(1)
			case <-stop:
				return
			}
		}
	}()
	return &received
}

// sendInboundVia points dev1 at one of dev0's two channel-bind sockets (port 2
// is dev0's first receive function, port 4 its second) and sends one packet.
// On a fork that parks in the pool this parks that receive goroutine on the replacement
// buffer it needs after handing the packet off; in production keepalives and
// handshakes on the v4, v6 and relay sockets do this within seconds of the
// pool draining.
func sendInboundVia(t *testing.T, pair [2]tunnelPeer, endpoint string) {
	t.Helper()
	dev0Pub := pair[0].key.PublicKey()
	require.NoError(t, pair[1].dev.IpcSet(uapiConfig(
		"public_key", hex.EncodeToString(dev0Pub[:]),
		"endpoint", endpoint,
	)))
	select {
	case pair[1].tun.Outbound <- tuntest.Ping(pair[0].ip, pair[1].ip):
	case <-time.After(wedgeProbeTimeout):
		t.Fatal("healthy device did not accept an outbound packet")
	}
}

// goroutineIn reports whether some goroutine's stack contains both fnA and fnB.
func goroutineIn(fnA, fnB string) bool {
	buf := make([]byte, 4<<20)
	n := runtime.Stack(buf, true)
	for _, g := range strings.Split(string(buf[:n]), "\n\n") {
		if strings.Contains(g, fnA) && strings.Contains(g, fnB) {
			return true
		}
	}
	return false
}

// settlePool returns once dev's message buffer pool refuses a TryGet, or after
// poolSettleTime if it never does.
func settlePool(t *testing.T, dev *device.Device) {
	t.Helper()
	deadline := time.Now().Add(poolSettleTime)
	for time.Now().Before(deadline) {
		buf, ok := dev.TryGetMessageBuffer()
		if !ok {
			return
		}
		dev.PutMessageBuffer(buf)
		time.Sleep(20 * time.Millisecond)
	}
}

// goroutinesParkedInPool counts the goroutines blocked inside WaitPool.Get
// while running fn, which is what a production goroutine dump of a wedged
// account shows.
func goroutinesParkedInPool(fn string) int {
	buf := make([]byte, 4<<20)
	n := runtime.Stack(buf, true)
	parked := 0
	for _, g := range strings.Split(string(buf[:n]), "\n\n") {
		if strings.Contains(g, "(*WaitPool).Get") && strings.Contains(g, fn) {
			parked++
		}
	}
	return parked
}

// poolWaiterStacks returns the frames of every goroutine parked in WaitPool.Get
// or waiting inside Device.Close, for failure diagnostics.
func poolWaiterStacks() string {
	buf := make([]byte, 4<<20)
	n := runtime.Stack(buf, true)
	var out []string
	for _, g := range strings.Split(string(buf[:n]), "\n\n") {
		if !strings.Contains(g, "(*WaitPool).Get") && !strings.Contains(g, "(*Device).Close") {
			continue
		}
		var frames []string
		for _, l := range strings.Split(g, "\n") {
			if strings.HasPrefix(l, "goroutine ") || strings.HasPrefix(l, "golang.zx2c4.com") {
				frames = append(frames, l)
			}
		}
		out = append(out, strings.Join(frames, " | "))
	}
	return strings.Join(out, "\n")
}

// wedgeDiagnostics describes the Device's state for a failure message: how
// many tunnel goroutines are parked in the pool and their stacks.
func wedgeDiagnostics() string {
	return fmt.Sprintf("TUN readers parked in WaitPool.Get: %d, receive goroutines parked: %d\n%s",
		goroutinesParkedInPool("RoutineReadFromTUN"), goroutinesParkedInPool("RoutineReceiveIncoming"), poolWaiterStacks())
}

// TestCappedPool_UnreachablePeerMustNotStallHealthyPeer: one peer that cannot
// complete its handshake must not stop traffic for the other peers on the same
// Device. On a fork that parks in the pool twelve packets staged for that peer exhaust the
// sixteen-buffer pool, the TUN reader parks in WaitPool.Get, and traffic for
// the healthy peer never leaves: every service of the account times out.
func TestCappedPool_UnreachablePeerMustNotStallHealthyPeer(t *testing.T) {
	pair := newTunnelPair(t, operatorPoolCap, operatorBatchSize)
	drainPoolWithUnreachablePeer(t, pair)

	assert.True(t, pingEventually(t, pair, 0, 1, wedgeProbeTimeout),
		"traffic to the healthy peer stopped while one peer cannot handshake\n%s", wedgeDiagnostics())
}

// TestCappedPool_InboundBurstMustNotStallHealthyAccount needs no unreachable
// peer at all. Every inbound segment the netstack accepts makes it emit a reply
// synchronously inside the receiver's Write, and that reply has to be taken by
// the TUN reader, which needs a buffer for it. On a fork that parks in the pool a burst of
// inbound packets fills the pool from the receive side, the TUN reader parks
// on the buffer for its reply, the receiver blocks handing over the next one,
// and no timer ever returns a buffer: the 38-minute wedge from the production
// dump, the sequential receiver stuck in WriteNotify while replying with a RST.
func TestCappedPool_InboundBurstMustNotStallHealthyAccount(t *testing.T) {
	stop := afterDeviceClose(t)
	pair := newTunnelPair(t, operatorPoolCap, operatorBatchSize)
	answered := startReplyingStack(t, pair, stop)
	drainTUN(t, pair[1].tun, stop)
	stopFlood := floodTUN(t, pair[1].tun, tuntest.Ping(pair[0].ip, pair[1].ip))

	// Let the burst reach the capped pool, then watch whether answers keep
	// flowing. Dropping some under pressure is fine; stopping is not.
	time.Sleep(2 * time.Second)
	before := answered.Load()
	time.Sleep(3 * time.Second)
	assert.Greater(t, answered.Load(), before,
		"the account stopped answering inbound traffic (%d answered, then none for 3s)\n%s", before, wedgeDiagnostics())

	// Recovery so the Devices can close on a fork that parks in the pool.
	pair[0].dev.SetPreallocatedBuffersPerPool(0)
	stopFlood()
	waitQuiescent(t, answered)
}

// TestCappedPool_PeerRemovalMustNotHangOnExhaustedPool is the chain the
// production dump showed: removing a peer (what a network map update or the
// lazy inactivity check does) runs Peer.Stop, which waits for the sequential
// receiver; on a fork that parks in the pool that receiver is stuck delivering into the
// netstack behind the parked TUN reader, so the removal never returns, the
// IpcSet holds ipcMutex for as long as that takes, the stats call behind every
// status check queues on it, and in the proxy the same removal also holds the
// engine's syncMsgMux and the interface mutex the dials need.
func TestCappedPool_PeerRemovalMustNotHangOnExhaustedPool(t *testing.T) {
	stop := afterDeviceClose(t)
	pair := newTunnelPair(t, operatorPoolCap, operatorBatchSize)
	answered := startReplyingStack(t, pair, stop)
	drainTUN(t, pair[1].tun, stop)
	stopFlood := floodTUN(t, pair[1].tun, tuntest.Ping(pair[0].ip, pair[1].ip))
	time.Sleep(2 * time.Second)

	dev1Pub := pair[1].key.PublicKey()
	removed := make(chan error, 1)
	go func() {
		removed <- pair[0].dev.IpcSet(uapiConfig(
			"public_key", hex.EncodeToString(dev1Pub[:]),
			"remove", "true",
		))
	}()
	statsDone := make(chan struct{})
	go func() {
		_, _ = pair[0].dev.IpcGet()
		close(statsDone)
	}()

	removalDone := false
	select {
	case err := <-removed:
		removalDone = true
		assert.NoError(t, err, "peer removal must succeed")
	case <-time.After(wedgeProbeTimeout):
		t.Errorf("peer removal hung for %s: Peer.Stop is waiting for a receiver parked behind the pool\n%s", wedgeProbeTimeout, wedgeDiagnostics())
	}
	select {
	case <-statsDone:
	case <-time.After(time.Second):
		t.Errorf("IpcGet (the stats and status path) hung behind ipcMutex held by the peer removal")
	}

	// Recovery so the Devices can close on a fork that parks in the pool.
	pair[0].dev.SetPreallocatedBuffersPerPool(0)
	if !removalDone {
		select {
		case <-removed:
		case <-time.After(wedgeSettleTimeout):
			t.Fatal("peer removal did not complete even after the pool cap was lifted")
		}
	}
	<-statsDone
	stopFlood()
	waitQuiescent(t, answered)
	waitSendersIdle(t)
}

// TestCappedPool_CloseMustNotHangOnExhaustedPool is the form reached through
// client.Stop. On a fork that parks in the pool, once inbound datagrams have parked every
// receive goroutine in the pool, Device.Close waits for those goroutines in
// closeBindLocked before it flushes the peers that hold the buffers, while
// holding ipcMutex, so the account can be neither stopped nor inspected.
func TestCappedPool_CloseMustNotHangOnExhaustedPool(t *testing.T) {
	pair := newTunnelPair(t, operatorPoolCap, operatorBatchSize)
	drainPoolWithUnreachablePeer(t, pair)
	sendInboundVia(t, pair, "127.0.0.1:2")
	sendInboundVia(t, pair, "127.0.0.1:4")
	time.Sleep(500 * time.Millisecond)

	closed := make(chan struct{})
	go func() {
		pair[0].dev.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(wedgeProbeTimeout):
		t.Errorf("Device.Close hung for %s waiting in closeBindLocked for goroutines parked in the pool\n%s", wedgeProbeTimeout, wedgeDiagnostics())
		pair[0].dev.SetPreallocatedBuffersPerPool(0)
		select {
		case <-closed:
		case <-time.After(wedgeSettleTimeout):
			t.Fatal("Device.Close did not complete even after the pool cap was lifted")
		}
	}
}

// TestCappedPool_InboundBurstUncappedKeepsFlowing is the control: the same
// burst against an uncapped Device keeps being answered.
func TestCappedPool_InboundBurstUncappedKeepsFlowing(t *testing.T) {
	stop := afterDeviceClose(t)
	pair := newTunnelPair(t, 0, operatorBatchSize)
	answered := startReplyingStack(t, pair, stop)
	drainTUN(t, pair[1].tun, stop)
	stopFlood := floodTUN(t, pair[1].tun, tuntest.Ping(pair[0].ip, pair[1].ip))

	time.Sleep(time.Second)
	first := answered.Load()
	time.Sleep(time.Second)
	assert.Greater(t, first, int64(0), "the stack must be answering packets")
	assert.Greater(t, answered.Load(), first, "answers must keep flowing with an uncapped pool")

	stopFlood()
	waitQuiescent(t, answered)
}

// TestCappedPool_UncappedDeviceUnaffected is the control for the unreachable
// peer: with NB_PROXY_PREALLOCATED_BUFFERS unset the same traffic pattern pins
// at most MaxStagedPackets buffers for that peer and the healthy peer keeps
// working.
func TestCappedPool_UncappedDeviceUnaffected(t *testing.T) {
	pair := newTunnelPair(t, 0, operatorBatchSize)
	deadIP := addUnreachablePeer(t, pair[0].dev)
	floodUnreachablePeer(t, pair, deadIP)
	time.Sleep(500 * time.Millisecond)

	assert.True(t, pingThrough(t, pair, 0, 1, wedgeProbeTimeout), "ping to the healthy peer must be delivered with an uncapped pool")
	assert.True(t, pingThrough(t, pair, 1, 0, wedgeProbeTimeout), "ping from the healthy peer must be delivered with an uncapped pool")
}

// TestCappedPool_LargeCapUnaffected shows a cap above the eager floor plus
// MaxStagedPackets is safe for a single unreachable peer.
func TestCappedPool_LargeCapUnaffected(t *testing.T) {
	pair := newTunnelPair(t, 4096, operatorBatchSize)
	deadIP := addUnreachablePeer(t, pair[0].dev)
	floodUnreachablePeer(t, pair, deadIP)
	time.Sleep(500 * time.Millisecond)

	assert.True(t, pingThrough(t, pair, 0, 1, wedgeProbeTimeout), "ping to the healthy peer must be delivered with cap 4096")
}
