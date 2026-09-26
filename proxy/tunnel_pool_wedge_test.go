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

// These tests reproduce what NB_PROXY_PREALLOCATED_BUFFERS=16 together with
// NB_PROXY_MAX_BATCH_SIZE=1 does to one account's tunnel Device as soon as a
// peer with allowed IPs cannot complete its handshake: an offline backend, or a
// lazy-connection placeholder peer whose activation never succeeds.
//
// The tests assert the defective behaviour on purpose. They document the
// failure mode the operator sees in production and must be inverted once the
// wireguard-go fork drops packets instead of blocking on an exhausted pool.

const (
	// operatorPoolCap and operatorBatchSize mirror the production settings
	// NB_PROXY_PREALLOCATED_BUFFERS=16 and NB_PROXY_MAX_BATCH_SIZE=1.
	operatorPoolCap   = 16
	operatorBatchSize = 1

	wedgeSettleTimeout = 10 * time.Second
	wedgeProbeTimeout  = 3 * time.Second
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
		// Lift the cap before closing: Close waits for goroutines parked in
		// the pool and hangs forever on a wedged Device otherwise.
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
	var once sync.Once
	stop = func() { once.Do(func() { close(ch) }) }
	t.Cleanup(stop)
	go func() {
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

// waitPoolDrained blocks until dev's message buffer pool refuses a TryGet.
func waitPoolDrained(t *testing.T, dev *device.Device) {
	t.Helper()
	require.Eventually(t, func() bool {
		buf, ok := dev.TryGetMessageBuffer()
		if ok {
			dev.PutMessageBuffer(buf)
		}
		return !ok
	}, wedgeSettleTimeout, 20*time.Millisecond, "the staged packets never exhausted the capped pool")
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

func goroutineParkedInPool(fn string) bool {
	return goroutinesParkedInPool(fn) > 0
}

// goroutineWaitingIn reports whether some goroutine is currently inside fn.
func goroutineWaitingIn(fn string) bool {
	buf := make([]byte, 4<<20)
	n := runtime.Stack(buf, true)
	return strings.Contains(string(buf[:n]), fn)
}

// parkReceiveGoroutine points dev1 at one of dev0's two channel-bind sockets
// (port 2 is dev0's first receive function, port 4 its second) and sends one
// packet, which parks that receive goroutine on the replacement buffer it needs
// after handing the packet off. In production keepalives and handshakes on the
// v4, v6 and relay sockets do this within seconds of the pool draining.
func parkReceiveGoroutine(t *testing.T, pair [2]tunnelPeer, endpoint string) {
	t.Helper()
	before := goroutinesParkedInPool("RoutineReceiveIncoming")
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
	require.Eventually(t, func() bool { return goroutinesParkedInPool("RoutineReceiveIncoming") > before },
		wedgeSettleTimeout, 20*time.Millisecond, "a RoutineReceiveIncoming goroutine must park in WaitPool.Get")
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

// wedgeDevice reproduces the operator scenario on dev0: one unreachable peer
// receives traffic until the capped pool is empty. It returns once
// RoutineReadFromTUN is parked in the pool.
func wedgeDevice(t *testing.T, pair [2]tunnelPeer) {
	t.Helper()
	deadIP := addUnreachablePeer(t, pair[0].dev)
	floodUnreachablePeer(t, pair, deadIP)
	waitPoolDrained(t, pair[0].dev)
	require.Eventually(t, func() bool { return goroutineParkedInPool("RoutineReadFromTUN") },
		wedgeSettleTimeout, 20*time.Millisecond, "RoutineReadFromTUN must park in WaitPool.Get once the pool is empty")
}

// TestRepro_CappedPool_UnreachablePeerWedgesAccount is the operator
// configuration. Twelve staged packets for one peer that cannot handshake
// exhaust the sixteen-buffer pool, the TUN reader parks in WaitPool.Get, and
// traffic for the healthy peer on the same Device never leaves: every service
// of that account times out.
func TestRepro_CappedPool_UnreachablePeerWedgesAccount(t *testing.T) {
	pair := newTunnelPair(t, operatorPoolCap, operatorBatchSize)
	wedgeDevice(t, pair)

	delivered := pingThrough(t, pair, 0, 1, wedgeProbeTimeout)
	assert.False(t, delivered, "ping to the healthy peer must not be delivered while the pool is exhausted")
}

// TestRepro_CappedPool_CloseHangsOnWedgedDevice is the permanent form the
// operator sees as "debug status hangs, only a restart helps". Once inbound
// datagrams have parked every receive goroutine in the pool, Device.Close waits
// for those goroutines in closeBindLocked before it flushes the peers that hold
// the buffers, while holding ipcMutex. Every client.Stop, IpcGet and status
// call on that account blocks until the cap is lifted or the process restarts.
func TestRepro_CappedPool_CloseHangsOnWedgedDevice(t *testing.T) {
	pair := newTunnelPair(t, operatorPoolCap, operatorBatchSize)
	wedgeDevice(t, pair)
	parkReceiveGoroutine(t, pair, "127.0.0.1:2")
	parkReceiveGoroutine(t, pair, "127.0.0.1:4")

	closed := make(chan struct{})
	go func() {
		pair[0].dev.Close()
		close(closed)
	}()
	require.Eventually(t, goroutineWaitingInCloseBind, wedgeSettleTimeout, 20*time.Millisecond,
		"Device.Close must reach closeBindLocked")

	// Close holds ipcMutex for its whole duration, so the stats and status
	// paths queue up behind it.
	ipcDone := make(chan struct{})
	go func() {
		_, _ = pair[0].dev.IpcGet()
		close(ipcDone)
	}()

	select {
	case <-closed:
		t.Fatalf("Device.Close returned on a wedged Device; expected it to hang in closeBindLocked\n%s", poolWaiterStacks())
	case <-time.After(wedgeProbeTimeout):
	}
	select {
	case <-ipcDone:
		t.Fatal("IpcGet returned while Close held ipcMutex; expected the status path to hang")
	default:
	}

	// Lifting the cap is the only recovery short of a restart. This is what
	// `netbird-proxy debug perf <n>` does for every account.
	pair[0].dev.SetPreallocatedBuffersPerPool(0)
	select {
	case <-closed:
	case <-time.After(wedgeSettleTimeout):
		t.Fatal("Device.Close did not complete after the pool cap was lifted")
	}
	select {
	case <-ipcDone:
	case <-time.After(wedgeSettleTimeout):
		t.Fatal("IpcGet did not complete after the pool cap was lifted")
	}
}

func goroutineWaitingInCloseBind() bool {
	return goroutineWaitingIn("device.closeBindLocked")
}

// TestRepro_CappedPool_InboundBurstWedgesHealthyAccount needs no unreachable
// peer at all. Every inbound segment the netstack accepts makes it emit a reply
// synchronously inside the receiver's Write, and that reply has to be taken by
// the TUN reader, which needs a buffer for it. A burst of inbound packets fills
// the sixteen-buffer pool from the receive side, the TUN reader parks on the
// buffer for its reply, the receiver blocks handing over the next one, and no
// timer ever returns a buffer. This is the 38-minute wedge from the production
// dump: the sequential receiver stuck in WriteNotify while replying with a RST.
func TestRepro_CappedPool_InboundBurstWedgesHealthyAccount(t *testing.T) {
	stop := afterDeviceClose(t)
	pair := newTunnelPair(t, operatorPoolCap, operatorBatchSize)
	answered := startReplyingStack(t, pair, stop)
	drainTUN(t, pair[1].tun, stop)
	stopFlood := floodTUN(t, pair[1].tun, tuntest.Ping(pair[0].ip, pair[1].ip))

	require.Eventually(t, func() bool { return goroutineParkedInPool("RoutineReadFromTUN") },
		wedgeSettleTimeout, 20*time.Millisecond, "RoutineReadFromTUN must park in WaitPool.Get")
	require.Eventually(t, func() bool { return goroutineIn("RoutineSequentialReceiver", "(*chTun).Write") },
		wedgeSettleTimeout, 20*time.Millisecond, "the sequential receiver must block delivering into the stack")

	before := answered.Load()
	time.Sleep(2 * time.Second)
	assert.Equal(t, before, answered.Load(), "no packet may be answered while the Device is wedged")

	pair[0].dev.SetPreallocatedBuffersPerPool(0)
	require.Eventually(t, func() bool { return answered.Load() > before },
		wedgeSettleTimeout, 20*time.Millisecond, "traffic must resume once the cap is lifted")

	stopFlood()
	waitQuiescent(t, answered)
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

// TestCappedPool_UncappedDeviceUnaffected is the control for the wedge: with
// NB_PROXY_PREALLOCATED_BUFFERS unset the same traffic pattern pins at most
// MaxStagedPackets buffers for the unreachable peer and the healthy peer keeps
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
