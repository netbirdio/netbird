//go:build linux

package bind

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
	wgConn "golang.zx2c4.com/wireguard/conn"
	wgdevice "golang.zx2c4.com/wireguard/device"
)

// The tunnel hands the receiver as many buffers as its batch size, and under
// NB_PROXY_MAX_BATCH_SIZE=1 that is a single buffer per call. The receiver's
// recvmmsg message array is still IdealBatchSize long, so slots beyond the
// buffers it was given carry nothing: without GRO a burst lands in them and the
// receiver indexes past its sizes slice, with GRO every read targets them and
// each datagram is truncated to nothing. These tests state that every datagram
// must arrive, and that a socket opened under the override never has GRO on,
// since a datagram coalesced before GRO is switched off cannot be split later.

const smallBatchDatagrams = 4

type smallBatchResult struct {
	payloads []string
	panicked bool
	panicMsg string
}

func expectedDatagrams(from, n int) []string {
	var out []string
	for i := from; i < from+n; i++ {
		out = append(out, fmt.Sprintf("datagram-%d", i))
	}
	return out
}

// batchMsgPool mirrors the message pool StdNetBind hands to the receiver: one
// message per slot of the ideal batch, none of them carrying a buffer yet.
func batchMsgPool() *sync.Pool {
	return &sync.Pool{
		New: func() any {
			msgs := make([]ipv6.Message, wgConn.IdealBatchSize)
			for i := range msgs {
				msgs[i].Buffers = make(net.Buffers, 1)
				msgs[i].OOB = make([]byte, 0, 64)
			}
			return &msgs
		},
	}
}

func setUDPGRO(t *testing.T, conn *net.UDPConn, on int) error {
	t.Helper()
	rc, err := conn.SyscallConn()
	require.NoError(t, err)
	var sockErr error
	require.NoError(t, rc.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO, on)
	}))
	return sockErr
}

// udpGROEnabled reports whether UDP GRO is on for conn's socket; a kernel
// without getsockopt support for it reads as off.
func udpGROEnabled(t *testing.T, conn *net.UDPConn) bool {
	t.Helper()
	rc, err := conn.SyscallConn()
	require.NoError(t, err)
	enabled := false
	require.NoError(t, rc.Control(func(fd uintptr) {
		v, err := unix.GetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO)
		enabled = err == nil && v == 1
	}))
	return enabled
}

// sendDatagrams sends n payloads numbered from `from` to `to` and waits for
// them to reach the socket queue.
func sendDatagrams(t *testing.T, to net.Addr, from, n int) {
	t.Helper()
	sender, err := net.DialUDP("udp4", nil, to.(*net.UDPAddr))
	require.NoError(t, err)
	defer sender.Close()
	for _, payload := range expectedDatagrams(from, n) {
		_, err := sender.Write([]byte(payload))
		require.NoError(t, err)
	}
	time.Sleep(50 * time.Millisecond)
}

// startSmallBatchReceiver drives recvFn the way a tunnel created with a batch
// size of one does, one buffer per call, until the socket is closed.
func startSmallBatchReceiver(recvFn wgConn.ReceiveFunc) (payloads <-chan string, panics <-chan string) {
	out := make(chan string, 64)
	failed := make(chan string, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				failed <- fmt.Sprint(r)
			}
		}()
		bufs := [][]byte{make([]byte, 1<<16)}
		sizes := make([]int, 1)
		eps := make([]wgConn.Endpoint, 1)
		for {
			n, err := recvFn(bufs, sizes, eps)
			if err != nil {
				return
			}
			for i := 0; i < n; i++ {
				if sizes[i] > 0 {
					out <- string(bufs[i][:sizes[i]])
				}
			}
		}
	}()
	return out, failed
}

func collectDatagrams(payloads <-chan string, panics <-chan string, want int, timeout time.Duration) smallBatchResult {
	var res smallBatchResult
	deadline := time.After(timeout)
	for len(res.payloads) < want {
		select {
		case p := <-payloads:
			res.payloads = append(res.payloads, p)
		case msg := <-panics:
			res.panicked = true
			res.panicMsg = msg
			return res
		case <-deadline:
			return res
		}
	}
	return res
}

func TestICEBind_SmallBatchMustDeliverQueuedBurst(t *testing.T) {
	iceBind := setupICEBind(t)
	conn := listenUDP(t, "udp4", "127.0.0.1:0")
	t.Cleanup(func() { _ = conn.Close() })
	recvFn := receiverCreator{iceBind}.CreateReceiverFn(ipv4.NewPacketConn(conn), conn, false, batchMsgPool())

	// The burst is queued before the first read, so one recvmmsg sees all of it.
	sendDatagrams(t, conn.LocalAddr(), 0, smallBatchDatagrams)
	payloads, panics := startSmallBatchReceiver(recvFn)
	res := collectDatagrams(payloads, panics, smallBatchDatagrams, 2*time.Second)

	assert.False(t, res.panicked, "the receiver panicked on a burst wider than its batch: %s", res.panicMsg)
	assert.ElementsMatch(t, expectedDatagrams(0, smallBatchDatagrams), res.payloads,
		"recvmmsg filled message slots beyond the buffers the tunnel handed over")
}

func TestICEBind_SmallBatchMustDeliverWithGRO(t *testing.T) {
	iceBind := setupICEBind(t)
	conn := listenUDP(t, "udp4", "127.0.0.1:0")
	t.Cleanup(func() { _ = conn.Close() })
	if err := setUDPGRO(t, conn, 1); err != nil {
		t.Skipf("UDP GRO not available: %v", err)
	}
	recvFn := receiverCreator{iceBind}.CreateReceiverFn(ipv4.NewPacketConn(conn), conn, true, batchMsgPool())

	payloads, panics := startSmallBatchReceiver(recvFn)
	sendDatagrams(t, conn.LocalAddr(), 0, 1)
	first := collectDatagrams(payloads, panics, 1, time.Second)
	sendDatagrams(t, conn.LocalAddr(), 1, smallBatchDatagrams-1)
	rest := collectDatagrams(payloads, panics, smallBatchDatagrams-1, time.Second)

	assert.False(t, first.panicked || rest.panicked, "the receiver panicked: %s%s", first.panicMsg, rest.panicMsg)
	assert.ElementsMatch(t, expectedDatagrams(0, smallBatchDatagrams), append(first.payloads, rest.payloads...),
		"the coalesced read landed in message slots that carry no buffer")
}

// TestICEBind_OpenWithoutGROUnderSmallBatchOverride: under the proxy's batch
// size override the sockets must come up without GRO, so nothing is ever
// coalesced for a receiver that cannot split it.
func TestICEBind_OpenWithoutGROUnderSmallBatchOverride(t *testing.T) {
	t.Cleanup(func() { wgdevice.SetMaxBatchSizeOverride(0) })

	wgdevice.SetMaxBatchSizeOverride(0)
	if !udpGROEnabled(t, openICEBindIPv4(t)) {
		t.Skip("this kernel does not enable UDP GRO")
	}

	wgdevice.SetMaxBatchSizeOverride(1)
	assert.False(t, udpGROEnabled(t, openICEBindIPv4(t)),
		"UDP GRO is on for a socket opened under a batch size override of 1")
}

// openICEBindIPv4 opens a fresh ICEBind on an ephemeral port and returns its
// IPv4 socket.
func openICEBindIPv4(t *testing.T) *net.UDPConn {
	t.Helper()
	iceBind := setupICEBind(t)
	_, _, err := iceBind.Open(0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = iceBind.Close() })

	iceBind.muUDPMux.Lock()
	defer iceBind.muUDPMux.Unlock()
	require.NotNil(t, iceBind.ipv4Conn, "Open must create the IPv4 socket")
	return iceBind.ipv4Conn
}
