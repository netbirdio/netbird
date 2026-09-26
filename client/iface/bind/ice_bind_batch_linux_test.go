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
)

// The tunnel hands the receiver as many buffers as its batch size, and under
// NB_PROXY_MAX_BATCH_SIZE=1 that is a single buffer per call. The receiver's
// recvmmsg message array is still IdealBatchSize long, so slots beyond the
// buffers it was given carry nothing: without GRO a burst lands in them and the
// receiver indexes past its sizes slice, with GRO every read targets them and
// each datagram is truncated to nothing. Both tests state that every datagram
// must arrive and fail on the current code.

const smallBatchDatagrams = 4

type smallBatchResult struct {
	delivered int
	panicked  bool
	panicMsg  string
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

func enableUDPGRO(t *testing.T, conn *net.UDPConn) {
	t.Helper()
	rc, err := conn.SyscallConn()
	require.NoError(t, err)
	var sockErr error
	require.NoError(t, rc.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO, 1)
	}))
	if sockErr != nil {
		t.Skipf("UDP GRO not available: %v", sockErr)
	}
}

func sendDatagrams(t *testing.T, to net.Addr, n int) {
	t.Helper()
	sender, err := net.DialUDP("udp4", nil, to.(*net.UDPAddr))
	require.NoError(t, err)
	defer sender.Close()
	for i := 0; i < n; i++ {
		_, err := sender.Write([]byte(fmt.Sprintf("datagram-%d", i)))
		require.NoError(t, err)
	}
	// Let the datagrams reach the socket queue before the reader looks.
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
	for res.delivered < want {
		select {
		case <-payloads:
			res.delivered++
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

	sendDatagrams(t, conn.LocalAddr(), smallBatchDatagrams)
	payloads, panics := startSmallBatchReceiver(recvFn)
	res := collectDatagrams(payloads, panics, smallBatchDatagrams, 2*time.Second)

	assert.False(t, res.panicked, "the receiver panicked on a burst wider than its batch: %s", res.panicMsg)
	assert.Equal(t, smallBatchDatagrams, res.delivered,
		"recvmmsg filled message slots beyond the buffers the tunnel handed over")
}

func TestICEBind_SmallBatchMustDeliverWithGRO(t *testing.T) {
	iceBind := setupICEBind(t)
	conn := listenUDP(t, "udp4", "127.0.0.1:0")
	t.Cleanup(func() { _ = conn.Close() })
	enableUDPGRO(t, conn)
	recvFn := receiverCreator{iceBind}.CreateReceiverFn(ipv4.NewPacketConn(conn), conn, true, batchMsgPool())

	payloads, panics := startSmallBatchReceiver(recvFn)
	sendDatagrams(t, conn.LocalAddr(), 1)
	first := collectDatagrams(payloads, panics, 1, time.Second)
	sendDatagrams(t, conn.LocalAddr(), smallBatchDatagrams-1)
	rest := collectDatagrams(payloads, panics, smallBatchDatagrams-1, time.Second)

	assert.False(t, first.panicked || rest.panicked, "the receiver panicked: %s%s", first.panicMsg, rest.panicMsg)
	assert.Equal(t, smallBatchDatagrams, first.delivered+rest.delivered,
		"the coalesced read landed in message slots that carry no buffer")
}
