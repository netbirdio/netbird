//go:build linux

package proxy

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	wgconn "golang.zx2c4.com/wireguard/conn"
)

// The batch override behind NB_PROXY_MAX_BATCH_SIZE changes how many buffers a
// Device hands to the bind's receive function, but StdNetBind (and the ICEBind
// receiver that copies its logic) still sizes its recvmmsg message array at
// IdealBatchSize and, with UDP GRO enabled, reads into the tail of that array.
// Slots the Device did not attach a buffer to receive nothing, so the kernel
// truncates the datagram and it is dropped. The test below states that a
// smaller batch must still deliver every datagram; it failed on the fork before
// netbirdio/wireguard-go#22 made the bind read one message per buffer.

const (
	bindProbeDatagrams = 4
	bindProbeTimeout   = 1500 * time.Millisecond
)

type bindReceiveResult struct {
	payloads []string
	panicked bool
	panicMsg string
}

func probeDatagrams() []string {
	var out []string
	for i := 0; i < bindProbeDatagrams; i++ {
		out = append(out, fmt.Sprintf("datagram-%d", i))
	}
	return out
}

// freeUDPPort returns a UDP port that was free a moment ago.
func freeUDPPort(t *testing.T) uint16 {
	t.Helper()
	probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	port := probe.LocalAddr().(*net.UDPAddr).Port
	require.NoError(t, probe.Close())
	return uint16(port)
}

// receiveWithBatch opens a fresh StdNetBind, queues bindProbeDatagrams on it,
// then drains its receive functions with batch buffers per call (what a Device
// created under a batch override does) and reports what came out. The burst
// is queued before the first read so that one recvmmsg sees all of it.
func receiveWithBatch(t *testing.T, batch int) bindReceiveResult {
	t.Helper()

	// Open reports port 0 when the host has no IPv6 (the udp6 listen fails
	// with EAFNOSUPPORT after the udp4 one succeeded), so pick the port here.
	port := freeUDPPort(t)
	bind := wgconn.NewStdNetBind()
	fns, _, err := bind.Open(port)
	require.NoError(t, err)
	require.NotEmpty(t, fns, "bind must expose at least one receive function")
	t.Cleanup(func() { _ = bind.Close() })

	sender, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = sender.Close() })
	for _, payload := range probeDatagrams() {
		_, err := sender.Write([]byte(payload))
		require.NoError(t, err)
	}
	time.Sleep(50 * time.Millisecond)

	payloads := make(chan []byte, 64)
	panics := make(chan string, len(fns))
	var wg sync.WaitGroup
	for _, fn := range fns {
		wg.Add(1)
		go func(fn wgconn.ReceiveFunc) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					panics <- fmt.Sprint(r)
				}
			}()
			bufs := make([][]byte, batch)
			for i := range bufs {
				bufs[i] = make([]byte, wgconn.IdealBatchSize*16)
			}
			sizes := make([]int, batch)
			eps := make([]wgconn.Endpoint, batch)
			for {
				n, err := fn(bufs, sizes, eps)
				if err != nil {
					return
				}
				for i := 0; i < n; i++ {
					if sizes[i] == 0 {
						continue
					}
					payloads <- append([]byte(nil), bufs[i][:sizes[i]]...)
				}
			}
		}(fn)
	}

	var res bindReceiveResult
	deadline := time.After(bindProbeTimeout)
collect:
	for {
		select {
		case p := <-payloads:
			res.payloads = append(res.payloads, string(p))
			if len(res.payloads) == bindProbeDatagrams {
				break collect
			}
		case msg := <-panics:
			res.panicked = true
			res.panicMsg = msg
			break collect
		case <-deadline:
			break collect
		}
	}

	_ = bind.Close()
	wg.Wait()
	return res
}

// TestBindReceive_IdealBatchDeliversDatagrams is the control: with the default
// batch size every datagram reaches the Device.
func TestBindReceive_IdealBatchDeliversDatagrams(t *testing.T) {
	res := receiveWithBatch(t, wgconn.IdealBatchSize)
	assert.False(t, res.panicked, "receive function panicked: %s", res.panicMsg)
	assert.ElementsMatch(t, probeDatagrams(), res.payloads, "all datagrams must be delivered with the ideal batch size")
}

// TestBindReceive_BatchOverrideOneMustDeliverDatagrams states that
// NB_PROXY_MAX_BATCH_SIZE=1 must not cost direct UDP reception on Linux. On
// a fork that reads the whole message array, with UDP GRO (kernel 5.12+) the receive function reads into
// message slots that carry no buffer and every datagram is truncated and
// dropped; without GRO a burst overruns the one-element sizes slice and the
// receive goroutine panics. Either way direct peer traffic to the proxy is lost
// and only relayed traffic works.
func TestBindReceive_BatchOverrideOneMustDeliverDatagrams(t *testing.T) {
	res := receiveWithBatch(t, 1)
	assert.False(t, res.panicked, "the receive goroutine panicked with a batch override of 1: %s", res.panicMsg)
	assert.ElementsMatch(t, probeDatagrams(), res.payloads,
		"the bind lost direct UDP datagrams with a batch override of 1 (recvmmsg slots beyond len(bufs) carry no buffer)")
}
