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
// truncates the datagram and it is dropped. This test reproduces that on the
// real bind.

const (
	bindProbeDatagrams = 4
	bindProbeTimeout   = 1500 * time.Millisecond
)

type bindReceiveResult struct {
	delivered int
	panicked  bool
	panicMsg  string
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

// receiveWithBatch opens a fresh StdNetBind, drains its receive functions with
// batch buffers per call (what a Device created under a batch override does),
// sends bindProbeDatagrams to it and reports how many came out.
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

	sender, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = sender.Close() })
	for i := 0; i < bindProbeDatagrams; i++ {
		_, err := sender.Write([]byte(fmt.Sprintf("datagram-%d", i)))
		require.NoError(t, err)
	}

	var res bindReceiveResult
	deadline := time.After(bindProbeTimeout)
collect:
	for {
		select {
		case <-payloads:
			res.delivered++
			if res.delivered == bindProbeDatagrams {
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
	assert.Equal(t, bindProbeDatagrams, res.delivered, "all datagrams must be delivered with the ideal batch size")
}

// TestRepro_BindReceive_BatchOverrideOneLosesDatagrams shows what
// NB_PROXY_MAX_BATCH_SIZE=1 does to direct UDP reception on Linux. With UDP GRO
// (kernel 5.12+) the receive function reads into message slots that carry no
// buffer and every datagram is truncated and dropped; without GRO a burst
// overruns the one-element sizes slice and the receive goroutine panics. Either
// way direct peer traffic to the proxy is lost and only relayed traffic works.
func TestRepro_BindReceive_BatchOverrideOneLosesDatagrams(t *testing.T) {
	res := receiveWithBatch(t, 1)
	t.Logf("batch=1: delivered=%d/%d panicked=%v %s", res.delivered, bindProbeDatagrams, res.panicked, res.panicMsg)
	assert.True(t, res.panicked || res.delivered < bindProbeDatagrams,
		"expected datagram loss or a panic with a batch override of 1; the bind delivered everything")
}
