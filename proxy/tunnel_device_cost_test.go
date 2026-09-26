package proxy

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	wgconn "golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Every account the proxy serves owns one netstack-mode tunnel Device. This
// test measures what a single Device costs the process under the default
// settings, the operator settings and the recommended settings, and prints the
// extrapolation to 5,000 accounts. The invariants it asserts are the ones the
// tuning knobs cannot change or do change: worker goroutines scale with
// runtime.NumCPU regardless of the knobs, eager message buffers scale with the
// batch size.

const (
	costSampleDevices   = 8
	costTargetAccounts  = 5000
	costMessageBufBytes = device.MaxMessageSize
)

// newNetstackDevice mirrors what an embedded netstack-mode client owns per
// account: a gVisor stack, a real UDP bind on an ephemeral port, a
// wireguard-go Device and one configured peer.
func newNetstackDevice(t *testing.T, idx int) *device.Device {
	t.Helper()
	tunDev, _, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.AddrFrom4([4]byte{100, 64, byte(idx / 256), byte(idx%256 + 1)})},
		[]netip.Addr{netip.MustParseAddr("100.64.0.254")}, 1280)
	require.NoError(t, err)

	dev := device.NewDevice(tunDev, wgconn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	peerKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	peerPub := peerKey.PublicKey()
	cfg := fmt.Sprintf("private_key=%s\nlisten_port=0\npublic_key=%s\nallowed_ip=100.100.0.1/32\n",
		hex.EncodeToString(key[:]), hex.EncodeToString(peerPub[:]))
	require.NoError(t, dev.IpcSet(cfg))
	require.NoError(t, dev.Up())
	return dev
}

type deviceCost struct {
	goroutines float64
	heapBytes  float64
	batchSize  int
}

func heapInUse() float64 {
	runtime.GC()
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return float64(ms.HeapInuse)
}

// measureDeviceCost creates costSampleDevices Devices under the given pool cap
// and batch override and returns the per-Device delta in goroutines and heap.
func measureDeviceCost(t *testing.T, poolCap, batch uint32) deviceCost {
	t.Helper()
	device.SetPreallocatedBuffersPerPool(poolCap)
	device.SetMaxBatchSizeOverride(batch)
	t.Cleanup(func() {
		device.SetPreallocatedBuffersPerPool(0)
		device.SetMaxBatchSizeOverride(0)
	})

	goroutinesBefore := runtime.NumGoroutine()
	heapBefore := heapInUse()

	devs := make([]*device.Device, 0, costSampleDevices)
	t.Cleanup(func() {
		for _, d := range devs {
			d.SetPreallocatedBuffersPerPool(0)
			d.Close()
		}
	})
	for i := 0; i < costSampleDevices; i++ {
		devs = append(devs, newNetstackDevice(t, i))
	}
	// Eager buffers are taken by the receive goroutines once they start; give
	// them a moment before sampling.
	time.Sleep(200 * time.Millisecond)

	return deviceCost{
		goroutines: float64(runtime.NumGoroutine()-goroutinesBefore) / costSampleDevices,
		heapBytes:  (heapInUse() - heapBefore) / costSampleDevices,
		batchSize:  devs[0].BatchSize(),
	}
}

func logDeviceCost(t *testing.T, name string, c deviceCost) {
	t.Helper()
	t.Logf("%s: batch=%d NumCPU=%d GOMAXPROCS=%d goroutines/device=%.1f heap/device=%.1f MiB => %d accounts: %.0f goroutines, %.1f GiB heap",
		name, c.batchSize, runtime.NumCPU(), runtime.GOMAXPROCS(0), c.goroutines, c.heapBytes/(1<<20),
		costTargetAccounts, c.goroutines*costTargetAccounts, c.heapBytes*costTargetAccounts/(1<<30))
}

// TestTunnelDeviceCost_WorkerGoroutinesScaleWithNumCPU: each Device starts an
// encryption, a decryption and a handshake worker per CPU visible to the
// process (the affinity mask, not the cgroup quota), plus the TUN reader,
// event reader and receive goroutines. Neither tuning knob changes this.
func TestTunnelDeviceCost_WorkerGoroutinesScaleWithNumCPU(t *testing.T) {
	if testing.Short() {
		t.Skip("creates real sockets and gVisor stacks")
	}
	floor := float64(3*runtime.NumCPU() + 2)
	for _, tc := range []struct {
		name    string
		poolCap uint32
		batch   uint32
	}{
		{name: "defaults", poolCap: 0, batch: 0},
		{name: "operator cap=16 batch=1", poolCap: operatorPoolCap, batch: operatorBatchSize},
		{name: "recommended cap=0 batch=1", poolCap: 0, batch: operatorBatchSize},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := measureDeviceCost(t, tc.poolCap, tc.batch)
			logDeviceCost(t, tc.name, c)
			assert.GreaterOrEqual(t, c.goroutines, floor, "goroutines per Device must include 3 workers per CPU")
		})
	}
}

// TestTunnelDeviceCost_EagerBuffersScaleWithBatchSize: on Linux the default
// bind batch size is 128 and every receive goroutine and the TUN reader
// pre-take that many 64 KiB message buffers. A batch override of 1 removes
// that cost, which is why NB_PROXY_MAX_BATCH_SIZE=1 makes the proxy start.
func TestTunnelDeviceCost_EagerBuffersScaleWithBatchSize(t *testing.T) {
	if testing.Short() {
		t.Skip("creates real sockets and gVisor stacks")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the default bind batch size is 128 only on linux")
	}

	defaults := measureDeviceCost(t, 0, 0)
	logDeviceCost(t, "defaults", defaults)
	require.Equal(t, wgconn.IdealBatchSize, defaults.batchSize, "default Device batch size on linux")

	// At least the TUN reader and one receive goroutine take a full batch of
	// buffers each; a second UDP socket family adds another batch.
	minEager := float64(2 * wgconn.IdealBatchSize * costMessageBufBytes)
	assert.GreaterOrEqual(t, defaults.heapBytes, minEager*0.9, "eager buffers at batch=128 must dominate the per-Device heap")

	batchOne := measureDeviceCost(t, 0, operatorBatchSize)
	logDeviceCost(t, "batch=1", batchOne)
	assert.Equal(t, int(operatorBatchSize), batchOne.batchSize, "batch override must apply")
	assert.Less(t, batchOne.heapBytes, minEager/4, "batch=1 must remove the eager buffer cost")
}
