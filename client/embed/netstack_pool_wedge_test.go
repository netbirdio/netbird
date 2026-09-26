package embed

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	wgdevice "golang.zx2c4.com/wireguard/device"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/client/internal/peer"
	relayserver "github.com/netbirdio/netbird/relay/server"
	"github.com/netbirdio/netbird/shared/relay/auth/allow"
	sigProto "github.com/netbirdio/netbird/shared/signal/proto"
	signalserver "github.com/netbirdio/netbird/signal/server"
)

// End-to-end reproduction of the blocked-account symptom of the shared reverse
// proxy: an embedded netstack client created with the operator's tunnel
// tuning (NB_PROXY_PREALLOCATED_BUFFERS=16, NB_PROXY_MAX_BATCH_SIZE=1) stops
// serving HTTP through the tunnel under an ordinary burst of inbound data. The
// setup is real: an in-process management, signal and relay, two embedded
// clients registered with the same setup key, and HTTP responses fetched from
// one client's netstack through the other's.
//
// A batch override of 1 also makes the Linux bind drop every direct UDP
// datagram, so the capped client reaches its peer through the relay, exactly
// as the proxy does in production.

const (
	wedgeReproPoolCap    = 16
	wedgeReproBatchSize  = 1
	wedgeReproBodyBytes  = 512 << 10
	wedgeReproFetchers   = 4
	wedgeReproConnectFor = 90 * time.Second
	wedgeReproSettleFor  = 60 * time.Second
	testBackendPort      = "18080"
)

// startSignalServer runs the signal service on a loopback gRPC listener.
func startSignalServer(t *testing.T) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	s := grpc.NewServer()
	srv, err := signalserver.NewServer(context.Background(), otel.Meter(""))
	require.NoError(t, err)
	sigProto.RegisterSignalExchangeServer(s, srv)
	go func() {
		if err := s.Serve(lis); err != nil {
			t.Error(err)
		}
	}()
	t.Cleanup(s.Stop)
	return lis.Addr().String()
}

// startRelayServer runs a relay on loopback and returns its rel:// address.
func startRelayServer(t *testing.T) string {
	t.Helper()
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := probe.Addr().String()
	require.NoError(t, probe.Close())

	srv, err := relayserver.NewServer(relayserver.Config{
		Meter:          otel.Meter(""),
		ExposedAddress: "rel://" + addr,
		TLSSupport:     false,
		AuthValidator:  &allow.Auth{},
	})
	require.NoError(t, err)
	go func() {
		if err := srv.Listen(relayserver.ListenerConfig{Address: addr}); err != nil {
			t.Error(err)
		}
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	return "rel://" + addr
}

// resetTunnelTuning clears the process-global wireguard-go tuning that
// embed.New installs, before and after a test.
func resetTunnelTuning(t *testing.T) {
	t.Helper()
	wgdevice.SetPreallocatedBuffersPerPool(0)
	wgdevice.SetMaxBatchSizeOverride(0)
	t.Cleanup(func() {
		wgdevice.SetPreallocatedBuffersPerPool(0)
		wgdevice.SetMaxBatchSizeOverride(0)
	})
}

// startEmbeddedClient creates and starts a netstack client against mgmtAddr
// and stops it when the test ends.
func startEmbeddedClient(t *testing.T, name, mgmtAddr string, perf Performance) *Client {
	t.Helper()
	wgPort := 0
	eager := false
	client, err := New(Options{
		DeviceName:            name,
		SetupKey:              testSetupKey,
		ManagementURL:         "http://" + mgmtAddr,
		WireguardPort:         &wgPort,
		LazyConnectionEnabled: &eager,
		LogLevel:              "warn",
		Performance:           perf,
	})
	require.NoError(t, err)

	startCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	require.NoError(t, client.Start(startCtx), "%s must start", name)
	t.Cleanup(func() {
		// A wedged client cannot stop; the tests lift the cap before they
		// return so this completes, and the timeout keeps a failed run
		// from hanging the package.
		stopCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = client.Stop(stopCtx)
	})
	return client
}

// localOverlayIP returns the client's own address on the overlay.
func localOverlayIP(t *testing.T, client *Client) netip.Addr {
	t.Helper()
	status, err := client.Status()
	require.NoError(t, err)
	ip := status.LocalPeerState.IP
	if prefix, err := netip.ParsePrefix(ip); err == nil {
		return prefix.Addr()
	}
	addr, err := netip.ParseAddr(ip)
	require.NoError(t, err, "local overlay address %q", ip)
	return addr
}

// waitConnected blocks until client reports a connected tunnel to peerIP.
func waitConnected(t *testing.T, client *Client, peerIP netip.Addr) {
	t.Helper()
	require.Eventually(t, func() bool {
		status, err := client.Status()
		if err != nil {
			return false
		}
		for _, p := range status.Peers {
			if p.IP == peerIP.String() && p.ConnStatus == peer.StatusConnected {
				return true
			}
		}
		return false
	}, wedgeReproConnectFor, 250*time.Millisecond, "tunnel to %s must come up", peerIP)
}

// serveLargeBody listens on the backend's netstack and answers every request
// with wedgeReproBodyBytes of data.
func serveLargeBody(t *testing.T, backend *Client) {
	t.Helper()
	ln, err := backend.ListenTCP(":" + testBackendPort)
	require.NoError(t, err)
	body := strings.Repeat("x", wedgeReproBodyBytes)
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, body)
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
}

// fetchThrough downloads one body from the backend through front's tunnel.
func fetchThrough(front *Client, backendIP netip.Addr, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	url := fmt.Sprintf("http://%s/", net.JoinHostPort(backendIP.String(), testBackendPort))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	client := front.NewHTTPClient()
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	n, err := io.Copy(io.Discard, resp.Body)
	if err != nil {
		return err
	}
	if n != wedgeReproBodyBytes {
		return fmt.Errorf("short body: %d of %d bytes", n, wedgeReproBodyBytes)
	}
	return nil
}

// keepFetching runs wedgeReproFetchers download loops through front until stop
// is closed and reports how many downloads completed.
func keepFetching(t *testing.T, front *Client, backendIP netip.Addr) (completed func() int64, stop func()) {
	t.Helper()
	var (
		mu    sync.Mutex
		done  int64
		quit  = make(chan struct{})
		once  sync.Once
		group sync.WaitGroup
	)
	stop = func() {
		once.Do(func() { close(quit) })
		group.Wait()
	}
	t.Cleanup(stop)
	for i := 0; i < wedgeReproFetchers; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for {
				select {
				case <-quit:
					return
				default:
				}
				if err := fetchThrough(front, backendIP, 15*time.Second); err == nil {
					mu.Lock()
					done++
					mu.Unlock()
				}
			}
		}()
	}
	completed = func() int64 {
		mu.Lock()
		defer mu.Unlock()
		return done
	}
	return completed, stop
}

// keepProbingClosedPort has the backend dial a port nobody listens on at the
// front client until the test ends. Each SYN makes the front's netstack reply
// with a RST synchronously, inside the tunnel receiver's Write, which is the
// path the production dump showed parked: once the pool is empty that reply
// can never be handed to the TUN reader and the receiver holds its buffers
// for good. Established-connection traffic does not do this, its replies come
// from gVisor's own processor goroutines.
func keepProbingClosedPort(t *testing.T, backend *Client, frontIP netip.Addr) {
	t.Helper()
	quit := make(chan struct{})
	var group sync.WaitGroup
	t.Cleanup(func() {
		close(quit)
		group.Wait()
	})
	target := net.JoinHostPort(frontIP.String(), "9")
	group.Add(1)
	go func() {
		defer group.Done()
		for {
			select {
			case <-quit:
				return
			default:
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			if conn, err := backend.Dial(ctx, "tcp", target); err == nil {
				_ = conn.Close()
			}
			cancel()
		}
	}()
}

// tunReaderParkedFor reports whether a TUN reader stays parked in the pool
// across consecutive samples, which separates the permanent wedge from the
// short stalls a capped Device also goes through.
func tunReaderParkedFor(samples int, gap time.Duration) bool {
	for i := 0; i < samples; i++ {
		if !goroutineParkedInPool("RoutineReadFromTUN") {
			return false
		}
		time.Sleep(gap)
	}
	return true
}

// goroutineParkedInPool reports whether some goroutine is blocked inside
// WaitPool.Get while running fn, the signature of a wedged tunnel Device in a
// production goroutine dump.
func goroutineParkedInPool(fn string) bool {
	buf := make([]byte, 8<<20)
	n := runtime.Stack(buf, true)
	for _, g := range strings.Split(string(buf[:n]), "\n\n") {
		if strings.Contains(g, "(*WaitPool).Get") && strings.Contains(g, fn) {
			return true
		}
	}
	return false
}

// startTunnelPair brings up management, signal, relay, a backend client with
// default tuning and a front client with perf, and waits for the tunnel
// between them.
func startTunnelPair(t *testing.T, perf Performance) (front, backend *Client, backendIP netip.Addr) {
	t.Helper()
	resetTunnelTuning(t)
	signalAddr := startSignalServer(t)
	relayAddr := startRelayServer(t)
	mgmtAddr := startManagementWithRelay(t, signalAddr, relayAddr)

	// The tuning is process-global once installed, so the backend must be
	// running before the front client applies it.
	backend = startEmbeddedClient(t, "wedge-backend", mgmtAddr, Performance{})
	backendIP = localOverlayIP(t, backend)
	serveLargeBody(t, backend)

	front = startEmbeddedClient(t, "wedge-front", mgmtAddr, perf)
	waitConnected(t, front, backendIP)
	waitConnected(t, backend, localOverlayIP(t, front))
	return front, backend, backendIP
}

// TestRepro_NetstackClient_CappedPoolStallsUnderInboundBurst is the operator
// scenario end to end. A few concurrent downloads fill the front client's
// sixteen-buffer pool from the receive side and park its TUN reader in
// WaitPool.Get; while it is parked, a stray SYN to a closed port makes the
// netstack reply with a RST inside the tunnel receiver, which then waits for
// the parked reader with its buffers checked out. From there every request
// through that client times out until the cap is lifted, the way
// `netbird-proxy debug perf` does.
func TestRepro_NetstackClient_CappedPoolStallsUnderInboundBurst(t *testing.T) {
	if testing.Short() {
		t.Skip("starts management, signal, relay and two embedded clients")
	}
	poolCap := uint32(wedgeReproPoolCap)
	batch := uint32(wedgeReproBatchSize)
	front, backend, backendIP := startTunnelPair(t, Performance{PreallocatedBuffersPerPool: &poolCap, MaxBatchSize: &batch})

	completed, stopFetching := keepFetching(t, front, backendIP)
	keepProbingClosedPort(t, backend, localOverlayIP(t, front))
	require.Eventually(t, func() bool { return tunReaderParkedFor(6, 500*time.Millisecond) },
		wedgeReproSettleFor, 100*time.Millisecond, "the front client's TUN reader must stay parked in WaitPool.Get")

	stalledAt := completed()
	err := fetchThrough(front, backendIP, 10*time.Second)
	assert.Error(t, err, "a request through the wedged client must not complete")
	assert.Equal(t, stalledAt, completed(), "no download may complete while the Device is wedged (%d done before)", stalledAt)
	assert.True(t, goroutineParkedInPool("RoutineReadFromTUN"), "the TUN reader must still be parked")

	lifted := uint32(4096)
	require.NoError(t, front.SetPerformance(Performance{PreallocatedBuffersPerPool: &lifted}))
	require.Eventually(t, func() bool { return fetchThrough(front, backendIP, 10*time.Second) == nil },
		wedgeReproSettleFor, 500*time.Millisecond, "requests must succeed again once the cap is lifted")
	stopFetching()
}

// TestNetstackClient_DefaultTuningServesInboundBurst is the control: the same
// downloads through a client with default tuning keep completing.
func TestNetstackClient_DefaultTuningServesInboundBurst(t *testing.T) {
	if testing.Short() {
		t.Skip("starts management, signal, relay and two embedded clients")
	}
	front, backend, backendIP := startTunnelPair(t, Performance{})

	completed, stopFetching := keepFetching(t, front, backendIP)
	keepProbingClosedPort(t, backend, localOverlayIP(t, front))
	require.Eventually(t, func() bool { return completed() >= 20 },
		wedgeReproSettleFor, 250*time.Millisecond, "downloads must keep completing with default tuning")
	assert.False(t, goroutineParkedInPool("RoutineReadFromTUN"), "no TUN reader may park with an uncapped pool")
	stopFetching()
}
