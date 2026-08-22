//go:build devcert

package client

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"runtime/pprof"
	"strconv"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"go.opentelemetry.io/otel"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/relay/server"
	"github.com/netbirdio/netbird/shared/relay/auth/allow"
)

const pktSize = 1300

// benchPkts returns the packet count for burst tests, overridable via
// BENCH_PKTS to widen the measurement window for a stable CPU profile.
func benchPkts(def int) int {
	if v := os.Getenv("BENCH_PKTS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// procCPUSeconds returns cumulative user+system CPU seconds for this process.
// The harness runs both clients and the relay in-process, so this is the total
// pipeline CPU; pps divided by it is a stable per-core efficiency metric for
// A/B-ing a data-path change.
func procCPUSeconds() float64 {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0
	}
	u := time.Duration(ru.Utime.Sec)*time.Second + time.Duration(ru.Utime.Usec)*time.Microsecond
	s := time.Duration(ru.Stime.Sec)*time.Second + time.Duration(ru.Stime.Usec)*time.Microsecond
	return (u + s).Seconds()
}

// maybeCPUProfile starts an in-band CPU profile scoped to the measured window
// when BENCH_CPUPROFILE names an output file. Returns a stop func.
func maybeCPUProfile(t *testing.T) func() {
	path := os.Getenv("BENCH_CPUPROFILE")
	if path == "" {
		return func() {}
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create cpu profile %q: %v", path, err)
	}
	if err := pprof.StartCPUProfile(f); err != nil {
		_ = f.Close()
		t.Fatalf("start cpu profile: %v", err)
	}
	return func() {
		pprof.StopCPUProfile()
		_ = f.Close()
		t.Logf("cpu profile written to %s", path)
	}
}

// reportEfficiency prints the CPU-normalized throughput for a measured window.
func reportEfficiency(t *testing.T, label string, rcvd int64, cpuSec float64) {
	t.Helper()
	if cpuSec <= 0 {
		return
	}
	ppsPerCore := float64(rcvd) / cpuSec
	mbitPerCore := float64(rcvd) * pktSize * 8 / cpuSec / 1e6
	fmt.Printf("%s: cpu=%.2fs pps/core=%.0f Mbit/core-s=%.1f\n", label, cpuSec, ppsPerCore, mbitPerCore)
}

// benchClientA/B expose the last connected pair's clients so tests can read
// their inbound-drop counters.
var benchClientA, benchClientB *Client

func chanDrops() int64 {
	return benchClientA.InboundMsgDrops() + benchClientB.InboundMsgDrops()
}

func startBenchServer(t *testing.T, addr string) *server.Server {
	t.Helper()
	cfg := server.Config{
		Meter:          otel.Meter(""),
		ExposedAddress: "rel://" + addr,
		TLSSupport:     false,
		AuthValidator:  &allow.Auth{},
	}
	srv, err := server.NewServer(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	go func() {
		_ = srv.Listen(server.ListenerConfig{Address: addr})
	}()
	time.Sleep(1 * time.Second)
	return srv
}

func connectPair(t *testing.T, serverAddr, a, b string) (net.Conn, net.Conn, func()) {
	t.Helper()
	ctx := context.Background()
	ca := NewClient("rel://"+serverAddr, hmacTokenStore, a, iface.DefaultMTU)
	if err := ca.Connect(ctx); err != nil {
		t.Fatalf("%s connect: %v", a, err)
	}
	cb := NewClient("rel://"+serverAddr, hmacTokenStore, b, iface.DefaultMTU)
	if err := cb.Connect(ctx); err != nil {
		t.Fatalf("%s connect: %v", b, err)
	}
	benchClientA, benchClientB = ca, cb
	t.Logf("transports: %s=%s %s=%s", a, ca.Transport(), b, cb.Transport())
	connAB, err := ca.OpenConn(ctx, b)
	if err != nil {
		t.Fatalf("open %s->%s: %v", a, b, err)
	}
	connBA, err := cb.OpenConn(ctx, a)
	if err != nil {
		t.Fatalf("open %s->%s: %v", b, a, err)
	}
	// warmup: wait until full-size datagrams fit (QUIC path MTU discovery)
	warm := make([]byte, pktSize)
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, err := connAB.Write(warm); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("warmup: %d byte writes still failing after 20s", pktSize)
		}
		time.Sleep(200 * time.Millisecond)
	}
	// drain any warmup packets on the far side
	time.Sleep(300 * time.Millisecond)
	drainNonBlocking(connBA)
	cleanup := func() {
		_ = ca.Close()
		_ = cb.Close()
	}
	return connAB, connBA, cleanup
}

// drainNonBlocking empties pending messages without blocking (uses the
// underlying message channel via a short-lived reader goroutine).
func drainNonBlocking(conn net.Conn) {
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 2048)
		for {
			select {
			case <-done:
				return
			default:
			}
			_ = buf
			// rely on the outer timeout; Conn.Read blocks until a message arrives
			if _, err := conn.Read(buf); err != nil {
				return
			}
		}
	}()
	time.Sleep(200 * time.Millisecond)
	close(done)
}

// drainCount reads packets until idle for idleTimeout, returns count.
func drainCount(conn net.Conn, count *atomic.Int64, stop chan struct{}) {
	buf := make([]byte, 2048)
	for {
		select {
		case <-stop:
			return
		default:
		}
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		if n >= pktSize {
			count.Add(1)
		}
	}
}

func pump(conn net.Conn, npkts int, interval time.Duration) (sent int, elapsed time.Duration) {
	payload := make([]byte, pktSize)
	start := time.Now()
	var tick *time.Ticker
	if interval > 0 {
		tick = time.NewTicker(interval)
		defer tick.Stop()
	}
	errs := 0
	for i := 0; i < npkts; i++ {
		binary.BigEndian.PutUint64(payload, uint64(i))
		if _, err := conn.Write(payload); err != nil {
			errs++
			if errs > 100 {
				fmt.Printf("pump aborted after %d write errors, last: %v\n", errs, err)
				break
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		sent++
		if tick != nil {
			<-tick.C
		}
	}
	return sent, time.Since(start)
}

func mbit(pkts int64, d time.Duration) float64 {
	return float64(pkts) * pktSize * 8 / d.Seconds() / 1e6
}

// TestPipeBurst: one direction, send as fast as the pipeline accepts.
func TestPipeBurst(t *testing.T) {
	addr := "127.0.0.1:60111"
	srv := startBenchServer(t, addr)
	defer srv.Shutdown(context.Background())

	connAB, connBA, cleanup := connectPair(t, addr, "alice", "bob")
	defer cleanup()

	drops0 := chanDrops()
	var rcvd atomic.Int64
	stop := make(chan struct{})
	go drainCount(connBA, &rcvd, stop)

	n := benchPkts(50000)
	cpu0 := procCPUSeconds()
	stopProfile := maybeCPUProfile(t)
	sent, elapsed := pump(connAB, n, 0)
	// wait for the tail to drain
	last := rcvd.Load()
	for {
		time.Sleep(300 * time.Millisecond)
		cur := rcvd.Load()
		if cur == last {
			break
		}
		last = cur
	}
	stopProfile()
	cpuSec := procCPUSeconds() - cpu0
	close(stop)
	r := rcvd.Load()
	fmt.Printf("BURST: sent=%d in %v (send-side %.1f Mbit/s, %.0f pps) rcvd=%d loss=%.2f%% chanDrops=%d recv-rate~%.1f Mbit/s\n",
		sent, elapsed, mbit(int64(sent), elapsed), float64(sent)/elapsed.Seconds(),
		r, 100*float64(int64(sent)-r)/float64(sent), chanDrops()-drops0, mbit(r, elapsed))
	reportEfficiency(t, "BURST", r, cpuSec)
}

// TestPipePaced: one direction, fixed rates, find the drop onset.
func TestPipePaced(t *testing.T) {
	addr := "127.0.0.1:60112"
	srv := startBenchServer(t, addr)
	defer srv.Shutdown(context.Background())

	connAB, connBA, cleanup := connectPair(t, addr, "alice", "bob")
	defer cleanup()

	var rcvd atomic.Int64
	stop := make(chan struct{})
	go drainCount(connBA, &rcvd, stop)
	defer close(stop)

	for _, rateMbit := range []int{25, 50, 100, 200, 400, 800} {
		pps := float64(rateMbit) * 1e6 / 8 / pktSize
		interval := time.Duration(float64(time.Second) / pps)
		n := int(pps * 3) // ~3 seconds per rate
		drops0 := chanDrops()
		before := rcvd.Load()
		sent, elapsed := pump(connAB, n, interval)
		time.Sleep(500 * time.Millisecond)
		got := rcvd.Load() - before
		fmt.Printf("PACED %4d Mbit target: sent=%d actual=%.1f Mbit/s rcvd=%d loss=%.2f%% chanDrops=%d\n",
			rateMbit, sent, mbit(int64(sent), elapsed), got,
			100*float64(int64(sent)-got)/float64(sent), chanDrops()-drops0)
	}
}

// TestPipeBidir: both directions pump simultaneously (coupling check).
func TestPipeBidir(t *testing.T) {
	addr := "127.0.0.1:60113"
	srv := startBenchServer(t, addr)
	defer srv.Shutdown(context.Background())

	connAB, connBA, cleanup := connectPair(t, addr, "alice", "bob")
	defer cleanup()

	drops0 := chanDrops()
	var rcvdA, rcvdB atomic.Int64
	stop := make(chan struct{})
	go drainCount(connBA, &rcvdB, stop) // bob receives from alice
	go drainCount(connAB, &rcvdA, stop) // alice receives from bob

	const n = 50000
	type res struct {
		sent    int
		elapsed time.Duration
	}
	resCh := make(chan res, 2)
	go func() {
		s, e := pump(connAB, n, 0)
		resCh <- res{s, e}
	}()
	go func() {
		s, e := pump(connBA, n, 0)
		resCh <- res{s, e}
	}()
	r1, r2 := <-resCh, <-resCh
	time.Sleep(1 * time.Second)
	close(stop)
	fmt.Printf("BIDIR: dir1 sent=%d %.1f Mbit/s; dir2 sent=%d %.1f Mbit/s; rcvdByBob=%d rcvdByAlice=%d chanDrops=%d\n",
		r1.sent, mbit(int64(r1.sent), r1.elapsed),
		r2.sent, mbit(int64(r2.sent), r2.elapsed),
		rcvdB.Load(), rcvdA.Load(), chanDrops()-drops0)
}
