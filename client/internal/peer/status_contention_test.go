package peer

import (
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// This file validates the lock-contention hypothesis for the status recorder:
// since #6412 the data path (PeerStateByIP, one read per private-service request
// / DNS answer) shares a single lock with the connection state machine
// (UpdatePeerState et al., a write storm while bringing up ~1000 peers). When a
// lock holder is slow (GetRelayStates blocked on a relay handshake,
// RefreshWireGuardStats dumping WG stats for 1000 peers), every connect-side
// write and every data-path read queues behind it.
//
// Two layers of validation:
//   - Benchmarks against the *real* Status recorder, to measure the shipped
//     hot path as-is (RWMutex).
//   - A head-to-head model (BenchmarkLockModel / TestStatusLockContentionModel)
//     whose only variable is the lock type, so we can "run without rwmutex"
//     (plain Mutex, RLock degraded to Lock) on an identical workload.

const benchPeerCount = 1000

// newRecorderWithPeers builds a recorder pre-populated with n peers, each with a
// distinct tunnel IP, mirroring a client connected to a large mesh.
func newRecorderWithPeers(n int) (*Status, []string, []string) {
	s := NewRecorder("https://mgm")
	keys := make([]string, n)
	ips := make([]string, n)
	for i := 0; i < n; i++ {
		key := fmt.Sprintf("peer-%d", i)
		ip := fmt.Sprintf("100.%d.%d.%d", (i>>16)&0xff, (i>>8)&0xff, i&0xff)
		if err := s.AddPeer(key, key+".netbird.cloud", ip, ""); err != nil {
			panic(err)
		}
		keys[i] = key
		ips[i] = ip
	}
	return s, keys, ips
}

// BenchmarkPeerStateByIP measures the pure data-path read against the real
// recorder. This is the per-private-service-request lookup added in #6412.
func BenchmarkPeerStateByIP(b *testing.B) {
	s, _, ips := newRecorderWithPeers(benchPeerCount)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			s.PeerStateByIP(ips[i%len(ips)])
			i++
		}
	})
}

// BenchmarkStatusConnectStorm runs the real recorder under a mixed load: most
// goroutines hammer the data-path read (PeerStateByIP) while a fraction drive
// the connect-side write (UpdatePeerState), as happens while a busy client
// brings up 1000 peers. The write fraction is controlled per sub-benchmark.
func BenchmarkStatusConnectStorm(b *testing.B) {
	for _, writePct := range []int{1, 10, 50} {
		b.Run(fmt.Sprintf("write%dpct", writePct), func(b *testing.B) {
			s, keys, ips := newRecorderWithPeers(benchPeerCount)
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				i := 0
				for pb.Next() {
					if i%100 < writePct {
						// connect-side state transition (Lock)
						status := StatusConnecting
						if i&1 == 0 {
							status = StatusConnected
						}
						_ = s.UpdatePeerState(State{
							PubKey:           keys[i%len(keys)],
							ConnStatus:       status,
							ConnStatusUpdate: time.Now(),
						})
					} else {
						// data-path lookup (RLock)
						s.PeerStateByIP(ips[i%len(ips)])
					}
					i++
				}
			})
		})
	}
}

// TestStatusRecorderContention exercises the *real* recorder: data-path readers
// (PeerStateByIP) + a connect storm (UpdatePeerState) + a periodic GetFullStatus
// caller, which holds the recorder lock while cloning 1000 peers (what the UI /
// CLI status poll does). It reports UpdatePeerState latency percentiles so the
// same workload can be compared before and after flipping the recorder lock
// from RWMutex to Mutex in status.go.
//
//	go test ./client/internal/peer -run TestStatusRecorderContention -v
func TestStatusRecorderContention(t *testing.T) {
	if testing.Short() {
		t.Skip("contention reproduction is timing-based; skipped in -short")
	}

	const (
		readers = 64
		writers = 16
		pollers = 4
		dur     = 2 * time.Second
	)

	s, keys, ips := newRecorderWithPeers(benchPeerCount)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	var reads, writes, polls int64

	for r := 0; r < readers; r++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			i := seed
			var local int64
			for {
				select {
				case <-stop:
					atomic.AddInt64(&reads, local)
					return
				default:
				}
				s.PeerStateByIP(ips[i%len(ips)])
				i++
				local++
			}
		}(r)
	}

	latParts := make([][]time.Duration, writers)
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			i := idx
			var local int64
			samples := make([]time.Duration, 0, 4096)
			for {
				select {
				case <-stop:
					atomic.AddInt64(&writes, local)
					latParts[idx] = samples
					return
				default:
				}
				st := StatusConnecting
				if i&1 == 0 {
					st = StatusConnected
				}
				t0 := time.Now()
				_ = s.UpdatePeerState(State{
					PubKey:           keys[i%len(keys)],
					ConnStatus:       st,
					ConnStatusUpdate: time.Now(),
				})
				samples = append(samples, time.Since(t0))
				i++
				local++
			}
		}(w)
	}

	for p := 0; p < pollers; p++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var local int64
			for {
				select {
				case <-stop:
					atomic.AddInt64(&polls, local)
					return
				default:
				}
				_ = s.GetFullStatus()
				local++
			}
		}()
	}

	time.Sleep(dur)
	close(stop)
	wg.Wait()

	var lat []time.Duration
	for _, p := range latParts {
		lat = append(lat, p...)
	}

	p99 := percentile(lat, 0.99)
	p999 := percentile(lat, 0.999)
	max := percentile(lat, 1.0)

	t.Logf("real recorder: %d readers, %d writers, %d pollers, %d peers, window %v",
		readers, writers, pollers, benchPeerCount, dur)
	t.Logf("reads=%d writes=%d fullStatusPolls=%d", reads, writes, polls)
	t.Logf("UpdatePeerState latency: p50=%s p99=%s p999=%s max=%s",
		percentile(lat, 0.50), p99, p999, max)

	if writes == 0 {
		t.Fatal("no writes recorded")
	}

	// Regression guard. With sync.Mutex this workload measured:
	//   writes=88,724  p99=5.7ms  p999=10.3ms  max=17.8ms
	// With the RWMutex it regressed to (writer starvation):
	//   writes=19,498  p99=17.6ms p999=64ms    max=76ms
	// Thresholds sit roughly midway with headroom for slower/loaded runners,
	// so this fails if the connect-side write path regresses toward the
	// starving RWMutex behaviour but tolerates ordinary timing noise. The
	// separation is structural (fairness), not raw speed, so it holds across
	// machines. If this flakes on a constrained runner, prefer raising the
	// thresholds over reverting to an RWMutex.
	const (
		minWrites   = 40_000                // Mutex ~88k, RWMutex ~19k
		maxP99      = 12 * time.Millisecond // Mutex ~5.7ms, RWMutex ~17.6ms
		maxP999     = 30 * time.Millisecond // Mutex ~10ms, RWMutex ~64ms
		maxWriteLat = 45 * time.Millisecond // Mutex ~17.8ms, RWMutex ~76ms
	)
	if writes < minWrites {
		t.Errorf("connect-side writes regressed: got %d, want >= %d (RWMutex starvation territory)", writes, minWrites)
	}
	if p99 > maxP99 {
		t.Errorf("UpdatePeerState p99 regressed: got %s, want <= %s", p99, maxP99)
	}
	if p999 > maxP999 {
		t.Errorf("UpdatePeerState p999 regressed: got %s, want <= %s", p999, maxP999)
	}
	if max > maxWriteLat {
		t.Errorf("UpdatePeerState max regressed: got %s, want <= %s", max, maxWriteLat)
	}
}

// ---- head-to-head lock model ------------------------------------------------

// locker abstracts the recorder lock so the identical workload can run on a
// real RWMutex or on a plain Mutex. For the Mutex adapter RLock degrades to
// Lock, which is exactly what "reverting the RWMutex" would do to the read
// methods. Interface dispatch adds the same tiny constant to both, so the
// comparison stays fair.
type locker interface {
	Lock()
	Unlock()
	RLock()
	RUnlock()
}

type rwLocker struct{ sync.RWMutex }

type muLocker struct{ sync.Mutex }

func (m *muLocker) RLock()   { m.Mutex.Lock() }
func (m *muLocker) RUnlock() { m.Mutex.Unlock() }

// modelStore mirrors the fields PeerStateByIP / UpdatePeerState touch under the
// recorder lock: the ipToKey index and the peers map.
type modelStore struct {
	lock    locker
	peers   map[string]ConnStatus
	ipToKey map[string]string
	ips     []string
	keys    []string
}

func newModelStore(lk locker, n int) *modelStore {
	m := &modelStore{
		lock:    lk,
		peers:   make(map[string]ConnStatus, n),
		ipToKey: make(map[string]string, n),
		ips:     make([]string, n),
		keys:    make([]string, n),
	}
	for i := 0; i < n; i++ {
		key := fmt.Sprintf("peer-%d", i)
		ip := fmt.Sprintf("100.%d.%d.%d", (i>>16)&0xff, (i>>8)&0xff, i&0xff)
		m.peers[key] = StatusIdle
		m.ipToKey[ip] = key
		m.keys[i] = key
		m.ips[i] = ip
	}
	return m
}

// readByIP mirrors PeerStateByIP: RLock + two map lookups.
func (m *modelStore) readByIP(ip string) {
	m.lock.RLock()
	if key, ok := m.ipToKey[ip]; ok {
		_ = m.peers[key]
	}
	m.lock.RUnlock()
}

// updateState mirrors UpdatePeerState: Lock + map read/modify/write.
func (m *modelStore) updateState(key string, s ConnStatus) {
	m.lock.Lock()
	if _, ok := m.peers[key]; ok {
		m.peers[key] = s
	}
	m.lock.Unlock()
}

// slowReadHold mirrors GetRelayStates: the read lock held across a blocking
// call (a relay handshake reachable via Client.Transport's c.mu).
func (m *modelStore) slowReadHold(d time.Duration) {
	m.lock.RLock()
	time.Sleep(d)
	m.lock.RUnlock()
}

// runLockModel drives the model for a fixed wall-clock window with reader and
// writer goroutines plus an optional periodic slow lock holder, and returns
// completed read/write counts and the write-latency distribution. Write latency
// is the connect-side signal: a peer recording "connected" is one such write,
// so ballooning write latency is the peer-can't-connect symptom.
func runLockModel(lk locker, readers, writers int, dur, slowEvery, slowHold time.Duration) (reads, writes int64, writeLat []time.Duration) {
	m := newModelStore(lk, benchPeerCount)
	var readCount, writeCount int64

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// latency samples per writer, merged at the end (no shared lock on the hot path)
	latParts := make([][]time.Duration, writers)

	for r := 0; r < readers; r++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			i := seed
			var local int64
			for {
				select {
				case <-stop:
					atomic.AddInt64(&readCount, local)
					return
				default:
				}
				m.readByIP(m.ips[i%len(m.ips)])
				i++
				local++
			}
		}(r)
	}

	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			i := idx
			var local int64
			samples := make([]time.Duration, 0, 4096)
			for {
				select {
				case <-stop:
					atomic.AddInt64(&writeCount, local)
					latParts[idx] = samples
					return
				default:
				}
				s := StatusConnecting
				if i&1 == 0 {
					s = StatusConnected
				}
				t0 := time.Now()
				m.updateState(m.keys[i%len(m.keys)], s)
				samples = append(samples, time.Since(t0))
				i++
				local++
			}
		}(w)
	}

	if slowEvery > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			t := time.NewTicker(slowEvery)
			defer t.Stop()
			for {
				select {
				case <-stop:
					return
				case <-t.C:
					m.slowReadHold(slowHold)
				}
			}
		}()
	}

	time.Sleep(dur)
	close(stop)
	wg.Wait()

	for _, p := range latParts {
		writeLat = append(writeLat, p...)
	}
	return atomic.LoadInt64(&readCount), atomic.LoadInt64(&writeCount), writeLat
}

func percentile(samples []time.Duration, p float64) time.Duration {
	if len(samples) == 0 {
		return 0
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	idx := int(float64(len(samples)-1) * p)
	return samples[idx]
}

// BenchmarkLockModel runs the identical mixed workload against the RWMutex and
// the plain Mutex so the two can be compared directly with `go test -bench`.
func BenchmarkLockModel(b *testing.B) {
	cases := []struct {
		name     string
		writePct int
	}{
		{"write1pct", 1},
		{"write10pct", 10},
		{"write50pct", 50},
	}
	locks := []struct {
		name string
		make func() locker
	}{
		{"rwmutex", func() locker { return &rwLocker{} }},
		{"mutex", func() locker { return &muLocker{} }},
	}
	for _, lc := range locks {
		for _, c := range cases {
			b.Run(lc.name+"/"+c.name, func(b *testing.B) {
				m := newModelStore(lc.make(), benchPeerCount)
				b.ResetTimer()
				b.RunParallel(func(pb *testing.PB) {
					i := 0
					for pb.Next() {
						if i%100 < c.writePct {
							s := StatusConnecting
							if i&1 == 0 {
								s = StatusConnected
							}
							m.updateState(m.keys[i%len(m.keys)], s)
						} else {
							m.readByIP(m.ips[i%len(m.ips)])
						}
						i++
					}
				})
			})
		}
	}
}

// TestStatusLockContentionModel reproduces the production scenario and prints a
// side-by-side report: a busy client (many data-path readers) bringing up 1000
// peers (writers), while a periodic slow holder (relay handshake / WG stats
// dump) holds the lock. It reports throughput and write-latency percentiles for
// both lock types. Run with -v to see the numbers:
//
//	go test ./client/internal/peer -run TestStatusLockContentionModel -v
func TestStatusLockContentionModel(t *testing.T) {
	if testing.Short() {
		t.Skip("contention reproduction is timing-based; skipped in -short")
	}

	const (
		readers   = 64              // busy client: data-path lookups
		writers   = 16              // connect storm: peer state transitions
		dur       = 2 * time.Second // observation window
		slowEvery = 20 * time.Millisecond
		slowHold  = 5 * time.Millisecond // relay handshake / WG stats dump under the lock
	)

	type result struct {
		name          string
		reads, writes int64
		p50, p99, max time.Duration
	}

	run := func(name string, lk locker) result {
		reads, writes, lat := runLockModel(lk, readers, writers, dur, slowEvery, slowHold)
		return result{
			name:   name,
			reads:  reads,
			writes: writes,
			p50:    percentile(lat, 0.50),
			p99:    percentile(lat, 0.99),
			max:    percentile(lat, 1.0),
		}
	}

	results := []result{
		run("rwmutex", &rwLocker{}),
		run("mutex", &muLocker{}),
	}

	t.Logf("workload: %d readers, %d writers, %d peers, slow holder %v every %v, window %v",
		readers, writers, benchPeerCount, slowHold, slowEvery, dur)
	t.Logf("%-8s %12s %12s %12s %12s %12s", "lock", "reads", "writes", "write-p50", "write-p99", "write-max")
	for _, r := range results {
		t.Logf("%-8s %12d %12d %12s %12s %12s", r.name, r.reads, r.writes, r.p50, r.p99, r.max)
	}

	// Sanity: the workload actually ran and produced write-latency samples.
	for _, r := range results {
		if r.writes == 0 {
			t.Fatalf("%s: no writes recorded", r.name)
		}
		if r.p99 == 0 {
			t.Fatalf("%s: no write latency samples", r.name)
		}
	}
}
