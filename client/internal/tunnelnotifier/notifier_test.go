package tunnelnotifier

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type call struct {
	kind    string
	payload string
}

type recorder struct {
	mu       sync.Mutex
	calls    []call
	inFlight atomic.Int32
	overlap  atomic.Bool
	delay    time.Duration
}

func (r *recorder) record(kind, payload string) {
	if r.inFlight.Add(1) != 1 {
		r.overlap.Store(true)
	}
	if r.delay > 0 {
		time.Sleep(r.delay)
	}
	r.mu.Lock()
	r.calls = append(r.calls, call{kind: kind, payload: payload})
	r.mu.Unlock()
	r.inFlight.Add(-1)
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

func (r *recorder) snapshot() []call {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]call, len(r.calls))
	copy(out, r.calls)
	return out
}

type fakeListener struct {
	rec *recorder
}

func (f *fakeListener) OnNetworkChanged(routes string) {
	f.rec.record("routes", routes)
}

func (f *fakeListener) SetInterfaceIP(ip string) {
	f.rec.record("ip", ip)
}

func (f *fakeListener) SetInterfaceIPv6(ip string) {
	f.rec.record("ipv6", ip)
}

type fakeDNSManager struct {
	rec *recorder
}

func (f *fakeDNSManager) ApplyDns(config string) {
	f.rec.record("dns", config)
}

func TestFIFOOrder(t *testing.T) {
	rec := &recorder{}
	n := New(&fakeListener{rec: rec}, &fakeDNSManager{rec: rec})
	defer n.Close()

	n.SetInterfaceIP("10.0.0.1")
	n.SetInterfaceIPv6("fd00::1")
	n.ApplyDns(`{"domains":[]}`)
	n.OnNetworkChanged("10.0.0.0/8,192.168.0.0/16")
	n.ApplyDns(`{"domains":["example.com"]}`)

	require.Eventually(t, func() bool { return rec.count() == 5 }, time.Second, time.Millisecond)

	expected := []call{
		{kind: "ip", payload: "10.0.0.1"},
		{kind: "ipv6", payload: "fd00::1"},
		{kind: "dns", payload: `{"domains":[]}`},
		{kind: "routes", payload: "10.0.0.0/8,192.168.0.0/16"},
		{kind: "dns", payload: `{"domains":["example.com"]}`},
	}
	assert.Equal(t, expected, rec.snapshot())
}

func TestNoOverlappingCalls(t *testing.T) {
	rec := &recorder{delay: 100 * time.Microsecond}
	n := New(&fakeListener{rec: rec}, &fakeDNSManager{rec: rec})
	defer n.Close()

	const producers = 8
	const perProducer = 25

	var wg sync.WaitGroup
	for i := 0; i < producers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < perProducer; j++ {
				payload := fmt.Sprintf("%d-%d", id, j)
				switch j % 4 {
				case 0:
					n.OnNetworkChanged(payload)
				case 1:
					n.SetInterfaceIP(payload)
				case 2:
					n.SetInterfaceIPv6(payload)
				case 3:
					n.ApplyDns(payload)
				}
			}
		}(i)
	}
	wg.Wait()

	require.Eventually(t, func() bool { return rec.count() == producers*perProducer }, 5*time.Second, time.Millisecond)
	assert.False(t, rec.overlap.Load())
}

func TestDNSAndRoutesInterleaved(t *testing.T) {
	rec := &recorder{delay: 100 * time.Microsecond}
	n := New(&fakeListener{rec: rec}, &fakeDNSManager{rec: rec})
	defer n.Close()

	const events = 50

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < events; i++ {
			n.ApplyDns(fmt.Sprintf("dns-%d", i))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < events; i++ {
			n.OnNetworkChanged(fmt.Sprintf("routes-%d", i))
		}
	}()
	wg.Wait()

	require.Eventually(t, func() bool { return rec.count() == 2*events }, 5*time.Second, time.Millisecond)
	assert.False(t, rec.overlap.Load())

	var dnsSeen, routesSeen int
	for _, c := range rec.snapshot() {
		switch c.kind {
		case "dns":
			assert.Equal(t, fmt.Sprintf("dns-%d", dnsSeen), c.payload)
			dnsSeen++
		case "routes":
			assert.Equal(t, fmt.Sprintf("routes-%d", routesSeen), c.payload)
			routesSeen++
		}
	}
	assert.Equal(t, events, dnsSeen)
	assert.Equal(t, events, routesSeen)
}

func TestCloseDrainsQueue(t *testing.T) {
	rec := &recorder{delay: time.Millisecond}
	n := New(&fakeListener{rec: rec}, &fakeDNSManager{rec: rec})

	const events = 20
	for i := 0; i < events; i++ {
		n.OnNetworkChanged(fmt.Sprintf("routes-%d", i))
	}
	n.Close()

	require.Equal(t, events, rec.count(), "Close must not return before all queued events are delivered")

	n.OnNetworkChanged("after-close")
	n.ApplyDns("after-close")
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, events, rec.count())
}
