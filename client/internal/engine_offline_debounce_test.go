package internal

import (
	"sync"
	"testing"
	"time"
)

// Codex review: the offline-debounce timer can fire after Engine.Stop
// or after a mode-switch. Most of the safety checks live INSIDE the
// time.AfterFunc callback (re-validate ctx / mode / liveness) so a
// pure-unit test of those branches needs the full engine.
//
// The tests below cover the synchronous timer-map operations that DON'T
// require a full engine: scheduleRemoteOfflineClose idempotency,
// cancelRemoteOfflineClose, and cancelAllRemoteOfflineCloses.
//
// The callback re-validation paths are exercised by the end-to-end
// tests on real hardware (see docs/superpowers/test-reports/
// 2026-05-03-netbird-phase3-7i-end-to-end.md) and protected
// structurally — every guard returns early before touching peerStore.

// engineForDebounceTest builds an Engine value with just enough state
// to drive the timer-map helpers. The callback's re-validation branches
// won't fire because we never let the timer reach its deadline in
// these unit tests.
func engineForDebounceTest() *Engine {
	return &Engine{
		peerOfflineDebounce: make(map[string]*time.Timer),
	}
}

func TestScheduleRemoteOfflineClose_StoresTimer(t *testing.T) {
	e := engineForDebounceTest()
	e.scheduleRemoteOfflineClose("peerA")
	e.peerOfflineDebounceMu.Lock()
	_, ok := e.peerOfflineDebounce["peerA"]
	e.peerOfflineDebounceMu.Unlock()
	if !ok {
		t.Fatal("schedule must store a timer for the peer")
	}
	// cleanup so AfterFunc doesn't fire its callback after the test
	e.cancelAllRemoteOfflineCloses()
}

func TestScheduleRemoteOfflineClose_IsIdempotent(t *testing.T) {
	e := engineForDebounceTest()
	e.scheduleRemoteOfflineClose("peerA")
	e.peerOfflineDebounceMu.Lock()
	t1 := e.peerOfflineDebounce["peerA"]
	e.peerOfflineDebounceMu.Unlock()

	e.scheduleRemoteOfflineClose("peerA") // second call

	e.peerOfflineDebounceMu.Lock()
	t2 := e.peerOfflineDebounce["peerA"]
	e.peerOfflineDebounceMu.Unlock()

	if t1 != t2 {
		t.Error("second schedule for same peer must not replace the existing timer")
	}
	e.cancelAllRemoteOfflineCloses()
}

func TestCancelRemoteOfflineClose_RemovesEntry(t *testing.T) {
	e := engineForDebounceTest()
	e.scheduleRemoteOfflineClose("peerA")
	e.cancelRemoteOfflineClose("peerA")
	e.peerOfflineDebounceMu.Lock()
	_, ok := e.peerOfflineDebounce["peerA"]
	e.peerOfflineDebounceMu.Unlock()
	if ok {
		t.Fatal("cancel must remove the peer from the timer map")
	}
}

func TestCancelRemoteOfflineClose_OnAbsentPeer_NoOp(t *testing.T) {
	e := engineForDebounceTest()
	// must not panic
	e.cancelRemoteOfflineClose("never-scheduled")
	if len(e.peerOfflineDebounce) != 0 {
		t.Error("map must remain empty")
	}
}

func TestCancelAllRemoteOfflineCloses_ClearsEverything(t *testing.T) {
	e := engineForDebounceTest()
	for _, k := range []string{"a", "b", "c", "d"} {
		e.scheduleRemoteOfflineClose(k)
	}
	if len(e.peerOfflineDebounce) != 4 {
		t.Fatalf("setup: expected 4 timers, got %d", len(e.peerOfflineDebounce))
	}
	e.cancelAllRemoteOfflineCloses()
	if len(e.peerOfflineDebounce) != 0 {
		t.Errorf("cancel-all must clear the map, got %d entries", len(e.peerOfflineDebounce))
	}
}

// Stress: schedule + cancel from multiple goroutines concurrently.
// Mutex must keep the map consistent.
func TestRemoteOfflineDebounce_ConcurrentSafe(t *testing.T) {
	e := engineForDebounceTest()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			e.scheduleRemoteOfflineClose("peer" + string(rune('A'+i%5)))
		}(i)
		go func(i int) {
			defer wg.Done()
			e.cancelRemoteOfflineClose("peer" + string(rune('A'+i%5)))
		}(i)
	}
	wg.Wait()
	e.cancelAllRemoteOfflineCloses()
}
