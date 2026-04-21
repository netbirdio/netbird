package server

import (
	"sync"
	"testing"
)

func TestSendRateTracker_Increment(t *testing.T) {
	tracker := newSendRateTracker()

	tracker.increment("peer-a")
	tracker.increment("peer-a")
	tracker.increment("peer-b")

	snap := tracker.resetAndSnapshot()
	if snap["peer-a"] != 2 {
		t.Errorf("expected peer-a count 2, got %d", snap["peer-a"])
	}
	if snap["peer-b"] != 1 {
		t.Errorf("expected peer-b count 1, got %d", snap["peer-b"])
	}
}

func TestSendRateTracker_ResetAndSnapshot_Resets(t *testing.T) {
	tracker := newSendRateTracker()
	tracker.increment("peer-a")

	snap1 := tracker.resetAndSnapshot()
	if snap1["peer-a"] != 1 {
		t.Fatalf("expected 1, got %d", snap1["peer-a"])
	}

	snap2 := tracker.resetAndSnapshot()
	if len(snap2) != 0 {
		t.Errorf("expected empty snapshot after reset, got %v", snap2)
	}
}

func TestSendRateTracker_ConcurrentIncrement(t *testing.T) {
	tracker := newSendRateTracker()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tracker.increment("peer-x")
		}()
	}
	wg.Wait()

	snap := tracker.resetAndSnapshot()
	if snap["peer-x"] != 100 {
		t.Errorf("expected 100, got %d", snap["peer-x"])
	}
}
