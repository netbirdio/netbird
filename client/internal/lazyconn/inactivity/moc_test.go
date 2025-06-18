package inactivity

import (
	"fmt"
	"time"

	"github.com/netbirdio/netbird/client/iface/configurer"
)

type rxHistory struct {
	when    time.Duration
	RxBytes int64
}

// mockWgInterface mocks WgInterface to simulate peer stats.
type mockWgInterface struct {
	peerID        string
	statsSequence []rxHistory
	timer         *FakeTimer
	initialTime   time.Time
	reachedLast   bool
}

func newMockWgInterface(peerID string, history []rxHistory, timer *FakeTimer) *mockWgInterface {
	return &mockWgInterface{
		peerID:        peerID,
		statsSequence: history,
		timer:         timer,
		initialTime:   timer.Now(),
	}
}

func (m *mockWgInterface) GetStats() (map[string]configurer.WGStats, error) {
	if m.reachedLast {
		return nil, fmt.Errorf("no more data")
	}

	now := m.timer.Now()
	var rx int64
	for i, history := range m.statsSequence {
		if now.Before(m.initialTime.Add(history.when)) {
			break
		}

		if len(m.statsSequence)-1 == i {
			m.reachedLast = true
		}

		rx += history.RxBytes
	}

	wgStats := make(map[string]configurer.WGStats)
	wgStats[m.peerID] = configurer.WGStats{
		RxBytes: rx,
	}
	return wgStats, nil
}

// fakeTicker is a controllable ticker for use in tests
type fakeTicker struct {
	interval time.Duration
	timer    *FakeTimer

	ch  chan time.Time
	now time.Time
}

func newFakeTicker(interval time.Duration, timer *FakeTimer) *fakeTicker {
	return &fakeTicker{
		interval: interval,
		timer:    timer,
		ch:       make(chan time.Time, 1),
		now:      timer.Now(),
	}
}

func (f *fakeTicker) C() <-chan time.Time {
	f.now = f.now.Add(f.interval)
	f.timer.Set(f.now)
	f.ch <- f.now
	return f.ch
}

func (f *fakeTicker) Stop() {}

type FakeTimer struct {
	now time.Time
}

func NewFakeTimer() *FakeTimer {
	return &FakeTimer{
		now: time.Date(2025, time.June, 1, 0, 0, 0, 0, time.UTC),
	}
}

func (f *FakeTimer) Set(t time.Time) {
	f.now = t
}

func (f *FakeTimer) Now() time.Time {
	return f.now
}
