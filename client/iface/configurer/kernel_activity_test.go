//go:build (linux && !android) || freebsd

package configurer

import (
	"testing"

	"github.com/netbirdio/netbird/monotime"
)

func TestUpdateActivity_NewPeerSeededActive(t *testing.T) {
	c := NewKernelConfigurer("")

	now := monotime.Time(1000)
	got := c.updateActivity(map[string]WGStats{
		"peerA": {TxBytes: 500, RxBytes: 500},
	}, now)

	if got["peerA"] != now {
		t.Fatalf("new peer should be seeded active at now=%d, got %d", now, got["peerA"])
	}
}

func TestUpdateActivity_GrowthPastThresholdIsActive(t *testing.T) {
	c := NewKernelConfigurer("")

	t0 := monotime.Time(1000)
	c.updateActivity(map[string]WGStats{"peerA": {TxBytes: 1000}}, t0)

	// Grow well past the threshold.
	t1 := monotime.Time(2000)
	got := c.updateActivity(map[string]WGStats{
		"peerA": {TxBytes: 1000 + activityByteThreshold + 1},
	}, t1)

	if got["peerA"] != t1 {
		t.Fatalf("peer with >threshold growth should be active at t1=%d, got %d", t1, got["peerA"])
	}
}

func TestUpdateActivity_SubThresholdStaysIdleNoAccumulation(t *testing.T) {
	c := NewKernelConfigurer("")

	t0 := monotime.Time(1000)
	c.updateActivity(map[string]WGStats{"peerA": {TxBytes: 0}}, t0)

	// Several polls, each growing by less than the threshold (keepalive noise).
	// Even though the cumulative growth far exceeds the threshold, the per-poll
	// delta never does, so the peer must keep reporting its original activity.
	bytes := int64(0)
	step := int64(activityByteThreshold / 2)
	for i, ts := range []monotime.Time{2000, 3000, 4000, 5000, 6000} {
		bytes += step
		got := c.updateActivity(map[string]WGStats{"peerA": {TxBytes: bytes}}, ts)
		if got["peerA"] != t0 {
			t.Fatalf("poll %d: idle peer should stay at t0=%d, got %d", i, t0, got["peerA"])
		}
	}
}

func TestUpdateActivity_CounterResetIsActive(t *testing.T) {
	c := NewKernelConfigurer("")

	t0 := monotime.Time(1000)
	c.updateActivity(map[string]WGStats{"peerA": {TxBytes: 10_000, RxBytes: 5_000}}, t0)

	// Counter resets (peer suspended and re-added): total drops below baseline.
	t1 := monotime.Time(2000)
	got := c.updateActivity(map[string]WGStats{"peerA": {TxBytes: 0, RxBytes: 0}}, t1)

	if got["peerA"] != t1 {
		t.Fatalf("counter reset should be treated as activity at t1=%d, got %d", t1, got["peerA"])
	}
}

func TestUpdateActivity_PrunesRemovedPeers(t *testing.T) {
	c := NewKernelConfigurer("")

	t0 := monotime.Time(1000)
	c.updateActivity(map[string]WGStats{
		"peerA": {TxBytes: 1},
		"peerB": {TxBytes: 1},
	}, t0)

	// peerB disappears from the device dump.
	t1 := monotime.Time(2000)
	got := c.updateActivity(map[string]WGStats{"peerA": {TxBytes: 1}}, t1)

	if _, ok := got["peerB"]; ok {
		t.Fatalf("removed peer should not appear in returned activities")
	}

	c.mu.Lock()
	_, tracked := c.activity["peerB"]
	c.mu.Unlock()
	if tracked {
		t.Fatalf("removed peer should be pruned from the tracker")
	}
}
