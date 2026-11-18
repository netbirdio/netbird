package peer

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/hbwatch"
)

func TestAlignedHeartbeatToProto(t *testing.T) {
	assert.Nil(t, AlignedHeartbeatToProto(nil), "no watcher, no state")

	at := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	corr := hbwatch.Correction{
		At: at, Service: hbwatch.Relay, Addr: "rels://relay:443",
		Offset: -2500 * time.Millisecond, From: 7 * time.Second, Wanted: 9500 * time.Millisecond,
		Result: hbwatch.ResultClamped,
	}
	snap := &hbwatch.Snapshot{
		Streams: []hbwatch.StreamStatus{
			{Service: hbwatch.Management, Addr: "https://mgmt:443", Level: hbwatch.LevelStock},
			{
				Service: hbwatch.Relay, Addr: "rels://relay:443", Level: hbwatch.LevelAligned,
				Period: time.Minute, Phase: 7 * time.Second, LastHeartbeat: at,
				LastCorrection: &corr, Blocked: true, BlockedInRow: 3, ClampHits: 5,
			},
		},
		Corrections: []hbwatch.Correction{corr},
	}

	pb := FullStatus{AlignedHeartbeat: snap}.ToProto().GetAlignedHeartbeat()
	require.NotNil(t, pb, "state in the daemon status")
	require.Len(t, pb.GetStreams(), 2)

	mgmt := pb.GetStreams()[0]
	assert.Equal(t, "management", mgmt.GetService(), "service")
	assert.Equal(t, "stock", mgmt.GetLevel(), "level")
	assert.Nil(t, mgmt.GetLastHeartbeat(), "no heartbeat time before the first")
	assert.Nil(t, mgmt.GetLastCorrection(), "no correction")

	relay := pb.GetStreams()[1]
	assert.Equal(t, "rels://relay:443", relay.GetAddress(), "address")
	assert.Equal(t, "aligned", relay.GetLevel(), "level")
	assert.Equal(t, uint32(60), relay.GetPeriodSeconds(), "period")
	assert.Equal(t, uint32(7000), relay.GetPhaseMillis(), "phase")
	assert.Equal(t, at, relay.GetLastHeartbeat().AsTime(), "last heartbeat")
	assert.True(t, relay.GetCorrectionBlocked(), "blocked")
	assert.Equal(t, uint32(3), relay.GetBlockedInRow(), "in a row")
	assert.Equal(t, uint32(5), relay.GetClampHits(), "clamp hits")

	c := relay.GetLastCorrection()
	require.NotNil(t, c, "last correction")
	assert.Equal(t, int64(-2500), c.GetOffsetMillis(), "offset")
	assert.Equal(t, uint32(7000), c.GetFromPhaseMillis(), "from")
	assert.Equal(t, uint32(9500), c.GetWantedPhaseMillis(), "wanted")
	assert.Equal(t, "clamped", c.GetResult(), "result")
	assert.Equal(t, at, c.GetTime().AsTime(), "time")
	require.Len(t, pb.GetCorrections(), 1, "history")
	assert.Equal(t, c.String(), pb.GetCorrections()[0].String(), "history entry")
}

type wallClock struct{}

func (wallClock) Now() time.Time                      { return time.Now() }
func (wallClock) AfterFunc(d time.Duration, f func()) { time.AfterFunc(d, f) }

// The full status carries the state of the heartbeat watcher, so the daemon
// status and the debug bundle show it.
func TestGetFullStatusAlignedHeartbeat(t *testing.T) {
	w := hbwatch.New(wallClock{}, time.Minute)
	t.Cleanup(hbwatch.SetDefault(w))
	w.Register(hbwatch.Signal, hbwatch.Registration{Addr: "https://signal:443"})

	full := NewRecorder("https://mgmt:443").GetFullStatus()
	require.NotNil(t, full.AlignedHeartbeat, "state present with a watcher")
	require.Len(t, full.AlignedHeartbeat.Streams, 1)
	assert.Equal(t, "https://signal:443", full.AlignedHeartbeat.Streams[0].Addr, "registered stream")

	t.Cleanup(hbwatch.SetDefault(nil))
	assert.Nil(t, NewRecorder("https://mgmt:443").GetFullStatus().AlignedHeartbeat, "no watcher, no state")
}
