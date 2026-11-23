package peer

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/hbwatch"
)

// TestAlignedHeartbeatToProto covers the peer status addition: aligned and
// period per service, nothing else.
func TestAlignedHeartbeatToProto(t *testing.T) {
	assert.Nil(t, AlignedHeartbeatToProto(nil), "no watcher, no state")

	snap := &hbwatch.Snapshot{Streams: []hbwatch.StreamStatus{
		{Service: hbwatch.Management, Addr: "https://mgmt:443", Aligned: true, Period: time.Minute},
		{Service: hbwatch.Signal, Addr: "https://signal:443"},
		{Service: hbwatch.Relay, Addr: "rels://relay:443", Aligned: true, Period: 30 * time.Second},
	}}
	pb := FullStatus{AlignedHeartbeat: snap}.ToProto().GetAlignedHeartbeat()
	require.NotNil(t, pb)
	require.Len(t, pb.GetStreams(), 3)

	mgmt := pb.GetStreams()[0]
	assert.Equal(t, "management", mgmt.GetService())
	assert.True(t, mgmt.GetAligned())
	assert.Equal(t, uint32(60), mgmt.GetPeriodSeconds())

	signal := pb.GetStreams()[1]
	assert.False(t, signal.GetAligned(), "a stock stream reports not aligned")
	assert.Zero(t, signal.GetPeriodSeconds())

	relay := pb.GetStreams()[2]
	assert.Equal(t, "relay", relay.GetService())
	assert.Equal(t, uint32(30), relay.GetPeriodSeconds())
}

// TestGetFullStatusAlignedHeartbeat: the full status carries the watcher
// state when a watcher exists, and none without one.
func TestGetFullStatusAlignedHeartbeat(t *testing.T) {
	assert.Nil(t, NewRecorder("https://mgmt:443").GetFullStatus().AlignedHeartbeat,
		"this build has no default watcher")

	w := hbwatch.New(realClockForTest{}, time.Minute)
	t.Cleanup(hbwatch.SetDefault(w))
	w.Register(hbwatch.Signal, hbwatch.Registration{Addr: "https://signal:443"})
	w.Seen(hbwatch.Signal, time.Minute)

	full := NewRecorder("https://mgmt:443").GetFullStatus()
	require.NotNil(t, full.AlignedHeartbeat)
	require.Len(t, full.AlignedHeartbeat.Streams, 1)
	assert.True(t, full.AlignedHeartbeat.Streams[0].Aligned)
}

type realClockForTest struct{}

func (realClockForTest) Now() time.Time                      { return time.Now() }
func (realClockForTest) AfterFunc(d time.Duration, f func()) { time.AfterFunc(d, f) }
