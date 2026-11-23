package peer

import (
	"github.com/netbirdio/netbird/client/hbwatch"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/shared/alignedhb"
)

// alignedHeartbeatSnapshot returns the aligned heartbeat state of the
// default watcher, nil on a client that does not watch heartbeats.
func alignedHeartbeatSnapshot() *hbwatch.Snapshot {
	snap, ok := hbwatch.CurrentSnapshot()
	if !ok {
		return nil
	}
	return &snap
}

// alignedHeartbeatToProto converts the aligned heartbeat state to its
// proto form: per service whether the stream is aligned, and its period.
// Nil for a nil snap, so the status of a client without a watcher is
// unchanged.
func alignedHeartbeatToProto(snap *hbwatch.Snapshot) *proto.AlignedHeartbeatState {
	if snap == nil {
		return nil
	}
	out := &proto.AlignedHeartbeatState{}
	for _, st := range snap.Streams {
		out.Streams = append(out.Streams, &proto.AlignedHeartbeatStream{
			Service:       string(st.Service),
			Address:       st.Addr,
			Aligned:       st.Aligned,
			PeriodSeconds: alignedhb.PeriodSeconds(st.Period),
		})
	}
	return out
}
