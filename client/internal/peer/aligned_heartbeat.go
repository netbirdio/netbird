package peer

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/netbirdio/netbird/client/hbwatch"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/shared/alignedhb"
)

// alignedHeartbeatSnapshot returns the aligned heartbeat state, nil on a client
// that does not watch heartbeats.
func alignedHeartbeatSnapshot() *hbwatch.Snapshot {
	snap, ok := hbwatch.CurrentSnapshot()
	if !ok {
		return nil
	}
	return &snap
}

// AlignedHeartbeatToProto converts the aligned heartbeat state to its proto
// form, nil for a nil snap.
func AlignedHeartbeatToProto(snap *hbwatch.Snapshot) *proto.AlignedHeartbeatState {
	if snap == nil {
		return nil
	}
	out := &proto.AlignedHeartbeatState{}
	for _, st := range snap.Streams {
		pb := &proto.AlignedHeartbeatStream{
			Service:           string(st.Service),
			Address:           st.Addr,
			Level:             string(st.Level),
			PeriodSeconds:     alignedhb.PeriodSeconds(st.Period),
			PhaseMillis:       millis(st.Phase),
			LastHeartbeat:     timestamp(st.LastHeartbeat),
			CorrectionBlocked: st.Blocked,
			BlockedInRow:      uint32(max(st.BlockedInRow, 0)),
			ClampHits:         uint32(max(st.ClampHits, 0)),
		}
		if st.LastCorrection != nil {
			pb.LastCorrection = correctionToProto(*st.LastCorrection)
		}
		out.Streams = append(out.Streams, pb)
	}
	for _, c := range snap.Corrections {
		out.Corrections = append(out.Corrections, correctionToProto(c))
	}
	return out
}

func correctionToProto(c hbwatch.Correction) *proto.AlignedHeartbeatCorrection {
	return &proto.AlignedHeartbeatCorrection{
		Service:           string(c.Service),
		Address:           c.Addr,
		Time:              timestamp(c.At),
		OffsetMillis:      c.Offset.Milliseconds(),
		FromPhaseMillis:   millis(c.From),
		WantedPhaseMillis: millis(c.Wanted),
		Result:            string(c.Result),
	}
}

// millis returns a phase in whole milliseconds. Phases are below the maximum
// period, far inside the uint32 range.
func millis(d time.Duration) uint32 {
	return uint32(max(d.Milliseconds(), 0))
}

func timestamp(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}
