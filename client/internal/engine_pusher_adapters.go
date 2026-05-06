package internal

import (
	"context"

	"github.com/netbirdio/netbird/client/internal/peer"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

// enginePushSink bridges the Engine's mgmClient to the PushSink interface
// consumed by connStatePusher. Phase 3.7i of #5989.
type enginePushSink struct{ engine *Engine }

func (s *enginePushSink) Push(ctx context.Context, m *mgmProto.PeerConnectionMap) error {
	return s.engine.mgmClient.SyncPeerConnections(ctx, m)
}

// enginePeerStateSource bridges the Engine's statusRecorder to the
// PeerStateSource interface consumed by connStatePusher. Phase 3.7i of #5989.
type enginePeerStateSource struct{ engine *Engine }

func (s *enginePeerStateSource) SnapshotAllRemotePeers() []PeerStateChangeEvent {
	fs := s.engine.statusRecorder.GetFullStatus()
	out := make([]PeerStateChangeEvent, 0, len(fs.Peers))
	for _, st := range fs.Peers {
		out = append(out, peerStateToEvent(st.PubKey, st))
	}
	return out
}

// peerStateToEvent converts a peer.State to a PeerStateChangeEvent suitable
// for the connStatePusher. The Endpoint field is set to
// "local ↔ remote" when both ICE candidate endpoints are known.
func peerStateToEvent(pubkey string, st peer.State) PeerStateChangeEvent {
	var ct mgmProto.ConnType
	switch {
	case st.ConnStatus == peer.StatusConnected && !st.Relayed:
		ct = mgmProto.ConnType_CONN_TYPE_P2P
	case st.ConnStatus == peer.StatusConnected && st.Relayed:
		ct = mgmProto.ConnType_CONN_TYPE_RELAYED
	case st.ConnStatus == peer.StatusConnecting:
		ct = mgmProto.ConnType_CONN_TYPE_CONNECTING
	default:
		ct = mgmProto.ConnType_CONN_TYPE_IDLE
	}

	endpoint := st.LocalIceCandidateEndpoint
	if endpoint != "" && st.RemoteIceCandidateEndpoint != "" {
		endpoint = st.LocalIceCandidateEndpoint + " <-> " + st.RemoteIceCandidateEndpoint
	}

	return PeerStateChangeEvent{
		Pubkey:        pubkey,
		ConnType:      ct,
		LastHandshake: st.LastWireguardHandshake,
		LatencyMS:     uint32(st.Latency.Milliseconds()),
		Endpoint:      endpoint,
		RelayServer:   st.RelayServerAddress,
		RxBytes:       uint64(st.BytesRx),
		TxBytes:       uint64(st.BytesTx),
	}
}
