package internal

import (
	"testing"
	"time"

	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

// Codex review: isMaterialChange did NOT include RelayServer in its
// per-field comparison, so a peer migrating between relay servers
// would not generate an immediate-push event. Lock that in.
func TestIsMaterialChange_RelayServerFlip(t *testing.T) {
	ts := time.Date(2026, 5, 3, 20, 0, 0, 0, time.UTC)
	prev := PeerStateChangeEvent{
		Pubkey:        "peer1",
		ConnType:      mgmProto.ConnType_CONN_TYPE_RELAYED,
		Endpoint:      "100.87.61.232:51820",
		LastHandshake: ts,
		LatencyMS:     20,
		RelayServer:   "rels://relay1.example:443/relay",
	}
	cur := prev
	cur.RelayServer = "rels://relay2.example:443/relay"
	if !isMaterialChange(prev, cur) {
		t.Error("RelayServer change must register as material — UI/dashboard relies on this for relay-server flip surfacing")
	}
}

func TestIsMaterialChange_NoChange(t *testing.T) {
	ts := time.Date(2026, 5, 3, 20, 0, 0, 0, time.UTC)
	ev := PeerStateChangeEvent{
		Pubkey:        "peer1",
		ConnType:      mgmProto.ConnType_CONN_TYPE_P2P,
		Endpoint:      "100.87.61.232:51820",
		LastHandshake: ts,
		LatencyMS:     10,
		RelayServer:   "rels://r.example:443/relay",
	}
	if isMaterialChange(ev, ev) {
		t.Error("identical events must not be material")
	}
}

func TestIsMaterialChange_LatencyBelowThreshold(t *testing.T) {
	prev := PeerStateChangeEvent{Pubkey: "p1", LatencyMS: 10}
	cur := prev
	cur.LatencyMS = 12 // delta = 2, below 5 ms threshold
	if isMaterialChange(prev, cur) {
		t.Error("2 ms latency change must not be material (threshold = 5 ms)")
	}
}

func TestIsMaterialChange_LatencyAtThreshold(t *testing.T) {
	prev := PeerStateChangeEvent{Pubkey: "p1", LatencyMS: 10}
	cur := prev
	cur.LatencyMS = 15 // delta = 5, at threshold
	if !isMaterialChange(prev, cur) {
		t.Error("5 ms latency change must be material (threshold = 5 ms inclusive)")
	}
}

func TestIsMaterialChange_HandshakeProgress(t *testing.T) {
	t0 := time.Date(2026, 5, 3, 20, 0, 0, 0, time.UTC)
	prev := PeerStateChangeEvent{Pubkey: "p1", LastHandshake: t0}
	cur := prev
	cur.LastHandshake = t0.Add(time.Second)
	if !isMaterialChange(prev, cur) {
		t.Error("newer handshake must be material (peer is actively talking)")
	}
}

func TestIsMaterialChange_ConnTypeFlip(t *testing.T) {
	prev := PeerStateChangeEvent{Pubkey: "p1", ConnType: mgmProto.ConnType_CONN_TYPE_RELAYED}
	cur := prev
	cur.ConnType = mgmProto.ConnType_CONN_TYPE_P2P
	if !isMaterialChange(prev, cur) {
		t.Error("conn-type change must always be material")
	}
}

func TestIsMaterialChange_EndpointFlip(t *testing.T) {
	prev := PeerStateChangeEvent{Pubkey: "p1", Endpoint: "1.2.3.4:51820"}
	cur := prev
	cur.Endpoint = "5.6.7.8:51820"
	if !isMaterialChange(prev, cur) {
		t.Error("endpoint change must always be material (NAT roam, P2P/Relay flip)")
	}
}
