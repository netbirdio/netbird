package peer

import (
	log "github.com/sirupsen/logrus"
)

const (
	// StatusIdle indicate the peer is in disconnected state
	StatusIdle ConnStatus = iota
	// StatusConnecting indicate the peer is in connecting state
	StatusConnecting
	// StatusConnected indicate the peer is in connected state
	StatusConnected
)

// connStatusInputs is the primitive-valued snapshot of the state that drives the
// tri-state connection classification. Extracted so the decision logic can be unit-tested
// without constructing full Worker/Handshaker objects.
type connStatusInputs struct {
	forceRelay          bool // NB_FORCE_RELAY or JS/WASM
	peerUsesRelay       bool // remote peer advertises relay support AND local has relay
	relayConnected      bool // statusRelay reports Connected (independent of whether peer uses relay)
	remoteSupportsICE   bool // remote peer sent ICE credentials
	iceWorkerCreated    bool // local WorkerICE exists (false in force-relay mode)
	iceStatusConnecting bool // statusICE is anything other than Disconnected
	iceInProgress       bool // a negotiation is currently in flight
}


// ConnStatus describe the status of a peer's connection
type ConnStatus int32

func (s ConnStatus) String() string {
	switch s {
	case StatusConnecting:
		return "Connecting"
	case StatusConnected:
		return "Connected"
	case StatusIdle:
		return "Idle"
	default:
		log.Errorf("unknown status: %d", s)
		return "INVALID_PEER_CONNECTION_STATUS"
	}
}
