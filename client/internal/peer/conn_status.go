package peer

// connStatusInputs is the primitive-valued snapshot of the state that drives the
// tri-state connection classification. Extracted so the decision logic can be unit-tested
// without constructing full Worker/Handshaker objects.
type connStatusInputs struct {
	forceRelay          bool // NB_FORCE_RELAY or JS/WASM
	peerUsesRelay       bool // remote peer advertises relay support AND local has relay
	relayConnected      bool // statusRelay reports Connected (independent of whether peer uses relay)
	remoteSupportsICE   bool // remote peer sent ICE credentials
	iceWorkerCreated    bool // local ICE worker exists (false in force-relay mode)
	iceStatusConnecting bool // statusICE is anything other than Disconnected
	iceInProgress       bool // a negotiation is currently in flight
}
