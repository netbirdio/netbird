package pqkem

// WGCallbackHandler is implemented by the host (the NetBird wiring layer) and
// invoked by the library. The library only reports events; the host owns the
// WireGuard reaction. Keeping this an interface — rather than calling wgctrl
// directly — is what lets the KEM code be extracted as a standalone library.
type WGCallbackHandler interface {
	// OnNewPSKReady fires when a fresh post-quantum PSK has been derived for a
	// peer and must be programmed on the WireGuard interface. It is invoked at the
	// commit point of each side: the initiator on receiving the answer, the
	// responder on receiving the confirm.
	OnNewPSKReady(remoteWgKey string, psk PSK) error

	// OnRekeyFailed fires when an exchange fails to converge within the allotted
	// time. The host should tear the peer connection down so ICE re-establishes,
	// and log a WARN. The library reports the event; it does not dictate the
	// reaction.
	OnRekeyFailed(remoteWgKey string) error
}
