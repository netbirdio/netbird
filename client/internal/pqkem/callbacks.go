package pqkem

// CallbackHandler is implemented by the host and invoked by the library. The
// library only reports events; the host owns the reaction. Keeping this an
// interface — rather than touching the transport or keying directly — is what lets
// the KEM code be extracted as a standalone library.
type CallbackHandler interface {
	// OnNewPSKReady fires when a fresh post-quantum PSK has been derived for a peer
	// and must be programmed into the consumer's secure channel. It is invoked at
	// the commit point of each side: the initiator on receiving the answer, the
	// responder on receiving the confirm.
	//
	// bootstrap is true when the PSK came from a signalling exchange (initial setup or
	// a wake re-negotiation) rather than a data-path rotation. On bootstrap the consumer
	// must ensure the live channel actually adopts the PSK now (e.g. force a WireGuard
	// re-handshake) — the channel may already be up on a pre-PQ key. A rotation
	// (bootstrap=false) is adopted at the channel's next natural rekey.
	OnNewPSKReady(remoteID RemoteID, psk PSK, bootstrap bool) error

	// OnRekeyFailed fires when an exchange fails to converge within the allotted
	// time. The host should tear the peer connection down so it re-establishes, and
	// log a WARN. The library reports the event; it does not dictate the reaction.
	OnRekeyFailed(remoteID RemoteID) error
}
