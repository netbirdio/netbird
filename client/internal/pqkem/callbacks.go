package pqkem

// CallbackHandler is implemented by the host and invoked by the library. The
// library only reports events; the host owns the reaction. Keeping this an
// interface — rather than touching the transport or keying directly — is what lets
// the KEM code be extracted as a standalone library.
type CallbackHandler interface {
	// OnNewPSKReady fires when a fresh post-quantum PSK has been derived for a peer
	// and must be programmed into the consumer's secure channel. The protocol has no
	// explicit confirm: the initiator fires it on receiving the answer, the responder
	// fires it right after deriving the PSK from the offer and before sending that
	// answer. A fired callback therefore means the key is derived locally, not that the
	// peer has confirmed it — the next offer is the later acknowledgement.
	OnNewPSKReady(remoteID RemoteID, psk PSK) error

	// OnRekeyFailed fires when an exchange fails to converge within the allotted time.
	// Recovery is host-defined: the library reports the event and does not dictate the
	// reaction. The shipped NetBird host, for instance, re-bootstraps the KEM over
	// signalling and keeps the tunnel on its previous PSK rather than tearing the
	// connection down.
	OnRekeyFailed(remoteID RemoteID) error
}
