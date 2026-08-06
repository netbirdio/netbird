package internal

import (
	"net/netip"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/internal/pqkem"
)

// pqPresharedKeySetter is the subset of the WireGuard interface the ML-KEM callback
// needs: programming a peer's preshared key. *iface.WGIface satisfies it.
type pqPresharedKeySetter interface {
	SetPresharedKey(peerKey string, psk wgtypes.Key, updateOnly bool) error
}

// pqCallbackHandler programs the derived PQ PSK onto the WireGuard peer. It is the
// engine-side implementation of pqkem.CallbackHandler.
type pqCallbackHandler struct {
	wg pqPresharedKeySetter
	// reoffer re-bootstraps the KEM over Signal for a peer (a fresh signalling offer)
	// to recover from a persistent data-path rekey failure. Nil disables recovery.
	reoffer func(remoteKey string)
}

// OnNewPSKReady programs the freshly derived PSK for the peer (updateOnly: a no-op
// if the peer is not present, mirroring Rosenpass).
func (h pqCallbackHandler) OnNewPSKReady(remoteID pqkem.RemoteID, psk pqkem.PSK) error {
	// updateOnly: applies to an already-configured peer (rotation). At bootstrap the
	// peer is not configured yet, so this is a no-op there and the PSK is instead
	// pulled at peer-config time (pqHandshaker.PSK / conn.presharedKey).
	log.Tracef("pqkem: programming PSK for peer %s", remoteID)
	return h.wg.SetPresharedKey(string(remoteID), wgtypes.Key(psk), true)
}

// OnRekeyFailed reports a failed PQ (re)key convergence and re-bootstraps the KEM over
// Signal to recover: a fresh signalling offer starts a new exchange that overwrites the
// stalled PSK on both sides, resyncing after a persistent data-path desync. The tunnel
// stays up on the previous PSK meanwhile (the Signal channel is independent of the
// broken data path).
func (h pqCallbackHandler) OnRekeyFailed(remoteID pqkem.RemoteID) error {
	log.Warnf("pqkem: post-quantum rekey failed for peer %s, re-bootstrapping over signal", remoteID)
	if h.reoffer != nil {
		h.reoffer(string(remoteID))
	}
	return nil
}

// pqHandshaker adapts the pqkem manager to peer.PQHandshaker (string peer keys),
// wiring the host's signalling offers/answers to the KEM exchange.
type pqHandshaker struct {
	mgr *pqkem.Manager
}

// announcedPort is the PQ data-path port to advertise to peers. It is omitted (0) when
// the manager is on DefaultPort, since peers assume the default when no port is sent;
// only a non-default (collision-forced) port is announced explicitly.
func (p pqHandshaker) announcedPort() int {
	if port := p.mgr.LocalPort(); port != DefaultPort {
		return port
	}
	return 0
}

func (p pqHandshaker) OfferPayload(remoteKey string) ([]byte, int) {
	payload, err := p.mgr.SignalOffer(pqkem.RemoteID(remoteKey))
	if err != nil {
		log.Warnf("pqkem: build offer for %s: %v", remoteKey, err)
	}
	return payload, p.announcedPort()
}

func (p pqHandshaker) AnswerPayload(remoteKey string, recvOffer []byte) ([]byte, int) {
	if len(recvOffer) == 0 {
		// Capability signal (responder side): the KEM offer flows initiator->responder,
		// so if we are the responder for this peer (it is the KEM initiator by role) an
		// empty offer means it does not run the KEM. If we are the initiator, an empty
		// offer is normal — the peer is the responder and puts its material in the
		// answer — so we must not flag it.
		if !p.mgr.IsInitiator(pqkem.RemoteID(remoteKey)) {
			p.mgr.MarkNonCapable(pqkem.RemoteID(remoteKey))
		}
		return nil, p.announcedPort()
	}
	payload, err := p.mgr.SignalOnOffer(pqkem.RemoteID(remoteKey), recvOffer)
	if err != nil {
		log.Warnf("pqkem: build answer for %s: %v", remoteKey, err)
	}
	return payload, p.announcedPort()
}

func (p pqHandshaker) OnAnswer(remoteKey string, recvAnswer []byte) {
	if len(recvAnswer) == 0 {
		// Capability signal (initiator side): the KEM answer flows responder->initiator,
		// so an empty answer to our offer means the peer does not run the KEM — mark it
		// non-capable to stop offering (no failure/reoffer storm). Only meaningful when
		// we are the initiator: as the responder we also receive an (empty) answer to
		// our own non-KEM offer from a perfectly capable peer, which must not be flagged.
		if p.mgr.IsInitiator(pqkem.RemoteID(remoteKey)) {
			p.mgr.MarkNonCapable(pqkem.RemoteID(remoteKey))
		}
		return
	}
	if err := p.mgr.SignalOnAnswer(pqkem.RemoteID(remoteKey), recvAnswer); err != nil {
		log.Warnf("pqkem: process answer from %s: %v", remoteKey, err)
	}
}

// PSK exposes the peer's derived PSK for the conn to program at WG peer-config time.
func (p pqHandshaker) PSK(remoteKey string) (wgtypes.Key, bool) {
	psk, ok := p.mgr.PSK(pqkem.RemoteID(remoteKey))
	if !ok {
		return wgtypes.Key{}, false
	}
	return wgtypes.Key(psk), true
}

// SetRemoteAddr registers the peer's data-path endpoint learned from signalling. A
// zero port means the peer omitted it (it is on DefaultPort), so we resolve it here —
// DefaultPort lives in this package, not in peer. Sends only ever fire once the tunnel
// is up (clocked by OnDataPathRekeyed), so registering here is safe even before
// connection-up.
func (p pqHandshaker) SetRemoteAddr(remoteKey string, addr netip.AddrPort) {
	if !addr.Addr().IsValid() {
		return
	}
	port := addr.Port()
	if port == 0 {
		port = DefaultPort
	}
	p.mgr.AddPeer(pqkem.RemoteID(remoteKey), netip.AddrPortFrom(addr.Addr(), port))
}

// OnDataPathRekeyed clocks the next chained PSK rotation on a fresh WG handshake.
// sinceActivity is how long ago the peer last exchanged real user data; the manager
// skips rotation for idle tunnels.
func (p pqHandshaker) OnDataPathRekeyed(remoteKey string, sinceActivity time.Duration) {
	p.mgr.OnDataPathRekeyed(pqkem.RemoteID(remoteKey), sinceActivity)
}

// OnDataPathDown signals the peer's tunnel went down.
func (p pqHandshaker) OnDataPathDown(remoteKey string) {
	p.mgr.OnDataPathDown(pqkem.RemoteID(remoteKey))
}
