package internal

import (
	"net/netip"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/internal/pqkem"
)

// appliedGenerations records the newest PSK generation applied per peer, so an
// out-of-order OnNewPSKReady (two exchanges deriving concurrently) can't restore an
// older PSK over a newer one.
type appliedGenerations struct {
	mu   sync.Mutex
	last map[string]uint64
}

func newAppliedGenerations() *appliedGenerations {
	return &appliedGenerations{last: make(map[string]uint64)}
}

// apply runs set when gen is newer than the last generation applied for the peer, and
// reports whether it ran. The check and set run under one lock: with only the check
// atomic, an older apply already inside set could finish after a newer one and restore
// its stale key. The generation is recorded before set runs, so a failed newer apply
// still keeps an older one from landing afterwards. The lock is shared by all peers,
// which is cheap because set is a quick local interface call.
func (a *appliedGenerations) apply(peer string, gen uint64, set func() error) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if gen <= a.last[peer] {
		return false, nil
	}
	a.last[peer] = gen
	return true, set()
}

// locked runs fn under the apply lock, so it is ordered with every PSK push.
func (a *appliedGenerations) locked(fn func()) {
	a.mu.Lock()
	defer a.mu.Unlock()
	fn()
}

// pqPSKSource is the subset of the ML-KEM manager the reapply needs. *pqkem.Manager
// satisfies it.
type pqPSKSource interface {
	PSK(remoteID pqkem.RemoteID) (pqkem.PSK, bool)
}

// pqPSKReapplier programs the latest PQ PSK again after a WireGuard configure that may
// have used a stale one. The conn reads the PSK before configuring, and a rotation that
// commits in between pushes its key first, which the configure then overwrites.
type pqPSKReapplier struct {
	psks    pqPSKSource
	wg      pqPresharedKeySetter
	applied *appliedGenerations
}

// reapply reads the latest PSK under the apply lock: a push already done is visible in
// it, and a later push of a newer key runs after this one and wins.
func (r *pqPSKReapplier) reapply(peer string, programmed *wgtypes.Key) {
	r.applied.locked(func() {
		psk, ok := r.psks.PSK(pqkem.RemoteID(peer))
		if !ok || (programmed != nil && wgtypes.Key(psk) == *programmed) {
			return
		}
		log.Debugf("pqkem: reprogramming the latest PSK for peer %s after a stale configure", peer)
		if err := r.wg.SetPresharedKey(peer, wgtypes.Key(psk), true); err != nil {
			log.Warnf("pqkem: reprogram PSK for peer %s: %v", peer, err)
		}
	})
}

// pqPresharedKeySetter is the subset of the WireGuard interface the ML-KEM callback
// needs: programming a peer's preshared key. *iface.WGIface satisfies it.
type pqPresharedKeySetter interface {
	SetPresharedKey(peerKey string, psk wgtypes.Key, updateOnly bool) error
}

// pqStatusMarker is the subset of the status recorder ML-KEM needs: flagging a peer as
// post-quantum protected once its PSK is programmed, and clearing the flag when the peer
// downgrades. *peer.Status satisfies it.
type pqStatusMarker interface {
	MarkPeerQuantumResistant(peerPubKey string) error
	UnmarkPeerQuantumResistant(peerPubKey string) error
}

// pqCallbackHandler programs the derived PQ PSK onto the WireGuard peer. It is the
// engine-side implementation of pqkem.CallbackHandler.
type pqCallbackHandler struct {
	wg pqPresharedKeySetter
	// status reflects a newly programmed PSK in the peer's "Quantum resistance" flag.
	// Nil disables it.
	status pqStatusMarker
	// applied drops an out-of-order PSK apply so a stale callback can't overwrite a newer
	// key. Nil disables the guard.
	applied *appliedGenerations
	// recoverPQKeyOverSignal re-bootstraps the KEM over Signal for a peer (a fresh
	// signalling offer) after its exchange failed. Nil disables recovery.
	recoverPQKeyOverSignal func(remoteKey string)
}

// OnNewPSKReady programs the freshly derived PSK for the peer (updateOnly: a no-op
// if the peer is not present, mirroring Rosenpass). A callback whose generation is not
// newer than the last applied for the peer is dropped, so a reordered apply can't
// restore an older PSK over a newer one.
func (h pqCallbackHandler) OnNewPSKReady(remoteID pqkem.RemoteID, gen uint64, psk pqkem.PSK) error {
	// updateOnly: applies to an already-configured peer (rotation). At bootstrap the
	// peer is not configured yet, so this is a no-op there and the PSK is instead
	// pulled at peer-config time (pqHandshaker.PSK / conn.presharedKey).
	set := func() error {
		log.Tracef("pqkem: programming PSK for peer %s (gen %d)", remoteID, gen)
		return h.wg.SetPresharedKey(string(remoteID), wgtypes.Key(psk), true)
	}
	if h.applied == nil {
		if err := set(); err != nil {
			return err
		}
	} else {
		applied, err := h.applied.apply(string(remoteID), gen, set)
		if err != nil {
			return err
		}
		if !applied {
			log.Tracef("pqkem: dropping stale PSK apply for peer %s (gen %d)", remoteID, gen)
			return nil
		}
	}
	// The status flag is computed when the connection comes up; a PSK landing afterwards
	// would otherwise leave the peer reported as not quantum resistant.
	if h.status != nil {
		if err := h.status.MarkPeerQuantumResistant(string(remoteID)); err != nil {
			log.Debugf("pqkem: mark peer %s quantum resistant in status: %v", remoteID, err)
		}
	}
	return nil
}

// OnRekeyFailed reports a failed PQ (re)key convergence and re-bootstraps the KEM over
// Signal to recover: a fresh signalling offer starts a new exchange that overwrites the
// stalled PSK on both sides, resyncing after a persistent data-path desync. The tunnel
// stays up on the previous PSK meanwhile (the Signal channel is independent of the
// broken data path).
func (h pqCallbackHandler) OnRekeyFailed(remoteID pqkem.RemoteID) error {
	log.Debugf("pqkem: post-quantum key exchange failed for peer %s", remoteID)
	if h.recoverPQKeyOverSignal != nil {
		h.recoverPQKeyOverSignal(string(remoteID))
	}
	return nil
}

// pqHandshaker adapts the pqkem manager to peer.PQHandshaker (string peer keys),
// wiring the host's signalling offers/answers to the KEM exchange.
type pqHandshaker struct {
	mgr *pqkem.Manager
	// reapplier restores the latest PSK after a stale WireGuard configure. Nil disables it.
	reapplier *pqPSKReapplier
	// status clears the peer's "Quantum resistance" flag when it downgrades. Nil disables it.
	status pqStatusMarker
}

// announcedPort is the PQ data-path port to advertise to peers. It is sent even on
// DefaultPort: a non-zero port is how a peer that runs the KEM announces it, and a
// responder's offer carries nothing else that could (see SetRemoteAddr).
func (p pqHandshaker) announcedPort() uint16 {
	return uint16(p.mgr.LocalPort())
}

// markNonCapable records that the peer sent no KEM where one was due, and clears its
// status flag when that drops the PSK we held with it.
func (p pqHandshaker) markNonCapable(remoteKey string) {
	if !p.mgr.MarkNonCapable(pqkem.RemoteID(remoteKey)) || p.status == nil {
		return
	}
	if err := p.status.UnmarkPeerQuantumResistant(remoteKey); err != nil {
		log.Debugf("pqkem: unmark peer %s quantum resistant in status: %v", remoteKey, err)
	}
}

// OfferPayload builds the KEM offer to attach to an outgoing signalling offer for the
// peer, plus the data-path port to announce (0 when on DefaultPort). Payload is nil when
// this side has no offer to send.
func (p pqHandshaker) OfferPayload(remoteKey string) ([]byte, uint16) {
	payload, err := p.mgr.SignalOffer(pqkem.RemoteID(remoteKey))
	if err != nil {
		log.Warnf("pqkem: build offer for %s: %v", remoteKey, err)
	}
	return payload, p.announcedPort()
}

// ShouldSendBootstrapOffer reports whether the controller should reply to the peer's
// KEM-less offer with its own bootstrap offer instead of an answer.
func (p pqHandshaker) ShouldSendBootstrapOffer(remoteKey string) bool {
	return p.mgr.ShouldSendBootstrapOffer(pqkem.RemoteID(remoteKey))
}

// SignalOfferInFlight reports whether our KEM offer over signalling to the peer still
// awaits its answer.
func (p pqHandshaker) SignalOfferInFlight(remoteKey string) bool {
	return p.mgr.SignalOfferInFlight(pqkem.RemoteID(remoteKey))
}

// AnswerPayload processes a received KEM offer (nil when absent) and returns the KEM
// answer to attach to the outgoing signalling answer, plus the data-path port to announce
// (0 when on DefaultPort). An empty offer is treated as a capability signal.
func (p pqHandshaker) AnswerPayload(remoteKey string, recvOffer []byte) ([]byte, uint16) {
	if len(recvOffer) == 0 {
		// Capability signal (responder side): the KEM offer flows initiator->responder,
		// so if we are the responder for this peer (it is the KEM initiator by role) an
		// empty offer means it does not run the KEM. If we are the initiator, an empty
		// offer is normal — the peer is the responder and puts its material in the
		// answer — so we must not flag it.
		if !p.mgr.IsInitiator(pqkem.RemoteID(remoteKey)) {
			p.markNonCapable(remoteKey)
		}
		return nil, p.announcedPort()
	}
	payload, err := p.mgr.SignalOnOffer(pqkem.RemoteID(remoteKey), recvOffer)
	if err != nil {
		log.Warnf("pqkem: build answer for %s: %v", remoteKey, err)
	}
	return payload, p.announcedPort()
}

// OnAnswer feeds a received KEM answer (nil when absent) into the exchange. An empty
// answer to our offer is treated as a capability signal on the initiator side.
func (p pqHandshaker) OnAnswer(remoteKey string, recvAnswer []byte) {
	if len(recvAnswer) == 0 {
		// Capability signal (initiator side): an empty answer to our KEM offer means the
		// peer does not run the KEM, so mark it non-capable to stop offering (no
		// failure/recovery storm). Answering an offer that carried no KEM, an empty answer
		// says nothing, from either role.
		if p.mgr.SignalOfferInFlight(pqkem.RemoteID(remoteKey)) {
			p.markNonCapable(remoteKey)
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

// ReapplyPSK programs the peer's latest PSK again when the conn configured WireGuard with
// a different one.
func (p pqHandshaker) ReapplyPSK(remoteKey string, programmed *wgtypes.Key) {
	if p.reapplier != nil {
		p.reapplier.reapply(remoteKey, programmed)
	}
}

// SetRemoteAddr registers the peer's data-path endpoint learned from signalling. Sends
// only ever fire once the tunnel is up (clocked by OnDataPathRekeyed), so registering here
// is safe even before connection-up. A non-zero port means the peer runs the KEM, so one
// found non-capable earlier is offered it again; this is how a peer that enabled ML-KEM
// after we met it gets upgraded. A zero port comes from a peer that does not run the KEM
// and is resolved to DefaultPort, harmlessly, since nothing is sent to such a peer.
func (p pqHandshaker) SetRemoteAddr(remoteKey string, addr netip.AddrPort) {
	if !addr.Addr().IsValid() {
		return
	}
	port := addr.Port()
	if port == 0 {
		port = DefaultPort
	} else {
		p.mgr.ClearNonCapable(pqkem.RemoteID(remoteKey))
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
