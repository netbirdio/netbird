package internal

import (
	"net/netip"

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
}

// OnNewPSKReady programs the freshly derived PSK for the peer (updateOnly: a no-op
// if the peer is not present, mirroring Rosenpass). remoteID is the peer's WG pubkey.
func (h pqCallbackHandler) OnNewPSKReady(remoteID pqkem.RemoteID, psk pqkem.PSK) error {
	// updateOnly: applies to an already-configured peer (rotation). At bootstrap the
	// peer is not configured yet, so this is a no-op there and the PSK is instead
	// pulled at peer-config time (pqHandshaker.PSK / conn.presharedKey).
	log.Debugf("pqkem: programming PSK for peer %s", remoteID)
	return h.wg.SetPresharedKey(string(remoteID), wgtypes.Key(psk), true)
}

// OnRekeyFailed reports a failed PQ (re)key convergence.
// TODO(NET-1406): tear the peer connection down / trigger ICE reconnect.
func (h pqCallbackHandler) OnRekeyFailed(remoteID pqkem.RemoteID) error {
	log.Warnf("pqkem: post-quantum rekey failed for peer %s", remoteID)
	return nil
}

// pqHandshaker adapts the pqkem manager to peer.PQHandshaker (string peer keys),
// wiring the host's signalling offers/answers to the KEM exchange.
type pqHandshaker struct {
	mgr *pqkem.Manager
}

func (p pqHandshaker) OfferPayload(remoteKey string) ([]byte, int) {
	payload, err := p.mgr.SignalOffer(pqkem.RemoteID(remoteKey))
	if err != nil {
		log.Warnf("pqkem: build offer for %s: %v", remoteKey, err)
	}
	return payload, p.mgr.LocalPort()
}

func (p pqHandshaker) AnswerPayload(remoteKey string, recvOffer []byte) ([]byte, int) {
	if len(recvOffer) == 0 {
		return nil, p.mgr.LocalPort()
	}
	payload, err := p.mgr.SignalOnOffer(pqkem.RemoteID(remoteKey), recvOffer)
	if err != nil {
		log.Warnf("pqkem: build answer for %s: %v", remoteKey, err)
	}
	return payload, p.mgr.LocalPort()
}

func (p pqHandshaker) OnAnswer(remoteKey string, recvAnswer []byte) {
	if len(recvAnswer) == 0 {
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

// SetRemoteAddr registers the peer's data-path endpoint (overlay IP + pq UDP port)
// learned from signalling. Sends only ever fire once the tunnel is up (clocked by
// OnDataPathRekeyed), so registering here is safe even before connection-up.
func (p pqHandshaker) SetRemoteAddr(remoteKey string, addr netip.AddrPort) {
	if !addr.IsValid() || addr.Port() == 0 {
		return
	}
	p.mgr.AddPeer(pqkem.RemoteID(remoteKey), addr)
}

// OnDataPathRekeyed clocks the next chained PSK rotation on a fresh WG handshake.
func (p pqHandshaker) OnDataPathRekeyed(remoteKey string) {
	p.mgr.OnDataPathRekeyed(pqkem.RemoteID(remoteKey))
}

// OnDataPathDown signals the peer's tunnel went down.
func (p pqHandshaker) OnDataPathDown(remoteKey string) {
	p.mgr.OnDataPathDown(pqkem.RemoteID(remoteKey))
}
