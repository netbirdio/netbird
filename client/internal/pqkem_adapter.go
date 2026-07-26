package internal

import (
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
