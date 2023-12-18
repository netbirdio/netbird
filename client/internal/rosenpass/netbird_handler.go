package rosenpass

import (
	"fmt"
	"log/slog"

	rp "cunicu.li/go-rosenpass"
	log "github.com/sirupsen/logrus"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type wireGuardPeer struct {
	Interface string
	PublicKey rp.Key
}

type NetbirdHandler struct {
	ifaceName    string
	client       *wgctrl.Client
	peers        map[rp.PeerID]wireGuardPeer
	presharedKey [32]byte
}

func NewNetbirdHandler(preSharedKey *[32]byte, wgIfaceName string) (hdlr *NetbirdHandler, err error) {
	hdlr = &NetbirdHandler{
		ifaceName: wgIfaceName,
		peers:     map[rp.PeerID]wireGuardPeer{},
	}

	if preSharedKey != nil {
		hdlr.presharedKey = *preSharedKey
	}

	if hdlr.client, err = wgctrl.New(); err != nil {
		return nil, fmt.Errorf("failed to creat WireGuard client: %w", err)
	}

	return hdlr, nil
}

func (h *NetbirdHandler) AddPeer(pid rp.PeerID, intf string, pk rp.Key) {
	h.peers[pid] = wireGuardPeer{
		Interface: intf,
		PublicKey: pk,
	}
}

func (h *NetbirdHandler) RemovePeer(pid rp.PeerID) {
	delete(h.peers, pid)
}

func (h *NetbirdHandler) HandshakeCompleted(pid rp.PeerID, key rp.Key) {
	log.Debug("Handshake complete")
	h.outputKey(rp.KeyOutputReasonStale, pid, key)
}

func (h *NetbirdHandler) HandshakeExpired(pid rp.PeerID) {
	key, _ := rp.GeneratePresharedKey()
	log.Debug("Handshake expired")
	h.outputKey(rp.KeyOutputReasonStale, pid, key)
}

func (h *NetbirdHandler) outputKey(_ rp.KeyOutputReason, pid rp.PeerID, psk rp.Key) {
	wg, ok := h.peers[pid]
	if !ok {
		return
	}

	device, err := h.client.Device(h.ifaceName)
	if err != nil {
		log.Errorf("Failed to get WireGuard device: %v", err)
		return
	}
	config := []wgtypes.PeerConfig{
		{
			UpdateOnly:   true,
			PublicKey:    wgtypes.Key(wg.PublicKey),
			PresharedKey: (*wgtypes.Key)(&psk),
		},
	}
	for _, peer := range device.Peers {
		if peer.PublicKey == wgtypes.Key(wg.PublicKey) {
			if publicKeyEmpty(peer.PresharedKey) || peer.PresharedKey == h.presharedKey {
				log.Debugf("Restart wireguard connection to peer %s", peer.PublicKey)
				config = []wgtypes.PeerConfig{
					{
						PublicKey:    wgtypes.Key(wg.PublicKey),
						PresharedKey: (*wgtypes.Key)(&psk),
						Endpoint:     peer.Endpoint,
						AllowedIPs:   peer.AllowedIPs,
					},
				}
				err = h.client.ConfigureDevice(wg.Interface, wgtypes.Config{
					Peers: []wgtypes.PeerConfig{
						{
							Remove:    true,
							PublicKey: wgtypes.Key(wg.PublicKey),
						},
					},
				})
				if err != nil {
					slog.Debug("Failed to remove peer")
					return
				}
			}

		}
	}

	if err = h.client.ConfigureDevice(wg.Interface, wgtypes.Config{
		Peers: config,
	}); err != nil {
		log.Errorf("Failed to apply rosenpass key: %v", err)
	}
}

func publicKeyEmpty(key wgtypes.Key) bool {
	for _, b := range key {
		if b != 0 {
			return false
		}
	}
	return true
}
