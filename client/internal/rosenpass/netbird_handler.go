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
	client       *wgctrl.Client
	peers        map[rp.PeerID]wireGuardPeer
	presharedKey [32]byte
}

func NewNetbirdHandler(preSharedKey [32]byte) (hdlr *NetbirdHandler, err error) {
	hdlr = &NetbirdHandler{
		peers:        map[rp.PeerID]wireGuardPeer{},
		presharedKey: preSharedKey,
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
	log.Debug("Applaying new key")
	wg, ok := h.peers[pid]
	if !ok {
		return
	}
	log.Debug("Getting devices")

	devices, err := h.client.Devices()
	if err != nil {
		slog.Error("Failed to get WireGuard devices", slog.Any("error", err))
		return
	}
	config := []wgtypes.PeerConfig{
		{
			UpdateOnly:   true,
			PublicKey:    wgtypes.Key(wg.PublicKey),
			PresharedKey: (*wgtypes.Key)(&psk),
		},
	}
	for _, device := range devices {
		for _, peer := range device.Peers {
			if peer.PublicKey == wgtypes.Key(wg.PublicKey) {
				log.Debug("Found WireGuard peer")
				if publicKeyEmpty(peer.PresharedKey) || peer.PresharedKey == h.presharedKey {
					config = []wgtypes.PeerConfig{
						{
							PublicKey:    wgtypes.Key(wg.PublicKey),
							PresharedKey: (*wgtypes.Key)(&psk),
							Endpoint:     peer.Endpoint,
							AllowedIPs:   peer.AllowedIPs,
						},
					}
					err := h.client.ConfigureDevice(wg.Interface, wgtypes.Config{
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
	}

	if err := h.client.ConfigureDevice(wg.Interface, wgtypes.Config{
		Peers: config,
	}); err != nil {
		slog.Error("Failed to configure WireGuard peer",
			slog.Any("interface", wg.Interface),
			slog.Any("peer", wg.PublicKey),
			slog.Any("error", err))
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
