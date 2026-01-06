package rosenpass

import (
	"net"

	rp "cunicu.li/go-rosenpass"
	log "github.com/sirupsen/logrus"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/configurer"
)

// WGConfigurer is the interface for configuring WireGuard peers.
// This abstraction allows rosenpass to work with both kernel WireGuard (via wgctrl)
// and userspace WireGuard (via IPC) on platforms like Android/iOS.
type WGConfigurer interface {
	ConfigureDevice(config wgtypes.Config) error
	FullStats() (*configurer.Stats, error)
}

type wireGuardPeer struct {
	Interface string
	PublicKey rp.Key
}

type NetbirdHandler struct {
	configurer   WGConfigurer
	peers        map[rp.PeerID]wireGuardPeer
	presharedKey [32]byte
}

func NewNetbirdHandler(preSharedKey *[32]byte) *NetbirdHandler {
	hdlr := &NetbirdHandler{
		peers: map[rp.PeerID]wireGuardPeer{},
	}

	if preSharedKey != nil {
		hdlr.presharedKey = *preSharedKey
	}

	return hdlr
}

// SetConfigurer sets the WireGuard configurer for the handler.
// This must be called after the WireGuard interface is created.
func (h *NetbirdHandler) SetConfigurer(configurer WGConfigurer) {
	h.configurer = configurer
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
	h.outputKey(rp.KeyOutputReasonStale, pid, key)
}

func (h *NetbirdHandler) HandshakeExpired(pid rp.PeerID) {
	key, _ := rp.GeneratePresharedKey()
	h.outputKey(rp.KeyOutputReasonStale, pid, key)
}

func (h *NetbirdHandler) outputKey(_ rp.KeyOutputReason, pid rp.PeerID, psk rp.Key) {
	if h.configurer == nil {
		log.Warn("rosenpass: WGConfigurer not set, cannot update preshared key")
		return
	}

	wg, ok := h.peers[pid]
	if !ok {
		return
	}

	stats, err := h.configurer.FullStats()
	if err != nil {
		log.Errorf("Failed to get WireGuard device: %v", err)
		return
	}

	// Default: UpdateOnly mode - only update PSK, preserve all other settings
	config := []wgtypes.PeerConfig{
		{
			UpdateOnly:   true,
			PublicKey:    wgtypes.Key(wg.PublicKey),
			PresharedKey: (*wgtypes.Key)(&psk),
		},
	}

	// Find the peer and check if we need to restart the connection
	for _, peer := range stats.Peers {
		if peer.PublicKey == wgtypes.Key(wg.PublicKey).String() {
			if publicKeyEmpty(peer.PresharedKey) || peer.PresharedKey == h.presharedKey {
				log.Debugf("Restart wireguard connection to peer %s", peer.PublicKey)

				// Build full peer config preserving all settings including keepalive
				var endpoint *net.UDPAddr
				if peer.Endpoint.IP != nil {
					endpoint = &peer.Endpoint
				}
				keepalive := peer.PersistentKeepalive

				config = []wgtypes.PeerConfig{
					{
						PublicKey:                   wgtypes.Key(wg.PublicKey),
						PresharedKey:                (*wgtypes.Key)(&psk),
						Endpoint:                    endpoint,
						AllowedIPs:                  peer.AllowedIPs,
						PersistentKeepaliveInterval: &keepalive,
					},
				}

				// Remove the peer first
				err = h.configurer.ConfigureDevice(wgtypes.Config{
					Peers: []wgtypes.PeerConfig{
						{
							Remove:    true,
							PublicKey: wgtypes.Key(wg.PublicKey),
						},
					},
				})
				if err != nil {
					log.Debugf("Failed to remove peer: %v", err)
					return
				}
			}
			break
		}
	}

	if err = h.configurer.ConfigureDevice(wgtypes.Config{
		Peers: config,
	}); err != nil {
		log.Errorf("Failed to apply rosenpass key: %v", err)
	}
}

func publicKeyEmpty(key [32]byte) bool {
	for _, b := range key {
		if b != 0 {
			return false
		}
	}
	return true
}
