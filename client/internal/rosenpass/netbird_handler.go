package rosenpass

import (
	"net"
	"net/netip"
	"time"

	rp "cunicu.li/go-rosenpass"
	log "github.com/sirupsen/logrus"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/configurer"
)

// WGConfigurer is the interface for configuring WireGuard peers.
// This abstraction allows rosenpass to work with both kernel WireGuard (via wgctrl)
// and userspace WireGuard (via IPC) on platforms like Android/iOS.
type WGConfigurer interface {
	FullStats() (*configurer.Stats, error)
	UpdatePeer(peerKey string, allowedIps []netip.Prefix, keepAlive time.Duration, endpoint *net.UDPAddr, preSharedKey *wgtypes.Key) error
	RemovePeer(peerKey string) error
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

	peerKey := wgtypes.Key(wg.PublicKey).String()

	stats, err := h.configurer.FullStats()
	if err != nil {
		log.Errorf("Failed to get WireGuard stats: %v", err)
		return
	}

	// Find the peer in current WireGuard config
	var peer *configurer.Peer
	for i := range stats.Peers {
		if stats.Peers[i].PublicKey == peerKey {
			peer = &stats.Peers[i]
			break
		}
	}

	if peer == nil {
		log.Warnf("rosenpass: peer %s not found in WireGuard config", peerKey)
		return
	}

	pskKey := (*wgtypes.Key)(&psk)

	// Convert peer config for update
	allowedIPs := ipNetsToNetipPrefixes(peer.AllowedIPs)
	var endpoint *net.UDPAddr
	if peer.Endpoint.IP != nil {
		endpoint = &peer.Endpoint
	}

	// If no preshared key is set or it's the original NetBird preshared key,
	// we need to restart the connection by removing and re-adding the peer
	if !peer.PresharedKey || h.isOriginalPresharedKey(peer) {

		// Remove the peer first
		if err := h.configurer.RemovePeer(peerKey); err != nil {
			log.Errorf("rosenpass: failed to remove peer for restart: %v", err)
			return
		}

		// Re-add peer with new preshared key
		if err := h.configurer.UpdatePeer(peerKey, allowedIPs, 0, endpoint, pskKey); err != nil {
			log.Errorf("rosenpass: failed to re-add peer with PSK: %v", err)
		} else {
			log.Infof("rosenpass: applied PSK to peer %s", peerKey)
		}
		return
	}

	// Just update the preshared key
	if err := h.configurer.UpdatePeer(peerKey, allowedIPs, 0, endpoint, pskKey); err != nil {
		log.Errorf("rosenpass: failed to update PSK: %v", err)
	} else {
		log.Infof("rosenpass: updated PSK for peer %s", peerKey)
	}
}

// isOriginalPresharedKey checks if the peer might be using the original NetBird preshared key.
// Since stats only provides a boolean, we can't verify the actual key value.
// We return false here, meaning we only restart when no PSK is set at all.
func (h *NetbirdHandler) isOriginalPresharedKey(_ *configurer.Peer) bool {
	return false
}

// ipNetsToNetipPrefixes converts []net.IPNet to []netip.Prefix
func ipNetsToNetipPrefixes(ipNets []net.IPNet) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(ipNets))
	for _, ipNet := range ipNets {
		if addr, ok := netip.AddrFromSlice(ipNet.IP); ok {
			ones, _ := ipNet.Mask.Size()
			prefix := netip.PrefixFrom(addr, ones)
			prefixes = append(prefixes, prefix)
		}
	}
	return prefixes
}
