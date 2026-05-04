package rosenpass

import (
	"sync"

	rp "cunicu.li/go-rosenpass"
	log "github.com/sirupsen/logrus"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// PresharedKeySetter is the interface for setting preshared keys on WireGuard peers.
// This minimal interface allows rosenpass to update PSKs without depending on the full WGIface.
type PresharedKeySetter interface {
	SetPresharedKey(peerKey string, psk wgtypes.Key, updateOnly bool) error
}

type wireGuardPeer struct {
	Interface string
	PublicKey rp.Key
}

type NetbirdHandler struct {
	mu               sync.Mutex
	iface            PresharedKeySetter
	peers            map[rp.PeerID]wireGuardPeer
	initializedPeers map[rp.PeerID]bool
}

func NewNetbirdHandler() *NetbirdHandler {
	return &NetbirdHandler{
		peers:            map[rp.PeerID]wireGuardPeer{},
		initializedPeers: map[rp.PeerID]bool{},
	}
}

// SetInterface sets the WireGuard interface for the handler.
// This must be called after the WireGuard interface is created.
func (h *NetbirdHandler) SetInterface(iface PresharedKeySetter) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.iface = iface
}

func (h *NetbirdHandler) AddPeer(pid rp.PeerID, intf string, pk rp.Key) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.peers[pid] = wireGuardPeer{
		Interface: intf,
		PublicKey: pk,
	}
}

func (h *NetbirdHandler) RemovePeer(pid rp.PeerID) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.peers, pid)
	delete(h.initializedPeers, pid)
}

// IsPeerInitialized returns true if Rosenpass has completed a handshake
// and set a PSK for this peer.
func (h *NetbirdHandler) IsPeerInitialized(pid rp.PeerID) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.initializedPeers[pid]
}

func (h *NetbirdHandler) HandshakeCompleted(pid rp.PeerID, key rp.Key) {
	h.outputKey(rp.KeyOutputReasonStale, pid, key)
}

func (h *NetbirdHandler) HandshakeExpired(pid rp.PeerID) {
	key, _ := rp.GeneratePresharedKey()
	h.outputKey(rp.KeyOutputReasonStale, pid, key)
}

func (h *NetbirdHandler) outputKey(_ rp.KeyOutputReason, pid rp.PeerID, psk rp.Key) {
	h.mu.Lock()
	iface := h.iface
	wg, ok := h.peers[pid]
	isInitialized := h.initializedPeers[pid]
	h.mu.Unlock()

	if iface == nil {
		log.Warn("rosenpass: interface not set, cannot update preshared key")
		return
	}

	if !ok {
		return
	}

	peerKey := wgtypes.Key(wg.PublicKey).String()
	pskKey := wgtypes.Key(psk)

	// Use updateOnly=true for later rotations (peer already has Rosenpass PSK)
	// Use updateOnly=false for first rotation (peer has original/empty PSK)
	if err := iface.SetPresharedKey(peerKey, pskKey, isInitialized); err != nil {
		log.Errorf("Failed to apply rosenpass key: %v", err)
		return
	}

	// Mark peer as isInitialized after the successful first rotation
	if !isInitialized {
		h.mu.Lock()
		if _, exists := h.peers[pid]; exists {
			h.initializedPeers[pid] = true
		}
		h.mu.Unlock()
	}
}
