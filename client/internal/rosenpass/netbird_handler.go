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
	SetPresharedKey(peerKey string, psk wgtypes.Key, originalPSK [32]byte) error
}

type wireGuardPeer struct {
	Interface string
	PublicKey rp.Key
}

type NetbirdHandler struct {
	mu           sync.Mutex
	iface        PresharedKeySetter
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
	presharedKey := h.presharedKey
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

	if err := iface.SetPresharedKey(peerKey, pskKey, presharedKey); err != nil {
		log.Errorf("Failed to apply rosenpass key: %v", err)
	}
}
