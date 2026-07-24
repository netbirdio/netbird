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
	// initialized is true once a completed exchange has set a
	// Rosenpass-managed PSK for this peer.
	initialized bool
	// chainKey is the key output by the last completed exchange, advanced by
	// one ratchet step on expiry. Nil until the first exchange completes and
	// after the peer has fallen back to the rendezvous key.
	chainKey *wgtypes.Key
	// expiries counts failed renewals since the last completed exchange.
	expiries int
}

type NetbirdHandler struct {
	mu    sync.Mutex
	iface PresharedKeySetter
	// preSharedKey is the account-level preshared key, used as the rendezvous
	// key when set. Nil means the deterministic seed key is used instead.
	preSharedKey *[32]byte
	// localWgKey is the local WireGuard public key, one of the two inputs to
	// the deterministic seed key.
	localWgKey wgtypes.Key
	peers      map[rp.PeerID]*wireGuardPeer
}

func NewNetbirdHandler(preSharedKey *[32]byte, localWgKey wgtypes.Key) *NetbirdHandler {
	return &NetbirdHandler{
		preSharedKey: preSharedKey,
		localWgKey:   localWgKey,
		peers:        map[rp.PeerID]*wireGuardPeer{},
	}
}

// SetInterface sets the WireGuard interface for the handler.
// This must be called after the WireGuard interface is created.
func (h *NetbirdHandler) SetInterface(iface PresharedKeySetter) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.iface = iface
}

// AddPeer registers a peer with the handler. Re-adding a known peer (every
// reconnection does) keeps its key recovery state.
func (h *NetbirdHandler) AddPeer(pid rp.PeerID, intf string, pk rp.Key) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if existing, ok := h.peers[pid]; ok && existing.PublicKey == pk {
		existing.Interface = intf
		return
	}
	h.peers[pid] = &wireGuardPeer{
		Interface: intf,
		PublicKey: pk,
	}
}

func (h *NetbirdHandler) RemovePeer(pid rp.PeerID) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.peers, pid)
}

// IsPeerInitialized returns true if Rosenpass has completed a handshake
// and set a PSK for this peer.
func (h *NetbirdHandler) IsPeerInitialized(pid rp.PeerID) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	peer, ok := h.peers[pid]
	return ok && peer.initialized
}

// HandshakeCompleted programs the freshly exchanged output key and resets the
// peer's key recovery state.
func (h *NetbirdHandler) HandshakeCompleted(pid rp.PeerID, key rp.Key) {
	psk := wgtypes.Key(key)

	h.mu.Lock()
	defer h.mu.Unlock()

	peer, ok := h.peers[pid]
	if !ok {
		return
	}
	if peer.expiries > 0 {
		log.Infof("rosenpass exchange completed for peer %s after %d expired renewals", wgtypes.Key(peer.PublicKey), peer.expiries)
	}
	// chainKey tracks the shared exchange output regardless of the local write
	// outcome, so both ends still converge on the next expiry.
	peer.chainKey = &psk
	peer.expiries = 0
	if !h.applyKeyLocked(pid, psk, peer.initialized) {
		return
	}
	peer.initialized = true
}

// HandshakeExpired replaces the expired key. The renewal exchange runs over
// the tunnel keyed by the PSK itself, so the replacement must be derivable on
// both ends without communication: the first expiry ratchets the last shared
// key forward, repeated expiries (and expiries without a completed exchange)
// fall back to the rendezvous key and drop the peer out of the initialized
// state so connection reconfigurations reprogram the rendezvous key as well.
func (h *NetbirdHandler) HandshakeExpired(pid rp.PeerID) {
	h.mu.Lock()
	defer h.mu.Unlock()

	peer, ok := h.peers[pid]
	if !ok {
		return
	}

	peer.expiries++

	var psk wgtypes.Key
	if peer.chainKey != nil && peer.expiries == 1 {
		log.Infof("rosenpass key for peer %s expired without renewal, advancing to ratcheted key", wgtypes.Key(peer.PublicKey))
		psk = RatchetKey(*peer.chainKey)
		peer.chainKey = &psk
	} else {
		rendezvous, err := h.rendezvousKey(peer)
		if err != nil {
			// Fail closed: without a rendezvous key the expired key must
			// still be rotated out, even if the replacement is unusable.
			log.Errorf("failed to derive rendezvous key, replacing expired key with a random one: %v", err)
			h.applyRandomKeyLocked(pid)
			return
		}
		log.Warnf("rosenpass key for peer %s expired %d times without renewal, falling back to the rendezvous key", wgtypes.Key(peer.PublicKey), peer.expiries)
		psk = rendezvous
		peer.chainKey = nil
		peer.initialized = false
	}

	h.applyKeyLocked(pid, psk, true)
}

// rendezvousKey returns the key both ends converge on without communication:
// the account-level preshared key when configured, the deterministic seed key
// otherwise. It mirrors the key that peer connections program when Rosenpass
// does not manage the peer yet.
func (h *NetbirdHandler) rendezvousKey(peer *wireGuardPeer) (wgtypes.Key, error) {
	if h.preSharedKey != nil {
		return *h.preSharedKey, nil
	}

	seed, err := DeterministicSeedKey(h.localWgKey.String(), wgtypes.Key(peer.PublicKey).String())
	if err != nil {
		return wgtypes.Key{}, err
	}
	return *seed, nil
}

// applyKeyLocked writes the preshared key for the peer to the WireGuard
// interface and reports whether the write succeeded. Callers must hold h.mu
// for the whole state-mutation-plus-write so that a concurrent completion and
// expiry cannot reorder their writes relative to the in-memory chain key.
func (h *NetbirdHandler) applyKeyLocked(pid rp.PeerID, psk wgtypes.Key, updateOnly bool) bool {
	peer, ok := h.peers[pid]
	if !ok {
		return false
	}

	if h.iface == nil {
		log.Warn("rosenpass: interface not set, cannot update preshared key")
		return false
	}

	peerKey := wgtypes.Key(peer.PublicKey).String()
	if err := h.iface.SetPresharedKey(peerKey, psk, updateOnly); err != nil {
		log.Errorf("Failed to apply rosenpass key: %v", err)
		return false
	}

	return true
}

func (h *NetbirdHandler) applyRandomKeyLocked(pid rp.PeerID) {
	key, err := rp.GeneratePresharedKey()
	if err != nil {
		log.Errorf("failed to generate random preshared key: %v", err)
		return
	}
	h.applyKeyLocked(pid, wgtypes.Key(key), true)
}
