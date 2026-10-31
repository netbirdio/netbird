package iface

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

// ErrOverlayRangeReserved is returned when a peer is asked to carry the overlay range itself.
var ErrOverlayRangeReserved = errors.New("prefix is the reserved overlay range")

// reserveOverlay binds the whole overlay range to a placeholder peer that never has an endpoint
// and never completes a handshake.
//
// WireGuard picks the peer for an address by the longest allowed IPs match, in both directions.
// A peer that has not been added yet has no entry, so a routed prefix covering its address, an
// exit node's 0.0.0.0/0, would be the longest match: the exit node could send as that peer and
// would be sent what is addressed to it. With the placeholder in place such an address is
// dropped locally, and a peer's own addresses still win as soon as they are added, being more
// specific than the overlay range.
//
// replace drops a reservation made earlier first, since adding a peer only adds allowed IPs. It
// must be false right after the device was configured, which removes all peers. The caller holds
// w.mu.
func (w *WGIface) reserveOverlay(replace bool) error {
	if w.configurer == nil {
		return ErrIfaceNotFound
	}

	if w.overlayPeerKey == "" {
		priv, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			return fmt.Errorf("generate overlay placeholder key: %w", err)
		}
		w.overlayPeerKey = priv.PublicKey().String()
	}

	if replace && len(w.overlayRange) > 0 {
		if err := w.configurer.RemovePeer(w.overlayPeerKey); err != nil {
			return fmt.Errorf("release overlay range: %w", err)
		}
	}
	w.overlayRange = nil

	prefixes := overlayPrefixes(w.tun.WgAddress())
	if err := w.configurer.UpdatePeer(w.overlayPeerKey, prefixes, 0, nil, nil); err != nil {
		return fmt.Errorf("reserve overlay range: %w", err)
	}
	w.overlayRange = prefixes

	log.Debugf("reserved overlay range %v on interface %s for a placeholder peer", prefixes, w.tun.DeviceName())
	return nil
}

func overlayPrefixes(addr wgaddr.Address) []netip.Prefix {
	prefixes := []netip.Prefix{addr.Network.Masked()}
	if addr.HasIPv6() && addr.IPv6Net.IsValid() {
		prefixes = append(prefixes, addr.IPv6Net.Masked())
	}
	return prefixes
}

// checkNotOverlayRange refuses prefixes that would take the overlay range away from the placeholder.
// WireGuard gives a prefix to one peer only, so a peer given the exact range replaces the placeholder
// and the addresses in it are no longer reserved. Prefixes that contain the range, such as an exit
// node's 0.0.0.0/0, or sit inside it, such as a peer's own address, do not conflict. The caller holds
// w.mu.
func (w *WGIface) checkNotOverlayRange(prefixes ...netip.Prefix) error {
	for _, p := range prefixes {
		if slices.Contains(w.overlayRange, p.Masked()) {
			return fmt.Errorf("%w: %s", ErrOverlayRangeReserved, p)
		}
	}
	return nil
}
