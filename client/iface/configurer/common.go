package configurer

import (
	"net"
	"net/netip"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// buildPresharedKeyConfig creates a wgtypes.Config for setting a preshared key on a peer.
// This is a shared helper used by both kernel and userspace configurers.
func buildPresharedKeyConfig(peerKey string, psk wgtypes.Key, updateOnly bool) (wgtypes.Config, error) {
	peerKeyParsed, err := wgtypes.ParseKey(peerKey)
	if err != nil {
		return wgtypes.Config{}, err
	}
	return wgtypes.Config{
		Peers: []wgtypes.PeerConfig{{
			PublicKey:    peerKeyParsed,
			PresharedKey: &psk,
			UpdateOnly:   updateOnly,
		}},
	}, nil
}

func prefixesToIPNets(prefixes []netip.Prefix) []net.IPNet {
	ipNets := make([]net.IPNet, len(prefixes))
	for i, prefix := range prefixes {
		ipNets[i] = net.IPNet{
			IP:   prefix.Addr().AsSlice(),                             // Convert netip.Addr to net.IP
			Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen()), // Create subnet mask
		}
	}
	return ipNets
}
