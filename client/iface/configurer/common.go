package configurer

import (
	"net"
	"net/netip"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// buildPresharedKeyConfig creates a wgtypes.Config for setting a preshared key on a peer.
// This is a shared helper used by both kernel and userspace configurers.
func buildPresharedKeyConfig(peerKey wgtypes.Key, psk wgtypes.Key, updateOnly bool) wgtypes.Config {
	return wgtypes.Config{
		Peers: []wgtypes.PeerConfig{{
			PublicKey:    peerKey,
			PresharedKey: &psk,
			UpdateOnly:   updateOnly,
		}},
	}
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
