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

// prefixesToIPNets converts prefixes on their way to a device. It is the only place that
// conversion happens, so it also normalizes: the device is then given the same form the
// store records, and a v4-mapped prefix cannot reach net.IPNet, which prints such an
// address as v4 while taking the length from its 16 byte mask and so turns
// ::ffff:10.1.2.3/64 into 10.1.2.3/0 — an allowed IP matching every v4 address.
func prefixesToIPNets(prefixes []netip.Prefix) []net.IPNet {
	ipNets := make([]net.IPNet, len(prefixes))
	for i, prefix := range prefixes {
		normalized := normalizePrefix(prefix)
		ipNets[i] = net.IPNet{
			IP:   normalized.Addr().AsSlice(),
			Mask: net.CIDRMask(normalized.Bits(), normalized.Addr().BitLen()),
		}
	}
	return ipNets
}
