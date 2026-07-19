package configurer

import (
	"net"
	"net/netip"
	"time"

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

// buildIdlePeerEndpointConfig creates a config that removes and re-creates a peer in a
// single transaction with the given allowed IPs, endpoint and disabled keepalive.
func buildIdlePeerEndpointConfig(peerKey wgtypes.Key, allowedIPs []netip.Prefix, endpoint *net.UDPAddr) wgtypes.Config {
	keepAlive := time.Duration(0)
	return wgtypes.Config{
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey: peerKey,
				Remove:    true,
			},
			{
				PublicKey:                   peerKey,
				AllowedIPs:                  prefixesToIPNets(allowedIPs),
				Endpoint:                    endpoint,
				PersistentKeepaliveInterval: &keepAlive,
			},
		},
	}
}

// mergePrefixes returns the union of the two prefix lists, keeping the original order and
// dropping duplicates.
func mergePrefixes(current, base []netip.Prefix) []netip.Prefix {
	merged := make([]netip.Prefix, 0, len(current)+len(base))
	seen := make(map[netip.Prefix]struct{}, len(current)+len(base))
	for _, group := range [][]netip.Prefix{current, base} {
		for _, prefix := range group {
			if _, ok := seen[prefix]; ok {
				continue
			}
			seen[prefix] = struct{}{}
			merged = append(merged, prefix)
		}
	}
	return merged
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
