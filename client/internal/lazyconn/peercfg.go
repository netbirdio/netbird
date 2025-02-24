package lazyconn

import (
	"net/netip"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type PeerConfig struct {
	PublicKey  wgtypes.Key
	AllowedIPs []netip.Prefix
}
