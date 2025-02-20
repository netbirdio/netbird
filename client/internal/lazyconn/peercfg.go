package lazyconn

import (
	"net"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type PeerConfig struct {
	PublicKey wgtypes.Key
	AllowedIP net.IPNet
}
