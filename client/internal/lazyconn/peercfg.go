package lazyconn

import (
	"net/netip"
)

type PeerConfig struct {
	PublicKey  string
	AllowedIPs []netip.Prefix
}
