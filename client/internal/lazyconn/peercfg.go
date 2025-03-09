package lazyconn

import (
	"net/netip"

	"github.com/netbirdio/netbird/client/internal/peer"
)

type PeerConfig struct {
	PublicKey  string
	AllowedIPs []netip.Prefix
	PeerConnID peer.ConnID
}
