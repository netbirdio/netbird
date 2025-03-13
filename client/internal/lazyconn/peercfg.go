package lazyconn

import (
	"net/netip"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/peer"
)

type PeerConfig struct {
	PublicKey  string
	AllowedIPs []netip.Prefix
	PeerConnID peer.ConnID
	Log        *log.Entry
}
