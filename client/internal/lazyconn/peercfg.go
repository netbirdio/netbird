package lazyconn

import (
	"net/netip"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/peer/id"
)

type PeerConfig struct {
	PublicKey  string
	AllowedIPs []netip.Prefix
	PeerConnID id.ConnID
	Log        *log.Entry
}
