package lazyconn

import (
	"net/netip"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/internal/peer/id"
)

type PeerConfig struct {
	PublicKey  string
	AllowedIPs []netip.Prefix
	PeerConnID id.ConnID
	Log        *log.Entry
	// PresharedKey returns the key to install with the idle WireGuard peer, or nil to
	// leave the peer's key as it is. It is read when the peer is installed, not when the
	// config is built, so it reflects keys derived after the peer joined. A nil func
	// leaves the key unchanged too.
	PresharedKey func() *wgtypes.Key
}

// IdlePresharedKey is the key to install with the idle WireGuard peer (nil: unchanged).
func (c PeerConfig) IdlePresharedKey() *wgtypes.Key {
	if c.PresharedKey == nil {
		return nil
	}
	return c.PresharedKey()
}
