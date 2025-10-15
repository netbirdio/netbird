package activity

import (
	"errors"

	"github.com/netbirdio/netbird/client/internal/lazyconn"
)

// listener defines the contract for activity detection listeners.
type listener interface {
	ReadPackets()
	Close()
}

// newListener creates a listener appropriate for the WireGuard interface type.
// Returns BindListener for userspace bind mode with ICEBind, otherwise UDPListener.
func newListener(wgIface WgInterface, cfg lazyconn.PeerConfig) (listener, error) {
	if !wgIface.IsUserspaceBind() {
		return NewUDPListener(wgIface, cfg)
	}

	provider, ok := wgIface.(bindProvider)
	if !ok {
		return nil, errors.New("interface claims userspace bind but doesn't implement bindProvider")
	}

	return NewBindListener(wgIface, provider.GetBind(), cfg)
}
