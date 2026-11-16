//go:build ios

package NetBirdSDK

import (
	"github.com/netbirdio/netbird/client/internal/peer"
)

// Client state values, re-exported as basic constants so gomobile emits them
// into the generated bindings. They mirror peer.ClientState*: append-only,
// never reorder.
const (
	ClientStateDisconnected  = int(peer.ClientStateDisconnected)
	ClientStateConnected     = int(peer.ClientStateConnected)
	ClientStateConnecting    = int(peer.ClientStateConnecting)
	ClientStateDisconnecting = int(peer.ClientStateDisconnecting)
	ClientStateNoNetwork     = int(peer.ClientStateNoNetwork)
)

// ConnectionListener exports the internal listener for mobile, carrying typed
// states as plain integers for gomobile bindings.
type ConnectionListener interface {
	OnStateChanged(state int)
	OnConnected()
	OnDisconnected()
	OnConnecting()
	OnDisconnecting()
	OnAddressChanged(string, string)
	OnPeersListChanged(int)
}

// connectionListenerAdapter adapts the gomobile-facing ConnectionListener to
// peer.Listener.
type connectionListenerAdapter struct {
	ConnectionListener
}

func (a connectionListenerAdapter) OnStateChanged(state peer.ClientState) {
	a.ConnectionListener.OnStateChanged(int(state))
}
