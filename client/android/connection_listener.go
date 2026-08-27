//go:build android

package android

import (
	"github.com/netbirdio/netbird/client/internal/peer"
)

// Client state values delivered via ConnectionListener.OnStateChanged,
// re-exported as basic constants so gomobile emits them into the generated
// Java bindings. They mirror peer.ClientState*: append-only, never reorder.
const (
	ClientStateDisconnected  = int(peer.ClientStateDisconnected)
	ClientStateConnected     = int(peer.ClientStateConnected)
	ClientStateConnecting    = int(peer.ClientStateConnecting)
	ClientStateDisconnecting = int(peer.ClientStateDisconnecting)
	ClientStateNoNetwork     = int(peer.ClientStateNoNetwork)
)

// ConnectionListener export internal Listener for mobile. It mirrors
// peer.Listener with OnStateChanged taking a plain int (one of the
// ClientState* constants), because gomobile cannot bind named types.
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
// peer.Listener, converting the typed state to the int the binding carries.
type connectionListenerAdapter struct {
	ConnectionListener
}

func (a connectionListenerAdapter) OnStateChanged(state peer.ClientState) {
	a.ConnectionListener.OnStateChanged(int(state))
}
