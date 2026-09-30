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

// ConnectionListener export internal Listener for mobile.
//
// It intentionally lacks OnStateChanged for now: adding a method to a gomobile
// interface breaks every Swift implementation, so the iOS app keeps building
// against the legacy per-state callbacks. A follow-up will extend it together
// with the app.
type ConnectionListener interface {
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

// OnStateChanged maps NoNetwork to the legacy reconnecting callback. NoNetwork
// has no per-state callback in peer.notifyListener, so dropping it leaves iOS
// displaying Connected during an outage. Other states already have callbacks.
func (a connectionListenerAdapter) OnStateChanged(state peer.ClientState) {
	if state == peer.ClientStateNoNetwork {
		a.OnConnecting()
	}
}
