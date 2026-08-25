package peer

// ClientState identifies the client connection state delivered via
// Listener.OnStateChanged.
type ClientState int

// Client states. The numeric values cross the gomobile boundary (the mobile
// bindings re-export them as integer constants), so they are a wire format:
// append new states at the end, never reorder or insert.
const (
	ClientStateDisconnected ClientState = iota
	ClientStateConnected
	ClientStateConnecting
	ClientStateDisconnecting
	// ClientStateNoNetwork is an overlay state: it is never stored as the
	// last notification, only derived from ClientStateConnecting while the
	// OS reports no usable network (see notifier.effectiveState).
	ClientStateNoNetwork
)

// Listener is a callback type about the NetBird network connection state
type Listener interface {
	// OnStateChanged reports every client state transition. New states are
	// delivered only through this callback; the per-state callbacks below
	// are kept for compatibility and will be removed once all consumers
	// have migrated.
	OnStateChanged(state ClientState)

	// Deprecated: consume OnStateChanged instead.
	OnConnected()
	// Deprecated: consume OnStateChanged instead.
	OnDisconnected()
	// Deprecated: consume OnStateChanged instead.
	OnConnecting()
	// Deprecated: consume OnStateChanged instead.
	OnDisconnecting()

	OnAddressChanged(string, string)
	OnPeersListChanged(int)
}
