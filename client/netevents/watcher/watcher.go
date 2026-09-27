package watcher

import "context"

// EventKind indicates the scope or target of a network lifecycle event.
type EventKind int

const (
	// EventNetworkDisconnected indicates that the host network is offline.
	EventNetworkDisconnected EventKind = iota
	// EventNetworkConnected indicates that the host network connectivity is restored.
	EventNetworkConnected
	// EventUnderlyingVPNDisconnected indicates that an underlying VPN connection disconnected.
	EventUnderlyingVPNDisconnected
	// EventUnderlyingVPNConnected indicates that an underlying VPN connection connected.
	EventUnderlyingVPNConnected
	// EventNetBirdInterfaceDisconnected indicates that the NetBird interface itself was disconnected.
	EventNetBirdInterfaceDisconnected
)

// String returns the human-readable string representation of an EventKind.
func (k EventKind) String() string {
	switch k {
	case EventNetworkDisconnected:
		return "NetworkDisconnected"
	case EventNetworkConnected:
		return "NetworkConnected"
	case EventUnderlyingVPNDisconnected:
		return "UnderlyingVPNDisconnected"
	case EventUnderlyingVPNConnected:
		return "UnderlyingVPNConnected"
	case EventNetBirdInterfaceDisconnected:
		return "NetBirdInterfaceDisconnected"
	default:
		return "Unknown"
	}
}

// Event carries details about an OS network or VPN lifecycle event.
type Event struct {
	Kind          EventKind
	Name          string
	Reason        string
	UserInitiated bool
}

// Handler receives network events from a Watcher.
type Handler interface {
	OnNetworkEvent(ev Event)
}

// HandlerFunc adapts a function to the Handler interface.
type HandlerFunc func(ev Event)

// OnNetworkEvent dispatches the event to the underlying function.
func (f HandlerFunc) OnNetworkEvent(ev Event) {
	f(ev)
}

// Watcher monitors the host network subsystem for connectivity and VPN events.
type Watcher interface {
	Start(ctx context.Context, handler Handler) error
	Stop() error
}
