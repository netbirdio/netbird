package event

import log "github.com/sirupsen/logrus"

type Type int

func (s Type) String() string {
	switch s {
	case ConnectedToManagement:
		return "ConnectedToManagement"
	case ConnectedToSignal:
		return "ConnectedToSignal"
	case PeerDisconnected:
		return "PeerDisconnected"
	case PeerConnected:
		return "PeerConnected"
	case ReceivedManagementUpdate:
		return "ReceivedManagementUpdate"
	case ReceivedSignal:
		return "ReceivedSignal"
	default:
		log.Errorf("unknown event type: %d", s)
		return "INVALID_EVENT"
	}
}

const (
	// ConnectedToManagement indicates the client app is connected to the Management service and receives updates.
	ConnectedToManagement = iota
	// ConnectedToSignal indicates the client app is connected to the Signal service and receives messages.
	ConnectedToSignal
	// PeerDisconnected indicates that the client app has disconnected from a peer
	PeerDisconnected
	// PeerConnected indicates that the client app has connected to a peer
	PeerConnected
	// ReceivedManagementUpdate indicates that the client app has received an update from the Management service
	ReceivedManagementUpdate
	// ReceivedSignal indicates that the client app has received a message from the Signal service
	ReceivedSignal
)

// Event represents a client application event
type Event struct {
	t    Type
	data interface{}
}

// New creates a new Event with provided type and data
func New(t Type, data interface{}) Event {
	return Event{
		t:    t,
		data: data,
	}
}

// Type returns the Event type
func (e *Event) Type() Type {
	return e.t
}

// Data returns the Event data
func (e *Event) Data() interface{} {
	return e.data
}
