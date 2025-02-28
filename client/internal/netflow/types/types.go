package types

import (
	"net/netip"
	"time"

	"github.com/google/uuid"

	"github.com/netbirdio/netbird/client/iface/device"
)

type Protocol uint8

const (
	ProtocolUnknown = Protocol(0)
	ICMP            = Protocol(1)
	TCP             = Protocol(6)
	UDP             = Protocol(17)
	SCTP            = Protocol(132)
)

func (p Protocol) String() string {
	switch p {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	default:
		return "unknown"
	}
}

type Type int

const (
	TypeUnknown = iota
	TypeStart
	TypeEnd
)

type Direction int

func (d Direction) String() string {
	switch d {
	case Ingress:
		return "ingress"
	case Egress:
		return "egress"
	default:
		return "unknown"
	}
}

const (
	DirectionUnknown = Direction(iota)
	Ingress
	Egress
)

type Event struct {
	ID        string
	Timestamp time.Time
	EventFields
}

type EventFields struct {
	FlowID     uuid.UUID
	Type       Type
	Direction  Direction
	Protocol   Protocol
	SourceIP   netip.Addr
	DestIP     netip.Addr
	SourcePort uint16
	DestPort   uint16
	ICMPType   uint8
	ICMPCode   uint8
}

type FlowConfig struct {
	URL            string
	Interval       time.Duration
	Enabled        bool
	TokenPayload   string
	TokenSignature string
}

type FlowManager interface {
	// FlowConfig handles network map updates
	Update(update *FlowConfig) error
	// Close closes the manager
	Close()
	// GetLogger returns a flow logger
	GetLogger() FlowLogger
}

type FlowLogger interface {
	// StoreEvent stores a flow event
	StoreEvent(flowEvent EventFields)
	// GetEvents returns all stored events
	GetEvents() []*Event
	// Close closes the logger
	Close()
	// Enable enables the flow logger receiver
	Enable()
	// Disable disables the flow logger receiver
	Disable()
}

type Store interface {
	// StoreEvent stores a flow event
	StoreEvent(event *Event)
	// GetEvents returns all stored events
	GetEvents() []*Event
	// DeleteEvents deletes events from the store
	DeleteEvents([]string)
	// Close closes the store
	Close()
}

// ConnTracker defines the interface for connection tracking functionality
type ConnTracker interface {
	// Start begins tracking connections by listening for conntrack events.
	Start() error
	// Stop stops the connection tracking.
	Stop()
	// Close stops listening for events and cleans up resources
	Close() error
}

// IFaceMapper provides interface to check if we're using userspace WireGuard
type IFaceMapper interface {
	IsUserspaceBind() bool
	Name() string
	Address() device.WGAddress
}
