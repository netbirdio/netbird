package types

import (
	"net/netip"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

const ZoneID = 0x1BD0

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
	case 132:
		return "SCTP"
	default:
		return strconv.FormatUint(uint64(p), 10)
	}
}

type Type int

const (
	TypeUnknown = Type(iota)
	TypeStart
	TypeEnd
	TypeDrop
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
	ID        uuid.UUID
	Timestamp time.Time
	EventFields
}

type EventFields struct {
	FlowID           uuid.UUID
	Type             Type
	RuleID           []byte
	Direction        Direction
	Protocol         Protocol
	SourceIP         netip.Addr
	DestIP           netip.Addr
	SourceResourceID []byte
	DestResourceID   []byte
	SourcePort       uint16
	DestPort         uint16
	ICMPType         uint8
	ICMPCode         uint8
	RxPackets        uint64
	TxPackets        uint64
	RxBytes          uint64
	TxBytes          uint64
}

type FlowConfig struct {
	URL                string
	Interval           time.Duration
	Enabled            bool
	Counters           bool
	TokenPayload       string
	TokenSignature     string
	DNSCollection      bool
	ExitNodeCollection bool
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
	// DeleteEvents deletes events from the store
	DeleteEvents([]uuid.UUID)
	// Close closes the logger
	Close()
	// Enable enables the flow logger receiver
	Enable()
	// UpdateConfig updates the flow manager configuration
	UpdateConfig(dnsCollection, exitNodeCollection bool)
}

type Store interface {
	// StoreEvent stores a flow event
	StoreEvent(event *Event)
	// GetEvents returns all stored events
	GetEvents() []*Event
	// DeleteEvents deletes events from the store
	DeleteEvents([]uuid.UUID)
	// Close closes the store
	Close()
}

// ConnTracker defines the interface for connection tracking functionality
type ConnTracker interface {
	// Start begins tracking connections by listening for conntrack events.
	Start(bool) error
	// Stop stops the connection tracking.
	Stop()
	// Close stops listening for events and cleans up resources
	Close() error
}

// IFaceMapper provides interface to check if we're using userspace WireGuard
type IFaceMapper interface {
	IsUserspaceBind() bool
	Name() string
	Address() wgaddr.Address
}
