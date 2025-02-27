package types

import (
	"net/netip"
	"time"

	"github.com/google/uuid"
)

type Type int

const (
	TypeStart = iota
	TypeEnd
)

type Direction int

const (
	Ingress = iota
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
	Protocol   uint8
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
