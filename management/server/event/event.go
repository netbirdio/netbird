package event

import "time"

const (
	// DeviceEvent describes an event that happened of a device (e.g, connected/disconnected)
	DeviceEvent Type = "device"
	// ManagementEvent describes an event that happened on a Management service (e.g., user added)
	ManagementEvent Type = "management"
)

type Type string

// Store provides an interface to store or stream events.
type Store interface {
	// Save an event in the store
	Save(event Event) (*Event, error)
	// GetSince returns a list of events from the store for a given account since the specified time
	GetSince(accountID string, from time.Time) ([]Event, error)
	// GetLast returns a top N of events from the store for a given account (ordered by timestamp desc)
	GetLast(accountID string, limit int) ([]Event, error)
	// Close the sink flushing events if necessary
	Close() error
}

// Event represents a network/system activity event.
type Event struct {
	// Timestamp of the event
	Timestamp time.Time
	// Operation that was performed during the event
	Operation string
	// ID of the event (can be empty, meaning that it wasn't yet generated)
	ID uint64
	// Type of the event
	Type Type
	// ModifierID is the ID of an object that modifies a Target
	ModifierID string
	// TargetID is the ID of an object that a Modifier modifies
	TargetID string
	// AccountID where event happened
	AccountID string
}

// Copy the event
func (e *Event) Copy() *Event {
	return &Event{
		Timestamp:  e.Timestamp,
		Operation:  e.Operation,
		ID:         e.ID,
		Type:       e.Type,
		ModifierID: e.ModifierID,
		TargetID:   e.TargetID,
		AccountID:  e.AccountID,
	}
}
