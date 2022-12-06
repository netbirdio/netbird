package event

import "time"

const (
	// DeviceEvent describes an event that happened of a device (e.g, connected/disconnected)
	DeviceEvent Type = "device"
	// ManagementEvent describes an event that happened on a Management service (e.g., user added)
	ManagementEvent Type = "management"
)

type Type string

// Sink provides an interface to store or stream events.
type Sink interface {
	// Add an event to the sink.
	Add(event *Event) error
	// Close the sink flushing events if necessary
	Close() error
}

// Event represents a network activity event.
type Event struct {
	// Timestamp of the event
	Timestamp time.Time
	// Message of the event
	Message string
	// ID of the event (can be empty, meaning that it wasn't yet generated)
	ID uint64
	// Type of the event
	Type Type

	//

}
