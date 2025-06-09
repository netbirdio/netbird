package activity

import (
	"time"
)

const (
	SystemInitiator = "sys"
)

// ActivityDescriber is an interface that describes an activity
type ActivityDescriber interface { //nolint:revive
	StringCode() string
	Message() string
}

// Event represents a network/system activity event.
type Event struct {
	// Timestamp of the event
	Timestamp time.Time
	// Activity that was performed during the event
	Activity Activity `gorm:"type:integer"`
	// ID of the event (can be empty, meaning that it wasn't yet generated)
	ID uint64 `gorm:"primaryKey;autoIncrement"`
	// InitiatorID is the ID of an object that initiated the event (e.g., a user)
	InitiatorID string
	// InitiatorName is the name of an object that initiated the event.
	InitiatorName string `gorm:"-"`
	// InitiatorEmail is the email address of an object that initiated the event.
	InitiatorEmail string `gorm:"-"`
	// TargetID is the ID of an object that was effected by the event (e.g., a peer)
	TargetID string
	// AccountID is the ID of an account where the event happened
	AccountID string `gorm:"index"`

	// Meta of the event, e.g. deleted peer information like name, IP, etc
	Meta map[string]any `gorm:"serializer:json"`
}

// Copy the event
func (e *Event) Copy() *Event {

	meta := make(map[string]any, len(e.Meta))
	for key, value := range e.Meta {
		meta[key] = value
	}

	return &Event{
		Timestamp:      e.Timestamp,
		Activity:       e.Activity,
		ID:             e.ID,
		InitiatorID:    e.InitiatorID,
		InitiatorName:  e.InitiatorName,
		InitiatorEmail: e.InitiatorEmail,
		TargetID:       e.TargetID,
		AccountID:      e.AccountID,
		Meta:           meta,
	}
}

type DeletedUser struct {
	ID      string `gorm:"primaryKey"`
	Email   string `gorm:"not null"`
	Name    string
	EncAlgo string `gorm:"not null"`
}
