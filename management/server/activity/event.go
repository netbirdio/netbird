package activity

import "time"

const (
	// PeerAddedByUser indicates that a user added a new peer to the system
	PeerAddedByUser Activity = iota
	// PeerAddedWithSetupKey indicates that a new peer joined the system using a setup key
	PeerAddedWithSetupKey
	// UserJoined indicates that a new user joined the account
	UserJoined
	// UserInvited indicates that a new user was invited to join the account
	UserInvited
	// AccountCreated indicates that a new account has been created
	AccountCreated
	// PeerRemovedByUser indicates that a user removed a peer from the system
	PeerRemovedByUser
	// RuleAdded indicates that a user added a new rule
	RuleAdded
	// RuleUpdated indicates that a user updated a rule
	RuleUpdated
	// RuleRemoved indicates that a user removed a rule
	RuleRemoved
)

const (
	// PeerAddedByUserMessage is a human-readable text message of the PeerAddedByUser activity
	PeerAddedByUserMessage string = "Peer added"
	// PeerAddedWithSetupKeyMessage is a human-readable text message of the PeerAddedWithSetupKey activity
	PeerAddedWithSetupKeyMessage = PeerAddedByUserMessage
	//UserJoinedMessage is a human-readable text message of the UserJoined activity
	UserJoinedMessage string = "User joined"
	//UserInvitedMessage is a human-readable text message of the UserInvited activity
	UserInvitedMessage string = "User invited"
	//AccountCreatedMessage is a human-readable text message of the AccountCreated activity
	AccountCreatedMessage string = "Account created"
	// PeerRemovedByUserMessage is a human-readable text message of the PeerRemovedByUser activity
	PeerRemovedByUserMessage string = "Peer deleted"
	// RuleAddedMessage is a human-readable text message of the RuleAdded activity
	RuleAddedMessage string = "Rule added"
	// RuleRemovedMessage is a human-readable text message of the RuleRemoved activity
	RuleRemovedMessage string = "Rule deleted"
	// RuleUpdatedMessage is a human-readable text message of the RuleRemoved activity
	RuleUpdatedMessage string = "Rule updated"
)

// Activity that triggered an Event
type Activity int

// Message returns a string representation of an activity
func (a Activity) Message() string {
	switch a {
	case PeerAddedByUser:
		return PeerAddedByUserMessage
	case PeerRemovedByUser:
		return PeerRemovedByUserMessage
	case PeerAddedWithSetupKey:
		return PeerAddedWithSetupKeyMessage
	case UserJoined:
		return UserJoinedMessage
	case UserInvited:
		return UserInvitedMessage
	case AccountCreated:
		return AccountCreatedMessage
	case RuleAdded:
		return RuleAddedMessage
	case RuleRemoved:
		return RuleRemovedMessage
	case RuleUpdated:
		return RuleUpdatedMessage
	default:
		return "UNKNOWN_ACTIVITY"
	}
}

// StringCode returns a string code of the activity
func (a Activity) StringCode() string {
	switch a {
	case PeerAddedByUser:
		return "user.peer.add"
	case PeerRemovedByUser:
		return "user.peer.delete"
	case PeerAddedWithSetupKey:
		return "setupkey.peer.add"
	case UserJoined:
		return "user.join"
	case UserInvited:
		return "user.invite"
	case AccountCreated:
		return "account.create"
	case RuleAdded:
		return "rule.add"
	case RuleRemoved:
		return "rule.delete"
	case RuleUpdated:
		return "rule.update"
	default:
		return "UNKNOWN_ACTIVITY"
	}
}

// Store provides an interface to store or stream events.
type Store interface {
	// Save an event in the store
	Save(event *Event) (*Event, error)
	// Get returns "limit" number of events from the "offset" index ordered descending or ascending by a timestamp
	Get(accountID string, offset, limit int, descending bool) ([]*Event, error)
	// Close the sink flushing events if necessary
	Close() error
}

// Event represents a network/system activity event.
type Event struct {
	// Timestamp of the event
	Timestamp time.Time
	// Activity that was performed during the event
	Activity Activity
	// ID of the event (can be empty, meaning that it wasn't yet generated)
	ID uint64
	// InitiatorID is the ID of an object that initiated the event (e.g., a user)
	InitiatorID string
	// TargetID is the ID of an object that was effected by the event (e.g., a peer)
	TargetID string
	// AccountID is the ID of an account where the event happened
	AccountID string
	// Meta of the event, e.g. deleted peer information like name, IP, etc
	Meta map[string]any
}

// Copy the event
func (e *Event) Copy() *Event {

	meta := make(map[string]any, len(e.Meta))
	for key, value := range e.Meta {
		meta[key] = value
	}

	return &Event{
		Timestamp:   e.Timestamp,
		Activity:    e.Activity,
		ID:          e.ID,
		InitiatorID: e.InitiatorID,
		TargetID:    e.TargetID,
		AccountID:   e.AccountID,
		Meta:        meta,
	}
}
