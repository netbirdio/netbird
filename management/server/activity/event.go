package activity

import (
	"sync"
	"time"
)

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
	// SetupKeyCreated indicates that a user created a new setup key
	SetupKeyCreated
	// SetupKeyUpdated indicates that a user updated a setup key
	SetupKeyUpdated
	// SetupKeyRevoked indicates that a user revoked a setup key
	SetupKeyRevoked
	// SetupKeyOverused indicates that setup key usage exhausted
	SetupKeyOverused
	// GroupCreated indicates that a user created a group
	GroupCreated
	// GroupUpdated indicates that a user updated a group
	GroupUpdated
	// PeerGroupsUpdated indicates that a user updated groups of a peer
	PeerGroupsUpdated
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
	// SetupKeyCreatedMessage is a human-readable text message of the SetupKeyCreated activity
	SetupKeyCreatedMessage string = "Setup key created"
	// SetupKeyUpdatedMessage is a human-readable text message of the SetupKeyUpdated activity
	SetupKeyUpdatedMessage string = "Setup key updated"
	// SetupKeyRevokedMessage is a human-readable text message of the SetupKeyRevoked activity
	SetupKeyRevokedMessage string = "Setup key revoked"
	// SetupKeyOverusedMessage is a human-readable text message of the SetupKeyOverused activity
	SetupKeyOverusedMessage string = "Setup key overused"
	// GroupCreatedMessage is a human-readable text message of the GroupCreated activity
	GroupCreatedMessage string = "Group created"
	// GroupUpdatedMessage is a human-readable text message of the GroupUpdated activity
	GroupUpdatedMessage string = "Group updated"
	// PeerGroupsUpdatedMessage is a human-readable text message of the PeerGroupsUpdated activity
	PeerGroupsUpdatedMessage string = "Peer groups updated"
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
	case SetupKeyCreated:
		return SetupKeyCreatedMessage
	case SetupKeyUpdated:
		return SetupKeyUpdatedMessage
	case SetupKeyRevoked:
		return SetupKeyRevokedMessage
	case SetupKeyOverused:
		return SetupKeyOverusedMessage
	case GroupCreated:
		return GroupCreatedMessage
	case GroupUpdated:
		return GroupUpdatedMessage
	case PeerGroupsUpdated:
		return PeerGroupsUpdatedMessage
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
	case SetupKeyCreated:
		return "setupkey.add"
	case SetupKeyRevoked:
		return "setupkey.revoke"
	case SetupKeyOverused:
		return "setupkey.overuse"
	case SetupKeyUpdated:
		return "setupkey.update"
	case GroupCreated:
		return "group.add"
	case GroupUpdated:
		return "group.update"
	case PeerGroupsUpdated:
		return "peer.groups.update"
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

// NoopEventStore implements the Store interface storing data in-memory
type NoopEventStore struct {
	mu     sync.Mutex
	nextID uint64
	events []*Event
}

// Save sets the Event.ID to 1
func (store *NoopEventStore) Save(event *Event) (*Event, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.events == nil {
		store.events = make([]*Event, 0)
	}
	event.ID = store.nextID
	store.nextID++
	store.events = append(store.events, event)
	return event, nil
}

// Get returns a list of ALL events that belong to the given accountID without taking offset, limit and order into consideration
func (store *NoopEventStore) Get(accountID string, offset, limit int, descending bool) ([]*Event, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	events := make([]*Event, 0)
	for _, event := range store.events {
		if event.AccountID == accountID {
			events = append(events, event)
		}
	}
	return events, nil
}

// Close cleans up the event list
func (store *NoopEventStore) Close() error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.events = make([]*Event, 0)
	return nil
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
