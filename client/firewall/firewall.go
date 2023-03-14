package firewall

import (
	"net"
)

// Rule to handle management of rules
//
// Eacn type of firewall manager should encapsulate its own rule type
// and implement the Rule interface
type Rule interface {
	// GetRuleID returns the rule id
	GetRuleID() string
}

// Direction is the direction of the traffic
type Direction int

const (
	// DirectionSrc is the direction of the traffic from the source
	DirectionSrc Direction = iota
	// DirectionDst is the direction of the traffic from the destination
	DirectionDst
)

// Action is the action to be taken on a rule
type Action int

const (
	// ActionAccept is the action to accept a packet
	ActionAccept Action = iota
	// ActionDrop is the action to drop a packet
	ActionDrop
)

// Manager is the high level abstraction of a firewall manager
//
// It's declares methods which handles actions required by the
// Netbird client to handle ACL and routing functionality
type Manager interface {
	// AddFiltering adds a filtering rule to the firewall
	AddFiltering(
		ip net.IP,
		port *Port,
		direction Direction,
		action Action,
		comment string,
	) (Rule, error)

	// DeleteRuleByID deletes a rule from the firewall by id.
	DeleteRule(rule Rule) error

	// Reset firewall to the default state.
	Reset() error

	// TODO: migrate routemanager firewal actions to this interface
}
