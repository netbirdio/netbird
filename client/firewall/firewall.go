package firewall

import (
	"net"
)

// Rule abstraction should be implemented by each firewall manager
//
// Each firewall type for different OS can use different type
// of the properties to hold data of the created rule
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
// It declares methods which handle actions required by the
// Netbird client for ACL and routing functionality
type Manager interface {
	// AddFiltering rule to the firewall
	//
	// If comment argument is empty firewall manager should set
	// rule ID as comment for the rule
	AddFiltering(
		ip net.IP,
		proto Protocol,
		port *Port,
		direction Direction,
		action Action,
		comment string,
	) (Rule, error)

	// DeleteRule from the firewall by rule definition
	DeleteRule(rule Rule) error

	// Reset firewall to the default state
	Reset() error

	// TODO: migrate routemanager firewal actions to this interface
}
