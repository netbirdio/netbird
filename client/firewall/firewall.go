package firewall

import (
	"net"
)

// RuleID to handle management of rules
type RuleID string

// Action is the action to be taken on a rule
type Action int

const (
	// ActionAccept is the action to accept a packet
	ActionAccept Action = iota
	// ActionDrop is the action to drop a packet
	ActionDrop
)

// RuleManager is the interface that wraps the basic rule management methods.
type RuleManager interface {
	// AddRule adds a rule to the firewall.
	AddRule(ip net.IP, port Port, action Action) (RuleID, error)

	// DeleteRuleByID deletes a rule from the firewall by id.
	DeleteRuleByID(id RuleID) error

	// Delete firewall to the default state.
	Reset() error
}
