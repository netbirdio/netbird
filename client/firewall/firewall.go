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

// RuleDirection is the traffic direction which a rule is applied
type RuleDirection int

const (
	// RuleDirectionIN applies to filters that handlers incoming traffic
	RuleDirectionIN RuleDirection = iota
	// RuleDirectionOUT applies to filters that handlers outgoing traffic
	RuleDirectionOUT
)

// Action is the action to be taken on a rule
type Action int

const (
	// ActionUnknown is a unknown action
	ActionUnknown Action = iota
	// ActionAccept is the action to accept a packet
	ActionAccept
	// ActionDrop is the action to drop a packet
	ActionDrop
)

// Manager is the high level abstraction of a firewall manager
//
// It declares methods which handle actions required by the
// Netbird client for ACL and routing functionality
type Manager interface {
	// AllowNetbird allows netbird interface traffic
	AllowNetbird() error

	// AddFiltering rule to the firewall
	//
	// If comment argument is empty firewall manager should set
	// rule ID as comment for the rule
	AddFiltering(ruleRequest RuleRequest) ([]Rule, error)

	// DeleteRule from the firewall by rule definition
	DeleteRule(rule Rule) error

	// Reset firewall to the default state
	Reset() error

	// Flush the changes to firewall controller
	Flush() error

	// TODO: migrate routemanager firewal actions to this interface
}

// RuleRequest is the request to create a rule
type RuleRequest struct {
	// IP is the IP address of the rule
	IP net.IP
	// Proto is the protocol of the rule
	Proto Protocol
	// SrcPort is the source port of the rule
	SrcPort *Port
	// DstPort is the destination port of the rule
	DstPort *Port
	// Direction is the direction of the rule
	Direction RuleDirection
	// Action is the action of the rule
	Action Action
	// IPSetName is the name of the IPSet
	IPSetName string
	// Comment is the comment of the rule
	Comment string
}
