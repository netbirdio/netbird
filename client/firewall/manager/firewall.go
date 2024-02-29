package manager

import (
	"fmt"
	"net"
)

const (
	NatFormat          = "netbird-nat-%s"
	ForwardingFormat   = "netbird-fwd-%s"
	InNatFormat        = "netbird-nat-in-%s"
	InForwardingFormat = "netbird-fwd-in-%s"
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
	// AllowNetbird allows netbird interface traffic
	AllowNetbird() error

	// AddFiltering rule to the firewall
	//
	// If comment argument is empty firewall manager should set
	// rule ID as comment for the rule
	AddFiltering(
		ip net.IP,
		proto Protocol,
		sPort *Port,
		dPort *Port,
		direction RuleDirection,
		action Action,
		ipsetName string,
		comment string,
	) ([]Rule, error)

	// DeleteRule from the firewall by rule definition
	DeleteRule(rule Rule) error

	// IsServerRouteSupported returns true if the firewall supports server side routing operations
	IsServerRouteSupported() bool

	// InsertRoutingRules inserts a routing firewall rule
	InsertRoutingRules(pair RouterPair) error

	// RemoveRoutingRules removes a routing firewall rule
	RemoveRoutingRules(pair RouterPair) error

	// ResetV6Firewall makes changes to the firewall to adapt to the IP address changes.
	// It is expected that after calling this method ApplyFiltering will be called to re-add the firewall rules.
	ResetV6Firewall() error

	// V6Active returns whether IPv6 rules should/may be created by upper layers.
	V6Active() bool

	// Reset firewall to the default state
	Reset() error

	// Flush the changes to firewall controller
	Flush() error
}

func GenKey(format string, input string) string {
	return fmt.Sprintf(format, input)
}
