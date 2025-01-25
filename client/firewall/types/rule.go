package types

import "fmt"

const (
	PreroutingFormat       = "netbird-prerouting-%s-%t"
	NatFormat              = "netbird-nat-%s-%t"
	ForwardingFormat       = "netbird-fwd-%s-%t"
	ForwardingFormatPrefix = "netbird-fwd-"
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

func GenRuleKey(format string, pair RouterPair) string {
	return fmt.Sprintf(format, pair.ID, pair.Inverse)
}
