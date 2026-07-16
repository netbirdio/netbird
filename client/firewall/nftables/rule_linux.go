package nftables

import (
	"net/netip"

	"github.com/google/nftables"

	"github.com/netbirdio/netbird/client/firewall/manager"
)

// Rule wraps an installed filter rule (peer or route). Source set
// membership is encoded in the rule's expressions; DeleteFilterRule
// recovers the set name via findSets so the refcounter can drop the
// right reference. mangleRule is set only for peer rules.
type Rule struct {
	nftRule    *nftables.Rule
	mangleRule *nftables.Rule
	// sources is the canonical source list this rule was created for.
	sources []netip.Prefix
	id      manager.RuleID
}

// ID returns the rule id
func (r *Rule) ID() manager.RuleID {
	return r.id
}
