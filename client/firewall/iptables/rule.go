package iptables

import "github.com/netbirdio/netbird/client/firewall/manager"

// Rule to handle management of rules. Source set membership (when the
// rule was built against a shared hash:net ipset) is encoded in specs;
// DeleteFilterRule recovers it via findSets so the refcounter can drop
// the right reference.
type Rule struct {
	id          manager.RuleID
	specs       []string
	mangleSpecs []string
	// extraRules holds the rules beyond the first when the ipset
	// fallback expands a multi-source rule into one rule per prefix.
	extraRules []filterSpecs
	chain      string
	v6         bool
}

// filterSpecs is one installed iptables rule: its filter-table spec and
// the paired mangle redirect-mark spec (nil for route rules or when the
// mangle rule could not be added).
type filterSpecs struct {
	specs       []string
	mangleSpecs []string
}

// allSpecs returns the spec pairs of every iptables rule backing this
// Rule, the primary one first.
func (r *Rule) allSpecs() []filterSpecs {
	return append([]filterSpecs{{specs: r.specs, mangleSpecs: r.mangleSpecs}}, r.extraRules...)
}

// ID returns the rule id
func (r *Rule) ID() manager.RuleID {
	return r.id
}
