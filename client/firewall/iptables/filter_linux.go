//go:build !android

package iptables

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	nbid "github.com/netbirdio/netbird/client/internal/acl/id"
	nbnet "github.com/netbirdio/netbird/client/net"
)

// AddFilterRule installs a packet-filtering rule. With destination
// empty, the rule goes to the peer ACL input chain plus a paired
// mangle PREROUTING rule for the redirect mark. With destination set
// (prefix or named set), it goes to the route ACL forward chain.
// Multi-source rules collapse to one iptables rule via the shared
// hash:net ipset.
func (r *family) AddFilterRule(
	id []byte,
	sources []netip.Prefix,
	destination firewall.Network,
	proto firewall.Protocol,
	sPort *firewall.Port,
	dPort *firewall.Port,
	action firewall.Action,
) (firewall.Rule, error) {
	ruleID := nbid.GenerateRuleID(sources, destination, proto, sPort, dPort, action)
	if existing, ok := r.filters[ruleID]; ok {
		return existing, nil
	}

	srcMatch, err := r.applySourceMatch(sourceNetwork(sources), sources)
	if err != nil {
		return nil, fmt.Errorf("apply source match: %w", err)
	}

	rule, err := r.installFilterRule(ruleID, srcMatch, destination, proto, sPort, dPort, action)
	if err != nil {
		r.dropSourceMatch(srcMatch)
		return nil, err
	}

	r.filters[ruleID] = rule
	r.updateState()
	return rule, nil
}

func (r *family) hasRule(id nbid.RuleID) bool {
	_, ok := r.filters[id]
	return ok
}

// hasDNATRule reports whether this family owns the DNAT rule set for
// the given user id. DNAT rules live in r.rules under the well-known
// "<id>_dnat" key; the lookup here is used by Manager.DeleteDNATRule
// to pick the right family.
func (r *family) hasDNATRule(id firewall.RuleID) bool {
	_, ok := r.rules[id+dnatSuffix]
	return ok
}

// DeleteFilterRule removes a previously installed filter rule. The
// rule's stored chain/table identify where to delete from; source set
// references are recovered from the spec via findSets and dropped
// from the shared ipset counter.
func (r *family) DeleteFilterRule(rule firewall.Rule) error {
	ruleID := rule.ID()
	pr, ok := r.filters[ruleID]
	if !ok {
		log.Debugf("filter rule %s not found", ruleID)
		return nil
	}

	// DeleteIfExists keeps both deletes idempotent so a retry after a
	// partial failure does not error on the half that was already removed.
	var merr *multierror.Error
	if err := r.iptablesClient.DeleteIfExists(tableFilter, pr.chain, pr.specs...); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("delete rule from %s: %w", pr.chain, err))
	}
	if pr.mangleSpecs != nil {
		if err := r.iptablesClient.DeleteIfExists(tableMangle, chainRTPre, pr.mangleSpecs...); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("delete mangle rule: %w", err))
		}
	}
	if merr != nil {
		// Leave the rule tracked so the caller retries the remaining half.
		return nberrors.FormatErrorOrNil(merr)
	}

	// The rule is gone from iptables, so untrack it regardless of how the
	// refcount decrement goes, but surface decrement failures so callers
	// see the ipset desync.
	delete(r.filters, ruleID)
	r.updateState()
	if err := r.decrementSetCounter(pr.specs); err != nil {
		return fmt.Errorf("drop source set references: %w", err)
	}
	return nil
}

// findSets scans an iptables rule spec for "-m set --match-set <name>
// <dir>" fragments and returns the named sets in occurrence order.
// Used at delete time to drop ipsetCounter references.
func findSets(rule []string) []string {
	var sets []string
	for i, arg := range rule {
		if arg == "-m" && i+3 < len(rule) && rule[i+1] == "set" && rule[i+2] == matchSet {
			sets = append(sets, rule[i+3])
		}
	}
	return sets
}

// sourceNetwork classifies a source-prefix list into the firewall.Network
// shape the rest of the spec-builder consumes: empty for match-any, a
// single prefix inline, or an ipset for multiple sources.
func sourceNetwork(sources []netip.Prefix) firewall.Network {
	switch {
	case len(sources) == 0:
		return firewall.Network{}
	case len(sources) == 1 && sources[0].Bits() == 0:
		return firewall.Network{}
	case len(sources) == 1:
		return firewall.Network{Prefix: sources[0]}
	default:
		return firewall.Network{Set: firewall.NewPrefixSet(sources)}
	}
}

// applySourceMatch returns the iptables match fragment for the rule's
// source. For a Set it increments the shared ipset's refcount; for a
// Prefix it emits a direct -s match; for the wildcard it returns nil.
func (r *family) applySourceMatch(network firewall.Network, prefixes []netip.Prefix) ([]string, error) {
	switch {
	case network.IsSet():
		if r.ipsetCounter == nil {
			return nil, fmt.Errorf("multi-source peer rule requires shared ipset counter")
		}
		name := r.ipsetName(network.Set.HashedName())
		if _, err := r.ipsetCounter.Increment(name, prefixes); err != nil {
			return nil, fmt.Errorf("ipset increment %s: %w", name, err)
		}
		return []string{"-m", "set", matchSet, name, "src"}, nil
	case network.IsPrefix():
		return []string{"-s", network.Prefix.String()}, nil
	default:
		return nil, nil
	}
}

// dropSourceMatch undoes whatever applySourceMatch reserved when
// installing a rule fails. Safe to call when the spec is empty or holds
// only inline matchers. Decrement errors are logged but not returned:
// the install error is what the caller needs to see.
func (r *family) dropSourceMatch(srcMatch []string) {
	if r.ipsetCounter == nil {
		return
	}
	for _, name := range findSets(srcMatch) {
		if _, err := r.ipsetCounter.Decrement(name); err != nil {
			log.Errorf("rollback ipset decrement %s: %v", name, err)
		}
	}
}

// decrementSetCounter drops ipset references owned by a raw rule spec
// stored in r.rules (NAT / legacy route entries). It returns an error
// aggregate so the caller surfaces decrement failures.
func (r *family) decrementSetCounter(rule []string) error {
	if r.ipsetCounter == nil {
		return nil
	}
	var merr *multierror.Error
	for _, name := range findSets(rule) {
		if _, err := r.ipsetCounter.Decrement(name); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("decrement counter: %w", err))
		}
	}
	return nberrors.FormatErrorOrNil(merr)
}

// installFilterRule assembles and writes one iptables filter-chain
// rule. With destination empty the rule lands in the peer ACL input
// chain and a paired mangle PREROUTING rule is added for the redirect
// mark. With destination set the rule lands in the route ACL forward
// chain and there is no mangle pairing.
func (r *family) installFilterRule(
	ruleID nbid.RuleID,
	srcMatch []string,
	destination firewall.Network,
	protocol firewall.Protocol,
	sPort, dPort *firewall.Port,
	action firewall.Action,
) (*Rule, error) {
	isRoute := !destination.IsZero()

	proto := protoForFamily(protocol, r.v6)

	specs := slices.Clone(srcMatch)
	var destExp []string
	if isRoute {
		var err error
		destExp, err = r.applyNetwork("-d", destination, nil)
		if err != nil {
			return nil, fmt.Errorf("apply network -d: %w", err)
		}
		specs = append(specs, destExp...)
	}
	specs = append(specs, filterMatchSpecs(proto, sPort, dPort)...)

	var mangleSpecs []string
	if !isRoute {
		mangleSpecs = slices.Clone(specs)
		mangleSpecs = append(mangleSpecs,
			"-i", r.wgIface.Name(),
			"-m", "addrtype", "--dst-type", "LOCAL",
			"-j", "MARK", "--set-xmark", fmt.Sprintf("%#x", nbnet.PreroutingFwmarkRedirected),
		)
	}

	specs = append(specs, "-j", actionToStr(action))

	chain := chainACLInput
	if isRoute {
		chain = chainRTFwdIn
	}

	// Peer ACL drops are inserted at position 1 so they precede the
	// chain's catch-all; route ACL drops are inserted at position 2
	// to sit immediately after the established/related accept rule.
	var err error
	if action == firewall.ActionDrop {
		pos := 1
		if isRoute {
			pos = 2
		}
		err = r.iptablesClient.Insert(tableFilter, chain, pos, specs...)
	} else {
		err = r.iptablesClient.Append(tableFilter, chain, specs...)
	}
	if err != nil {
		r.dropSourceMatch(destExp)
		return nil, fmt.Errorf("install filter rule on %s: %w", chain, err)
	}

	// The mangle redirect-mark rule is best effort: the filter rule itself
	// is what enforces the ACL, so a mangle failure must not undo it. Drop
	// the spec so teardown does not try to remove a rule that was not added.
	if mangleSpecs != nil {
		if err := r.iptablesClient.Append(tableMangle, chainRTPre, mangleSpecs...); err != nil {
			log.Errorf("add mangle rule: %v", err)
			mangleSpecs = nil
		}
	}

	return &Rule{
		id:          ruleID,
		specs:       specs,
		mangleSpecs: mangleSpecs,
		chain:       chain,
		v6:          r.v6,
	}, nil
}

// applyNetwork resolves a firewall.Network into the iptables match
// fragment for the given direction flag (-s or -d). Set networks
// increment the shared ipset refcount; prefixes emit a direct match;
// an empty network returns no spec ("match any").
func (r *family) applyNetwork(flag string, network firewall.Network, prefixes []netip.Prefix) ([]string, error) {
	direction := "src"
	if flag == "-d" {
		direction = "dst"
	}

	if network.IsSet() {
		name := r.ipsetName(network.Set.HashedName())
		if _, err := r.ipsetCounter.Increment(name, prefixes); err != nil {
			return nil, fmt.Errorf("create or get ipset: %w", err)
		}

		return []string{"-m", "set", matchSet, name, direction}, nil
	}
	if network.IsPrefix() {
		return []string{flag, network.Prefix.String()}, nil
	}

	// nolint:nilnil
	return nil, nil
}

// protoForFamily translates ICMP to ICMPv6 for ip6tables.
// ip6tables requires "ipv6-icmp" (or "icmpv6") instead of "icmp".
func protoForFamily(protocol firewall.Protocol, v6 bool) string {
	if v6 && protocol == firewall.ProtocolICMP {
		return "ipv6-icmp"
	}
	return string(protocol)
}

// filterMatchSpecs returns the proto/port match fragment for a
// filtering rule. The source match (-s or -m set) is built by the
// caller and prepended.
func filterMatchSpecs(protocol string, sPort, dPort *firewall.Port) (specs []string) {
	if protocol != "all" {
		specs = append(specs, "-p", protocol)
	}
	specs = append(specs, applyPort("--sport", sPort)...)
	specs = append(specs, applyPort("--dport", dPort)...)
	return specs
}

func actionToStr(action firewall.Action) string {
	if action == firewall.ActionAccept {
		return "ACCEPT"
	}
	return "DROP"
}

func applyPort(flag string, port *firewall.Port) []string {
	if port == nil {
		return nil
	}

	if port.IsRange && len(port.Values) == 2 {
		return []string{flag, fmt.Sprintf("%d:%d", port.Values[0], port.Values[1])}
	}

	if len(port.Values) > 1 {
		portList := make([]string, len(port.Values))
		for i, p := range port.Values {
			portList[i] = strconv.Itoa(int(p))
		}
		return []string{"-m", "multiport", flag, strings.Join(portList, ",")}
	}

	return []string{flag, strconv.Itoa(int(port.Values[0]))}
}
