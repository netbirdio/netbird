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

	rule, err := r.installFilterRules(ruleID, sources, destination, proto, sPort, dPort, action, r.ipsetSupported)
	if err != nil {
		return nil, err
	}

	r.filters[ruleID] = rule
	r.updateState()
	return rule, nil
}

// installFilterRules resolves the source matches and installs one
// iptables rule per match. It is more than one rule only when useIPSet
// is false and a multi-source rule has to be expanded per prefix.
func (r *family) installFilterRules(
	ruleID nbid.RuleID,
	sources []netip.Prefix,
	destination firewall.Network,
	proto firewall.Protocol,
	sPort *firewall.Port,
	dPort *firewall.Port,
	action firewall.Action,
	useIPSet bool,
) (*Rule, error) {
	srcMatches, err := r.applySourceMatches(sources, useIPSet)
	if err != nil {
		return nil, fmt.Errorf("apply source match: %w", err)
	}

	rule, err := r.installFilterRule(ruleID, srcMatches, destination, proto, sPort, dPort, action)
	if err != nil {
		for _, srcMatch := range srcMatches {
			r.dropSourceMatch(srcMatch)
		}
		return nil, err
	}
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

	// DeleteIfExists keeps the deletes idempotent so a retry after a
	// partial failure does not error on the parts already removed.
	var merr *multierror.Error
	for _, fs := range pr.allSpecs() {
		if err := r.iptablesClient.DeleteIfExists(tableFilter, pr.chain, fs.specs...); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("delete rule from %s: %w", pr.chain, err))
		}
		if fs.mangleSpecs != nil {
			if err := r.iptablesClient.DeleteIfExists(tableMangle, chainRTPre, fs.mangleSpecs...); err != nil {
				merr = multierror.Append(merr, fmt.Errorf("delete mangle rule: %w", err))
			}
		}
	}
	if merr != nil {
		// Leave the rule tracked so the caller retries the remaining part.
		return nberrors.FormatErrorOrNil(merr)
	}

	// The rule is gone from iptables, so untrack it regardless of how the
	// refcount decrement goes, but surface decrement failures so callers
	// see the ipset desync. Only the primary spec can reference sets: the
	// per-prefix expansion never uses them.
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

// applySourceMatches returns one source match fragment per iptables
// rule needed for the sources: normally a single fragment (a set match,
// a direct -s match, or nil for match-any), and one -s fragment per
// prefix when a multi-source rule cannot use ipset. Per-prefix rules
// are the only form a kernel without the ipset modules can express.
func (r *family) applySourceMatches(sources []netip.Prefix, useIPSet bool) ([][]string, error) {
	network := sourceNetwork(sources)
	if !network.IsSet() || useIPSet {
		match, err := r.applySourceMatch(network, sources)
		if err != nil {
			return nil, err
		}
		return [][]string{match}, nil
	}

	matches := make([][]string, 0, len(sources))
	for _, source := range sources {
		matches = append(matches, []string{"-s", source.String()})
	}
	return matches, nil
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

// installFilterRule assembles and writes the iptables filter-chain
// rules for one filter rule, one per source match fragment. With
// destination empty the rules land in the peer ACL input chain and each
// gets a paired mangle PREROUTING rule for the redirect mark. With
// destination set the rules land in the route ACL forward chain and
// there is no mangle pairing.
func (r *family) installFilterRule(
	ruleID nbid.RuleID,
	srcMatches [][]string,
	destination firewall.Network,
	protocol firewall.Protocol,
	sPort, dPort *firewall.Port,
	action firewall.Action,
) (*Rule, error) {
	isRoute := !destination.IsZero()

	proto := protoForFamily(protocol, r.v6)

	var destExp []string
	if isRoute {
		var err error
		destExp, err = r.applyNetwork("-d", destination, nil)
		if err != nil {
			return nil, fmt.Errorf("apply network -d: %w", err)
		}
	}
	matchSpecs := filterMatchSpecs(proto, sPort, dPort)

	chain := chainACLInput
	if isRoute {
		chain = chainRTFwdIn
	}

	var installed []filterSpecs
	for _, srcMatch := range srcMatches {
		specs := slices.Clone(srcMatch)
		specs = append(specs, destExp...)
		specs = append(specs, matchSpecs...)

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

		if err := r.insertFilterRule(chain, action, specs); err != nil {
			// Leave nothing half-installed: the caller sees an error, so a
			// partial rule would silently keep matching without being tracked.
			r.removeFilterSpecs(chain, installed)
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

		installed = append(installed, filterSpecs{specs: specs, mangleSpecs: mangleSpecs})
	}

	return &Rule{
		id:          ruleID,
		specs:       installed[0].specs,
		mangleSpecs: installed[0].mangleSpecs,
		extraRules:  installed[1:],
		chain:       chain,
		v6:          r.v6,
	}, nil
}

// insertFilterRule writes one assembled rule spec into the given ACL
// chain. Peer ACL drops are inserted at position 1 so they precede the
// chain's catch-all; route ACL drops are inserted at position 2 to sit
// immediately after the established/related accept rule.
func (r *family) insertFilterRule(chain string, action firewall.Action, specs []string) error {
	if action == firewall.ActionDrop {
		pos := 1
		if chain == chainRTFwdIn {
			pos = 2
		}
		return r.iptablesClient.Insert(tableFilter, chain, pos, specs...)
	}
	return r.iptablesClient.Append(tableFilter, chain, specs...)
}

// removeFilterSpecs deletes the already-installed rules of a partially
// applied filter rule.
func (r *family) removeFilterSpecs(chain string, installed []filterSpecs) {
	for _, fs := range installed {
		if err := r.iptablesClient.DeleteIfExists(tableFilter, chain, fs.specs...); err != nil {
			log.Debugf("delete partial filter rule: %v", err)
		}
		if fs.mangleSpecs != nil {
			if err := r.iptablesClient.DeleteIfExists(tableMangle, chainRTPre, fs.mangleSpecs...); err != nil {
				log.Debugf("delete partial mangle rule: %v", err)
			}
		}
	}
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
		// A destination set is populated later from DNS results, so unlike a
		// source set it cannot be expanded into per-prefix rules. Without
		// ipset such a rule is not expressible; report it instead of
		// installing something broader than the policy allows.
		if flag == "-d" && !r.ipsetSupported {
			return nil, fmt.Errorf("destination set %s requires ipset (ip_set_hash_net and xt_set)", network.Set.HashedName())
		}

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
