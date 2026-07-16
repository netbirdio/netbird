package acl

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/mitchellh/hashstructure/v2"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/internal/acl/id"
	"github.com/netbirdio/netbird/shared/management/domain"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/shared/netiputil"
)

var ErrSourceRangesEmpty = errors.New("sources range is empty")

// ErrNoRuleReturned is returned when the firewall backend reports success
// from AddFilterRule but yields no rule to track.
var ErrNoRuleReturned = errors.New("backend returned no rule")

// Manager is a ACL rules manager
type Manager interface {
	ApplyFiltering(networkMap *mgmProto.NetworkMap, dnsRouteFeatureFlag bool)
}

// DefaultManager uses firewall manager to handle
type DefaultManager struct {
	firewall           firewall.Manager
	peerRulesPairs     map[id.RuleID][]firewall.Rule
	routeRules         map[id.RuleID]firewall.Rule
	previousConfigHash uint64
	hasAppliedConfig   bool
	mutex              sync.Mutex
}

// peerRuleGroup collapses a set of single-source FirewallRules sharing
// the same selector into one multi-source rule to push to the backend.
type peerRuleGroup struct {
	direction mgmProto.RuleDirection
	action    mgmProto.RuleAction
	protocol  mgmProto.RuleProtocol
	port      *mgmProto.PortInfo
	// legacyPort is used only when PortInfo is empty (old management).
	legacyPort string
	policyID   []byte
	sources    []netip.Prefix
}

// peerRuleKey is the comparable selector that decides which single-source
// rules merge into one group. Rules with an equal key collapse into one
// multi-source backend rule. PortInfo is flattened into its scalar fields
// so the key compares by value; policyID keeps policies separate so two
// policies authorizing different peers don't merge under one attribution.
type peerRuleKey struct {
	v6         bool
	policyID   string
	direction  mgmProto.RuleDirection
	action     mgmProto.RuleAction
	protocol   mgmProto.RuleProtocol
	legacyPort string
	port       uint16
	rangeStart uint16
	rangeEnd   uint16
}

func NewDefaultManager(fm firewall.Manager) *DefaultManager {
	return &DefaultManager{
		firewall:       fm,
		peerRulesPairs: make(map[id.RuleID][]firewall.Rule),
		routeRules:     make(map[id.RuleID]firewall.Rule),
	}
}

// ApplyFiltering firewall rules to the local firewall manager processed by ACL policy.
//
// If allowByDefault is true it appends allow ALL traffic rules to input and output chains.
func (d *DefaultManager) ApplyFiltering(networkMap *mgmProto.NetworkMap, dnsRouteFeatureFlag bool) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if d.firewall == nil {
		log.Debug("firewall manager is not supported, skipping firewall rules")
		return
	}

	// Skip the full rebuild + flush when the inputs that drive the firewall
	// state are byte-for-byte identical to the last successfully applied
	// update. Management re-sends the same network map far more often than it
	// actually changes (account-wide updates, peer meta churn), and rebuilding
	// every peer/route ACL and flushing the firewall on every such sync is the
	// dominant client-side cost when nothing changed. Mirrors the same guard the
	// DNS server already uses (previousConfigHash). Only the fields ApplyFiltering
	// consumes participate in the hash, so an unrelated map change cannot mask a
	// real ACL change.
	hash, err := d.firewallConfigHash(networkMap, dnsRouteFeatureFlag)
	if err != nil {
		log.Errorf("unable to hash firewall configuration, applying unconditionally: %v", err)
	} else if d.hasAppliedConfig && d.previousConfigHash == hash {
		log.Debugf("not applying the firewall configuration update as there is nothing new (hash: %d)", hash)
		return
	}

	start := time.Now()
	defer func() {
		total := 0
		for _, pairs := range d.peerRulesPairs {
			total += len(pairs)
		}
		log.Infof(
			"ACL rules processed in: %v, total rules count: %d",
			time.Since(start), total)
	}()

	peerErr := d.applyPeerACLs(networkMap)
	if peerErr != nil {
		log.Errorf("apply peer ACLs: %v", peerErr)
	}

	routeErr := d.applyRouteACLs(networkMap.RoutesFirewallRules, dnsRouteFeatureFlag)
	if routeErr != nil {
		log.Errorf("apply route ACLs: %v", routeErr)
	}

	flushErr := d.firewall.Flush()
	if flushErr != nil {
		log.Error("failed to flush firewall rules: ", flushErr)
	}

	// Only remember the hash once the firewall actually reflects this config.
	// If applying or flushing failed, leave the previous hash untouched so the
	// next (possibly identical) update is not skipped and gets a chance to
	// reconcile the firewall state.
	if err == nil && peerErr == nil && routeErr == nil && flushErr == nil {
		d.previousConfigHash = hash
		d.hasAppliedConfig = true
	} else {
		d.hasAppliedConfig = false
	}
}

// firewallConfigHash hashes exactly the inputs ApplyFiltering uses to build the
// firewall state, so an identical hash means an identical resulting ruleset.
func (d *DefaultManager) firewallConfigHash(networkMap *mgmProto.NetworkMap, dnsRouteFeatureFlag bool) (uint64, error) {
	return hashstructure.Hash(struct {
		PeerRules           []*mgmProto.FirewallRule
		PeerRulesIsEmpty    bool
		RouteRules          []*mgmProto.RouteFirewallRule
		RouteRulesIsEmpty   bool
		DNSRouteFeatureFlag bool
	}{
		PeerRules:           networkMap.GetFirewallRules(),
		PeerRulesIsEmpty:    networkMap.GetFirewallRulesIsEmpty(),
		RouteRules:          networkMap.GetRoutesFirewallRules(),
		RouteRulesIsEmpty:   networkMap.GetRoutesFirewallRulesIsEmpty(),
		DNSRouteFeatureFlag: dnsRouteFeatureFlag,
	}, hashstructure.FormatV2, &hashstructure.HashOptions{
		ZeroNil:         true,
		IgnoreZeroValue: true,
		SlicesAsSets:    true,
		UseStringer:     true,
	})
}

func (d *DefaultManager) applyPeerACLs(networkMap *mgmProto.NetworkMap) error {
	rules := networkMap.FirewallRules

	// if we got empty rules list but management not set networkMap.FirewallRulesIsEmpty flag
	// we have old version of management without rules handling, we should allow all traffic
	if len(networkMap.FirewallRules) == 0 && !networkMap.FirewallRulesIsEmpty {
		log.Warn("this peer is connected to a NetBird Management service with an older version. Allowing all traffic from connected peers")
		rules = append(rules,
			&mgmProto.FirewallRule{
				PeerIP:    "0.0.0.0",
				Direction: mgmProto.RuleDirection_IN,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_ALL,
			},
			&mgmProto.FirewallRule{
				PeerIP:    "0.0.0.0",
				Direction: mgmProto.RuleDirection_OUT,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_ALL,
			},
		)
	}

	// Group incoming single-source rules from management by their
	// (direction, action, proto, port) selector and merge sources.
	// One call to the firewall backend per merged rule.
	// A deny we cannot decode would leave its traffic unblocked, so skip
	// the whole pass and keep existing rules until the next sync.
	groups, denyErr, err := groupPeerRules(rules)
	if denyErr != nil {
		return fmt.Errorf("decode deny rule sources: %w", denyErr)
	}

	newRulePairs := make(map[id.RuleID][]firewall.Rule)
	var merr *multierror.Error
	if err != nil {
		merr = multierror.Append(merr, err)
	}

	// Apply denies first. A deny that fails to install is a security
	// failure (fail-open), so if any deny errors we roll back the
	// denies we already installed in this pass and bail out without
	// installing any accept. Pre-existing rules stay untouched until
	// the next successful pass clears them.
	denies, accepts := splitDenyAccept(groups)
	if err := d.installPeerGroups(denies, newRulePairs, true); err != nil {
		return fmt.Errorf("install deny rules: %w", err)
	}

	if err := d.installPeerGroups(accepts, newRulePairs, false); err != nil {
		merr = multierror.Append(merr, err)
	}

	// Tear down rules that disappeared from the networkmap. Any rule
	// the backend refuses to delete stays in our tracking so it gets
	// retried on the next ApplyFiltering. Otherwise a transient
	// delete failure would leak the rule in the firewall until the
	// process exits.
	for pairID, rules := range d.peerRulesPairs {
		if _, ok := newRulePairs[pairID]; ok {
			continue
		}
		var remaining []firewall.Rule
		for _, rule := range rules {
			if err := d.firewall.DeleteFilterRule(rule); err != nil {
				merr = multierror.Append(merr, fmt.Errorf("delete peer rule, will retry: %w", err))
				remaining = append(remaining, rule)
			}
		}
		if len(remaining) > 0 {
			newRulePairs[pairID] = remaining
		}
	}
	d.peerRulesPairs = newRulePairs

	return nberrors.FormatErrorOrNil(merr)
}

// installPeerGroups applies each group and records the resulting rule
// pairs in newRulePairs. With atomic set (deny rules), a single failure
// rolls back every rule installed in this call and returns, leaving the
// firewall exactly as before: denies are fail-closed and must be applied
// all-or-nothing. With atomic unset (accept rules), failures are
// accumulated and the remaining groups still install, so one malformed
// allow cannot drop every other legitimate allow in the pass.
func (d *DefaultManager) installPeerGroups(groups []*peerRuleGroup, newRulePairs map[id.RuleID][]firewall.Rule, atomic bool) error {
	var freshlyInstalled []id.RuleID
	var merr *multierror.Error
	for _, g := range groups {
		pairID, rulePair, err := d.applyPeerGroup(g)
		if err != nil {
			if atomic {
				d.rollbackInstalled(freshlyInstalled)
				return fmt.Errorf("apply firewall rule: %w", err)
			}
			merr = multierror.Append(merr, fmt.Errorf("apply firewall rule: %w", err))
			continue
		}
		if len(rulePair) == 0 {
			continue
		}
		if _, existed := d.peerRulesPairs[pairID]; !existed {
			freshlyInstalled = append(freshlyInstalled, pairID)
		}
		d.peerRulesPairs[pairID] = rulePair
		newRulePairs[pairID] = rulePair
	}
	return nberrors.FormatErrorOrNil(merr)
}

func (d *DefaultManager) rollbackInstalled(pairIDs []id.RuleID) {
	var merr *multierror.Error
	for _, pairID := range pairIDs {
		// Keep any rule the backend refuses to delete tracked so it is
		// retried on the next ApplyFiltering instead of leaking in the
		// firewall with no tracking left to remove it.
		var remaining []firewall.Rule
		for _, rule := range d.peerRulesPairs[pairID] {
			if err := d.firewall.DeleteFilterRule(rule); err != nil {
				merr = multierror.Append(merr, fmt.Errorf("rule %s: %w", pairID, err))
				remaining = append(remaining, rule)
			}
		}
		if len(remaining) > 0 {
			d.peerRulesPairs[pairID] = remaining
		} else {
			delete(d.peerRulesPairs, pairID)
		}
	}
	if err := nberrors.FormatErrorOrNil(merr); err != nil {
		log.Errorf("rollback peer rules: %v", err)
	}
}

func (d *DefaultManager) applyPeerGroup(g *peerRuleGroup) (id.RuleID, []firewall.Rule, error) {
	protocol, err := ConvertToFirewallProtocol(g.protocol)
	if err != nil {
		return "", nil, fmt.Errorf("skipping firewall rule: %w", err)
	}
	action, err := convertFirewallAction(g.action)
	if err != nil {
		return "", nil, fmt.Errorf("skipping firewall rule: %w", err)
	}
	port, err := resolveGroupPort(g)
	if err != nil {
		return "", nil, err
	}

	var fwRule firewall.Rule
	switch g.direction {
	case mgmProto.RuleDirection_IN:
		fwRule, err = d.firewall.AddFilterRule(g.policyID, g.sources, firewall.Network{}, protocol, nil, port, action)
	case mgmProto.RuleDirection_OUT:
		if d.firewall.IsStateful() {
			return "", nil, nil
		}
		if shouldSkipInvertedRule(protocol, port) {
			return "", nil, nil
		}
		fwRule, err = d.firewall.AddFilterRule(g.policyID, g.sources, firewall.Network{}, protocol, port, nil, action)
	default:
		return "", nil, errors.New("invalid direction")
	}

	if err != nil {
		return "", nil, fmt.Errorf("add firewall rule: %w", err)
	}
	if fwRule == nil {
		return "", nil, fmt.Errorf("add firewall rule: %w", ErrNoRuleReturned)
	}

	// Derive the pair id from the backend rule, like the route path:
	// the backend dedups identical content, so two policies authorizing
	// the same flow resolve to the same id and a single backing rule.
	return fwRule.ID(), []firewall.Rule{fwRule}, nil
}

func (d *DefaultManager) applyRouteACLs(rules []*mgmProto.RouteFirewallRule, dynamicResolver bool) error {
	newRouteRules := make(map[id.RuleID]firewall.Rule, len(rules))
	var merr *multierror.Error

	// Apply new rules - firewall manager will return the existing rule if already present
	for _, rule := range rules {
		addedRule, err := d.applyRouteACL(rule, dynamicResolver)
		if err != nil {
			if errors.Is(err, ErrSourceRangesEmpty) {
				log.Debugf("skipping empty sources rule with destination %s: %v", rule.Destination, err)
			} else {
				merr = multierror.Append(merr, fmt.Errorf("add route rule: %w", err))
			}
			continue
		}
		newRouteRules[addedRule.ID()] = addedRule
	}

	// Tear down old route rules; retain ones the backend refused so a
	// transient failure doesn't leave orphaned rules in the firewall.
	for ruleID, rule := range d.routeRules {
		if _, exists := newRouteRules[ruleID]; exists {
			continue
		}
		if err := d.firewall.DeleteFilterRule(rule); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("delete route rule, will retry: %w", err))
			newRouteRules[ruleID] = rule
		}
	}

	d.routeRules = newRouteRules
	return nberrors.FormatErrorOrNil(merr)
}

func (d *DefaultManager) applyRouteACL(rule *mgmProto.RouteFirewallRule, dynamicResolver bool) (firewall.Rule, error) {
	if len(rule.SourceRanges) == 0 {
		return nil, ErrSourceRangesEmpty
	}

	var sources []netip.Prefix
	for _, sourceRange := range rule.SourceRanges {
		source, err := netip.ParsePrefix(sourceRange)
		if err != nil {
			return nil, fmt.Errorf("parse source range: %w", err)
		}
		sources = append(sources, firewall.UnmapPrefix(source))
	}

	destination, err := determineDestination(rule, dynamicResolver, sources)
	if err != nil {
		return nil, fmt.Errorf("determine destination: %w", err)
	}

	protocol, err := ConvertToFirewallProtocol(rule.Protocol)
	if err != nil {
		return nil, fmt.Errorf("invalid protocol: %w", err)
	}

	action, err := convertFirewallAction(rule.Action)
	if err != nil {
		return nil, fmt.Errorf("invalid action: %w", err)
	}

	dPorts := convertPortInfo(rule.PortInfo)

	addedRule, err := d.firewall.AddFilterRule(rule.PolicyID, sources, destination, protocol, nil, dPorts, action)
	if err != nil {
		return nil, fmt.Errorf("add route rule: %w", err)
	}
	if addedRule == nil {
		return nil, fmt.Errorf("add route rule: %w", ErrNoRuleReturned)
	}

	return addedRule, nil
}

// splitDenyAccept partitions groups by action so denies can be
// applied before accepts. Order within each bucket is preserved.
func splitDenyAccept(groups []*peerRuleGroup) (denies, accepts []*peerRuleGroup) {
	for _, g := range groups {
		if g.action == mgmProto.RuleAction_DROP {
			denies = append(denies, g)
		} else {
			accepts = append(accepts, g)
		}
	}
	return denies, accepts
}

// groupPeerRules merges single-source rules sharing a selector into
// multi-source groups. It splits source-decode failures by action:
// denyErr is non-nil when a deny rule could not be decoded, which is a
// fail-open risk the caller must treat as fatal for the pass; err
// carries the tolerable accept-rule failures the caller can log and
// continue past.
func groupPeerRules(rules []*mgmProto.FirewallRule) (groups []*peerRuleGroup, denyErr error, err error) {
	var denyMerr, acceptMerr *multierror.Error
	byKey := make(map[peerRuleKey]*peerRuleGroup)
	order := make([]peerRuleKey, 0)

	for _, r := range rules {
		srcs, decErr := extractRuleSources(r)
		if decErr != nil {
			if r.Action == mgmProto.RuleAction_DROP {
				denyMerr = multierror.Append(denyMerr, decErr)
			} else {
				acceptMerr = multierror.Append(acceptMerr, decErr)
			}
			continue
		}
		// A single FirewallRule normally carries one address family, but
		// split by family defensively: each backend keys a rule to one
		// family and would mismatch sources of the other, so a group's
		// sources must never span families.
		v4, v6 := splitPrefixesByFamily(srcs)
		for _, sub := range []struct {
			isV6    bool
			sources []netip.Prefix
		}{{false, v4}, {true, v6}} {
			if len(sub.sources) == 0 {
				continue
			}
			key := ruleGroupKey(r, sub.isV6)
			g, ok := byKey[key]
			if !ok {
				g = &peerRuleGroup{
					direction:  r.Direction,
					action:     r.Action,
					protocol:   r.Protocol,
					port:       r.PortInfo,
					legacyPort: r.Port,
					policyID:   r.PolicyID,
				}
				byKey[key] = g
				order = append(order, key)
			}
			g.sources = append(g.sources, sub.sources...)
		}
	}

	out := make([]*peerRuleGroup, 0, len(order))
	for _, k := range order {
		out = append(out, byKey[k])
	}
	return out, nberrors.FormatErrorOrNil(denyMerr), nberrors.FormatErrorOrNil(acceptMerr)
}

func prefixIsV6(p netip.Prefix) bool {
	return p.Addr().Is6() && !p.Addr().Is4In6()
}

// splitPrefixesByFamily partitions prefixes into IPv4 and IPv6 groups.
func splitPrefixesByFamily(prefixes []netip.Prefix) (v4, v6 []netip.Prefix) {
	for _, p := range prefixes {
		if prefixIsV6(p) {
			v6 = append(v6, p)
		} else {
			v4 = append(v4, p)
		}
	}
	return v4, v6
}

// ruleGroupKey builds the selector key for a rule. v6 must reflect the
// rule's source family: mgmt emits one rule per family and mixing them
// would break ICMP-variant selection in uspfilter.
func ruleGroupKey(r *mgmProto.FirewallRule, v6 bool) peerRuleKey {
	k := peerRuleKey{
		v6:         v6,
		policyID:   string(r.PolicyID),
		direction:  r.Direction,
		action:     r.Action,
		protocol:   r.Protocol,
		legacyPort: r.Port,
	}
	if pi := r.PortInfo; pi != nil {
		k.port = uint16(pi.GetPort())
		if rng := pi.GetRange(); rng != nil {
			k.rangeStart = uint16(rng.GetStart())
			k.rangeEnd = uint16(rng.GetEnd())
		}
	}
	return k
}

// extractRuleSources returns all source prefixes the rule applies to.
// New management populates sourcePrefixes; older management sets PeerIP.
func extractRuleSources(r *mgmProto.FirewallRule) ([]netip.Prefix, error) {
	if len(r.SourcePrefixes) > 0 {
		out := make([]netip.Prefix, 0, len(r.SourcePrefixes))
		for _, raw := range r.SourcePrefixes {
			addr, err := netiputil.DecodeAddr(raw)
			if err != nil {
				return nil, fmt.Errorf("decode source prefix: %w", err)
			}
			out = append(out, netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen()))
		}
		return out, nil
	}

	peerIP := r.PeerIP //nolint:staticcheck // PeerIP is the legacy source field for old management servers
	addr, err := netip.ParseAddr(peerIP)
	if err != nil {
		return nil, fmt.Errorf("parse peer IP %q: %w", peerIP, err)
	}
	addr = addr.Unmap()
	// An unspecified PeerIP means "any peer" (legacy management
	// allow-all fallback); only a /0 prefix matches any source in the
	// backends, a full-length prefix would match nothing.
	if addr.IsUnspecified() {
		return []netip.Prefix{netip.PrefixFrom(addr, 0)}, nil
	}
	return []netip.Prefix{netip.PrefixFrom(addr, addr.BitLen())}, nil
}

func resolveGroupPort(g *peerRuleGroup) (*firewall.Port, error) {
	if !portInfoEmpty(g.port) {
		return convertPortInfo(g.port), nil
	}
	if g.legacyPort != "" {
		value, err := strconv.ParseUint(g.legacyPort, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid port: %w", err)
		}
		return &firewall.Port{
			Values: []uint16{uint16(value)},
		}, nil
	}
	// nolint:nilnil // a nil port legitimately means "no port restriction"
	return nil, nil
}

func portInfoEmpty(portInfo *mgmProto.PortInfo) bool {
	if portInfo == nil {
		return true
	}

	switch portInfo.GetPortSelection().(type) {
	case *mgmProto.PortInfo_Port:
		return portInfo.GetPort() == 0
	case *mgmProto.PortInfo_Range_:
		r := portInfo.GetRange()
		return r == nil || r.Start == 0 || r.End == 0
	default:
		return true
	}
}

// ConvertToFirewallProtocol maps a management rule protocol to the
// firewall protocol type.
func ConvertToFirewallProtocol(protocol mgmProto.RuleProtocol) (firewall.Protocol, error) {
	switch protocol {
	case mgmProto.RuleProtocol_TCP:
		return firewall.ProtocolTCP, nil
	case mgmProto.RuleProtocol_UDP:
		return firewall.ProtocolUDP, nil
	case mgmProto.RuleProtocol_ICMP:
		return firewall.ProtocolICMP, nil
	case mgmProto.RuleProtocol_ALL:
		return firewall.ProtocolALL, nil
	default:
		return firewall.ProtocolALL, fmt.Errorf("invalid protocol type: %s", protocol.String())
	}
}

func shouldSkipInvertedRule(protocol firewall.Protocol, port *firewall.Port) bool {
	return protocol == firewall.ProtocolALL || protocol == firewall.ProtocolICMP || port == nil
}

func convertFirewallAction(action mgmProto.RuleAction) (firewall.Action, error) {
	switch action {
	case mgmProto.RuleAction_ACCEPT:
		return firewall.ActionAccept, nil
	case mgmProto.RuleAction_DROP:
		return firewall.ActionDrop, nil
	default:
		return firewall.ActionDrop, fmt.Errorf("invalid action type: %d", action)
	}
}

func convertPortInfo(portInfo *mgmProto.PortInfo) *firewall.Port {
	if portInfo == nil {
		return nil
	}

	if portInfo.GetPort() != 0 {
		return &firewall.Port{
			Values: []uint16{uint16(int(portInfo.GetPort()))},
		}
	}

	if portInfo.GetRange() != nil {
		return &firewall.Port{
			IsRange: true,
			Values:  []uint16{uint16(portInfo.GetRange().Start), uint16(portInfo.GetRange().End)},
		}
	}

	return nil
}

func determineDestination(rule *mgmProto.RouteFirewallRule, dynamicResolver bool, sources []netip.Prefix) (firewall.Network, error) {
	var destination firewall.Network

	if rule.IsDynamic {
		if dynamicResolver {
			if len(rule.Domains) > 0 {
				destination.Set = firewall.NewDomainSet(domain.FromPunycodeList(rule.Domains))
			} else {
				// isDynamic is set but no domains = outdated management server
				log.Warn("connected to an older version of management server (no domains in rules), using default destination")
				destination.Prefix = getDefault(sources[0])
			}
		} else {
			// client resolves DNS, we (router) don't know the destination
			destination.Prefix = getDefault(sources[0])
		}
		return destination, nil
	}

	prefix, err := netip.ParsePrefix(rule.Destination)
	if err != nil {
		return destination, fmt.Errorf("parse destination: %w", err)
	}
	destination.Prefix = prefix
	return destination, nil
}

func getDefault(prefix netip.Prefix) netip.Prefix {
	if prefix.Addr().Is6() {
		return netip.PrefixFrom(netip.IPv6Unspecified(), 0)
	}
	return netip.PrefixFrom(netip.IPv4Unspecified(), 0)
}
