package manager

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/statemanager"
)

// ErrIPv6NotInitialized is returned when an IPv6 address is passed to a firewall
// method but the IPv6 firewall components were not initialized.
var ErrIPv6NotInitialized = errors.New("IPv6 firewall not initialized")

// ErrNoSources is returned when AddFilterRule is called with an empty
// source list. "Match any source" must be expressed explicitly with a
// /0 prefix; an empty list is a caller error and is rejected rather
// than silently widening the rule to every source.
var ErrNoSources = errors.New("rule has no sources")

const (
	ForwardingFormatPrefix = "netbird-fwd-"
	ForwardingFormat       = "netbird-fwd-%s-%t"
	PreroutingFormat       = "netbird-prerouting-%s-%t"
	NatFormat              = "netbird-nat-%s-%t"
)

// RuleID identifies a firewall rule. It is a typed string so the
// compiler catches accidental mixing with arbitrary string keys. It is
// only an identifier and does not implement Rule.
type RuleID string

// Rule abstraction should be implemented by each firewall manager
//
// Each firewall type for different OS can use different type
// of the properties to hold data of the created rule
type Rule interface {
	// ID returns the rule id
	ID() RuleID
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

// String returns the string representation of the action
func (a Action) String() string {
	switch a {
	case ActionAccept:
		return "accept"
	case ActionDrop:
		return "drop"
	default:
		return "unknown"
	}
}

const (
	// ActionAccept is the action to accept a packet
	ActionAccept Action = iota
	// ActionDrop is the action to drop a packet
	ActionDrop
)

// Network is a rule destination, either a set or a prefix
type Network struct {
	Set    Set
	Prefix netip.Prefix
}

// String returns the string representation of the destination
func (d Network) String() string {
	if d.Prefix.IsValid() {
		return d.Prefix.String()
	}
	if d.IsSet() {
		return d.Set.HashedName()
	}
	return "<invalid network>"
}

// IsSet returns true if the destination is a set
func (d Network) IsSet() bool {
	return d.Set != Set{}
}

// IsPrefix returns true if the destination is a valid prefix
func (d Network) IsPrefix() bool {
	return d.Prefix.IsValid()
}

// IsZero returns true if the network designates no destination, i.e. it
// is the zero value. A zero Network is the peer-rule sentinel; a non-zero
// one carries a prefix or set destination.
func (d Network) IsZero() bool {
	return !d.IsPrefix() && !d.IsSet()
}

// Manager is the high level abstraction of a firewall manager
//
// It declares methods which handle actions required by the
// Netbird client for ACL and routing functionality
type Manager interface {
	Init(stateManager *statemanager.Manager) error

	// AddFilterRule adds a packet-filtering rule to the firewall.
	//
	// If destination is the zero Network, the rule applies to traffic
	// inbound to this node, i.e. peer ACL semantics, installed in
	// the kernel's input chain. If destination is set (prefix or
	// set), the rule applies to forwarded traffic with that
	// destination, route ACL semantics, installed in the forward
	// chain.
	//
	// sources must be a single address family; the caller splits mixed
	// families and calls once per family. "Match any source" must be
	// expressed with an explicit /0 prefix; an empty sources list is
	// rejected with ErrNoSources so a zeroed list can never widen a
	// rule to every source.
	//
	// Note: callers should call Flush() after adding rules.
	AddFilterRule(
		id []byte,
		sources []netip.Prefix,
		destination Network,
		proto Protocol,
		sPort *Port,
		dPort *Port,
		action Action,
	) (Rule, error)

	// DeleteFilterRule removes a filtering rule previously added via
	// AddFilterRule. The rule's own type identifies whether it lives
	// in the peer (input) or route (forward) path.
	DeleteFilterRule(rule Rule) error

	// IsServerRouteSupported returns true if the firewall supports server side routing operations
	IsServerRouteSupported() bool

	IsStateful() bool

	// AddNatRule inserts a routing NAT rule
	AddNatRule(pair RouterPair) error

	// RemoveNatRule removes a routing NAT rule
	RemoveNatRule(pair RouterPair) error

	// SetLegacyManagement sets the legacy management mode
	SetLegacyManagement(legacy bool) error

	// Close closes the firewall manager
	Close(stateManager *statemanager.Manager) error

	// Flush the changes to firewall controller
	Flush() error

	SetLogLevel(log.Level)

	EnableRouting() error

	DisableRouting() error

	// AddDNATRule adds outbound DNAT rule for forwarding external traffic to the NetBird network.
	AddDNATRule(ForwardRule) (Rule, error)

	// DeleteDNATRule deletes the outbound DNAT rule.
	DeleteDNATRule(Rule) error

	// UpdateSet updates the set with the given prefixes
	UpdateSet(hash Set, prefixes []netip.Prefix) error

	// AddInboundDNAT adds an inbound DNAT rule redirecting traffic from NetBird peers to local services
	AddInboundDNAT(localAddr netip.Addr, protocol Protocol, originalPort, translatedPort uint16) error

	// RemoveInboundDNAT removes inbound DNAT rule
	RemoveInboundDNAT(localAddr netip.Addr, protocol Protocol, originalPort, translatedPort uint16) error

	// AddOutputDNAT adds an OUTPUT chain DNAT rule for locally-generated traffic.
	AddOutputDNAT(localAddr netip.Addr, protocol Protocol, originalPort, translatedPort uint16) error

	// RemoveOutputDNAT removes an OUTPUT chain DNAT rule.
	RemoveOutputDNAT(localAddr netip.Addr, protocol Protocol, originalPort, translatedPort uint16) error

	// SetupEBPFProxyNoTrack creates static notrack rules for eBPF proxy loopback traffic.
	// This prevents conntrack from interfering with WireGuard proxy communication.
	SetupEBPFProxyNoTrack(proxyPort, wgPort uint16) error
}

// GenKey builds the rule id for this pair from the given format.
func (p RouterPair) GenKey(format string) RuleID {
	return RuleID(fmt.Sprintf(format, p.ID, p.Inverse))
}

// LegacyManager defines the interface for legacy management operations
type LegacyManager interface {
	RemoveAllLegacyRouteRules() error
	GetLegacyManagement() bool
	SetLegacyManagement(bool)
}

// SetLegacyManagement sets the route manager to use legacy management
func SetLegacyManagement(router LegacyManager, isLegacy bool) error {
	oldLegacy := router.GetLegacyManagement()

	if oldLegacy != isLegacy {
		router.SetLegacyManagement(isLegacy)
		log.Debugf("Set legacy management to %v", isLegacy)
	}

	// client reconnected to a newer mgmt, we need to clean up the legacy rules
	if !isLegacy && oldLegacy {
		if err := router.RemoveAllLegacyRouteRules(); err != nil {
			return fmt.Errorf("remove legacy routing rules: %v", err)
		}

		log.Debugf("Legacy routing rules removed")
	}

	return nil
}

// MergeIPRanges merges overlapping IP ranges and returns a slice of non-overlapping netip.Prefix
func MergeIPRanges(prefixes []netip.Prefix) []netip.Prefix {
	if len(prefixes) == 0 {
		return prefixes
	}

	merged := []netip.Prefix{prefixes[0]}
	for _, prefix := range prefixes[1:] {
		last := merged[len(merged)-1]
		if last.Contains(prefix.Addr()) {
			// If the current prefix is contained within the last merged prefix, skip it
			continue
		}
		if prefix.Contains(last.Addr()) {
			// If the current prefix contains the last merged prefix, replace it
			merged[len(merged)-1] = prefix
		} else {
			// Otherwise, add the current prefix to the merged list
			merged = append(merged, prefix)
		}
	}

	return merged
}

// UnmapPrefix normalizes a v4-mapped v6 prefix (::ffff:a.b.c.d) to its
// plain v4 form, shifting the prefix length out of the 96-bit mapped
// range. Other prefixes are returned unchanged. Keeping prefixes
// unmapped ensures v4 rules match consistently and the match builders
// read the correct address length.
func UnmapPrefix(p netip.Prefix) netip.Prefix {
	addr := p.Addr()
	if !addr.Is4In6() {
		return p
	}
	bits := max(p.Bits()-96, 0)
	return netip.PrefixFrom(addr.Unmap(), bits)
}

// SortPrefixes sorts the given slice of netip.Prefix in place.
// It sorts first by IP address, then by prefix length (most specific to least specific).
func SortPrefixes(prefixes []netip.Prefix) {
	sort.Slice(prefixes, func(i, j int) bool {
		addrCmp := prefixes[i].Addr().Compare(prefixes[j].Addr())
		if addrCmp != 0 {
			return addrCmp < 0
		}

		// If IP addresses are the same, compare prefix lengths (longer prefixes first)
		return prefixes[i].Bits() > prefixes[j].Bits()
	})
}
