package manager

import (
	"fmt"
	"net"
	"net/netip"
	"sort"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/statemanager"
)

const (
	ForwardingFormatPrefix = "netbird-fwd-"
	ForwardingFormat       = "netbird-fwd-%s-%t"
	PreroutingFormat       = "netbird-prerouting-%s-%t"
	NatFormat              = "netbird-nat-%s-%t"
)

// Rule abstraction should be implemented by each firewall manager
//
// Each firewall type for different OS can use different type
// of the properties to hold data of the created rule
type Rule interface {
	// ID returns the rule id
	ID() string
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

// Manager is the high level abstraction of a firewall manager
//
// It declares methods which handle actions required by the
// Netbird client for ACL and routing functionality
type Manager interface {
	Init(stateManager *statemanager.Manager) error

	// AllowNetbird allows netbird interface traffic
	AllowNetbird() error

	// AddPeerFiltering adds a rule to the firewall
	//
	// If comment argument is empty firewall manager should set
	// rule ID as comment for the rule
	//
	// Note: Callers should call Flush() after adding rules to ensure
	// they are applied to the kernel and rule handles are refreshed.
	AddPeerFiltering(
		id []byte,
		ip net.IP,
		proto Protocol,
		sPort *Port,
		dPort *Port,
		action Action,
		ipsetName string,
	) ([]Rule, error)

	// DeletePeerRule from the firewall by rule definition
	DeletePeerRule(rule Rule) error

	// IsServerRouteSupported returns true if the firewall supports server side routing operations
	IsServerRouteSupported() bool

	IsStateful() bool

	AddRouteFiltering(
		id []byte,
		sources []netip.Prefix,
		destination Network,
		proto Protocol,
		sPort, dPort *Port,
		action Action,
	) (Rule, error)

	// DeleteRouteRule deletes a routing rule
	DeleteRouteRule(rule Rule) error

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
	AddInboundDNAT(localAddr netip.Addr, protocol Protocol, sourcePort, targetPort uint16) error

	// RemoveInboundDNAT removes inbound DNAT rule
	RemoveInboundDNAT(localAddr netip.Addr, protocol Protocol, sourcePort, targetPort uint16) error

	// SetupEBPFProxyNoTrack creates static notrack rules for eBPF proxy loopback traffic.
	// This prevents conntrack from interfering with WireGuard proxy communication.
	SetupEBPFProxyNoTrack(proxyPort, wgPort uint16) error
}

func GenKey(format string, pair RouterPair) string {
	return fmt.Sprintf(format, pair.ID, pair.Inverse)
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
