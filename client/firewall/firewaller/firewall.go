package firewaller

import (
	"net"
	"net/netip"

	"github.com/netbirdio/netbird/client/firewall/types"
	"github.com/netbirdio/netbird/client/internal/statemanager"
)

// Firewall is the high level abstraction of a firewall manager
//
// It declares methods which handle actions required by the
// Netbird client for ACL and routing functionality
type Firewall interface {
	Init(stateManager *statemanager.Manager) error

	// AllowNetbird allows netbird interface traffic
	AllowNetbird() error

	// AddPeerFiltering adds a rule to the firewall
	//
	// If comment argument is empty firewall manager should set
	// rule ID as comment for the rule
	AddPeerFiltering(
		ip net.IP,
		proto types.Protocol,
		sPort *types.Port,
		dPort *types.Port,
		action types.Action,
		ipsetName string,
		comment string,
	) ([]types.Rule, error)

	// DeletePeerRule from the firewall by rule definition
	DeletePeerRule(rule types.Rule) error

	// IsServerRouteSupported returns true if the firewall supports server side routing operations
	IsServerRouteSupported() bool

	AddRouteFiltering(source []netip.Prefix, destination netip.Prefix, proto types.Protocol, sPort *types.Port, dPort *types.Port, action types.Action) (types.Rule, error)

	// DeleteRouteRule deletes a routing rule
	DeleteRouteRule(rule types.Rule) error

	// AddNatRule inserts a routing NAT rule
	AddNatRule(pair types.RouterPair) error

	// RemoveNatRule removes a routing NAT rule
	RemoveNatRule(pair types.RouterPair) error

	// SetLegacyManagement sets the legacy management mode
	SetLegacyManagement(legacy bool) error

	// Reset firewall to the default state
	Reset(stateManager *statemanager.Manager) error

	// Flush the changes to firewall controller
	Flush() error

	// AddDNATRule adds a DNAT rule
	AddDNATRule(types.ForwardRule) (types.Rule, error)

	// DeleteDNATRule deletes a DNAT rule
	// todo: do you need a string ID or the complete rule?
	DeleteDNATRule(types.Rule) error
}
