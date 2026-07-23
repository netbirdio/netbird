package types

import (
	"net/netip"
	"time"
)

// ComponentPeer is the self-contained peer representation used by
// NetworkMapComponents and the calculated NetworkMap. It carries exactly the
// subset of peer data that crosses the components wire format, so the shared
// calculation layer stays independent of the management server's domain
// types.
type ComponentPeer struct {
	ID                     string
	Key                    string
	IP                     netip.Addr
	IPv6                   netip.Addr
	DNSLabel               string
	SSHKey                 string
	SSHEnabled             bool
	ServerSSHAllowed       bool
	AgentVersion           string
	SupportsSourcePrefixes bool
	SupportsIPv6           bool
	LoginExpirationEnabled bool
	AddedWithSSOLogin      bool
	LastLogin              time.Time
}

// FQDN returns the peer's FQDN combined of the peer's DNS label and the system's DNS domain.
func (p *ComponentPeer) FQDN(dnsDomain string) string {
	if dnsDomain == "" {
		return ""
	}
	return p.DNSLabel + "." + dnsDomain
}

// LoginExpired indicates whether the peer's login has expired, mirroring the
// server-side peer semantics: only SSO-added peers with login expiration
// enabled can expire.
func (p *ComponentPeer) LoginExpired(expiresIn time.Duration) (bool, time.Duration) {
	if !p.AddedWithSSOLogin || !p.LoginExpirationEnabled {
		return false, 0
	}
	timeLeft := time.Until(p.LastLogin.Add(expiresIn))
	return timeLeft <= 0, timeLeft
}

// GroupAllName is the reserved name of the default group that contains every peer in an account.
const GroupAllName = "All"

// ComponentGroup is the self-contained group representation used by
// NetworkMapComponents: just the membership view the network-map calculation
// needs, without the server's storage fields.
type ComponentGroup struct {
	ID       string
	PublicID string
	Name     string
	Peers    []string
}

// IsGroupAll checks if the group is a default "All" group.
func (g *ComponentGroup) IsGroupAll() bool {
	return g.Name == GroupAllName
}

// ComponentRouter is the self-contained network-router representation used by
// NetworkMapComponents.
type ComponentRouter struct {
	NetworkID  string
	PublicID   string
	Peer       string
	PeerGroups []string
	Masquerade bool
	Metric     int
	Enabled    bool
}

// ComponentResourceType mirrors the network-resource type enum on the
// components wire format.
type ComponentResourceType string

const (
	ComponentResourceHost   ComponentResourceType = "host"
	ComponentResourceSubnet ComponentResourceType = "subnet"
	ComponentResourceDomain ComponentResourceType = "domain"
)

// ComponentResource is the self-contained network-resource representation
// used by NetworkMapComponents.
type ComponentResource struct {
	ID          string
	PublicID    string
	NetworkID   string
	AccountID   string
	Name        string
	Description string
	Type        ComponentResourceType
	Address     string
	Domain      string
	Prefix      netip.Prefix
	Enabled     bool
}
