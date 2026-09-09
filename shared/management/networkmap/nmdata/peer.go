package nmdata

import (
	"net"
	"net/netip"
	"slices"
	"time"
)

// Peer capability constants mirror the proto enum values.
const (
	PeerCapabilitySourcePrefixes      int32 = 1
	PeerCapabilityIPv6Overlay         int32 = 2
	PeerCapabilityComponentNetworkMap int32 = 3
)

// Peer is the slim twin of peer.Peer.
type Peer struct {
	ID                     string
	Key                    string
	SSHKey                 string
	DNSLabel               string
	UserID                 string
	SSHEnabled             bool
	LoginExpirationEnabled bool
	LastLogin              *time.Time
	IP                     netip.Addr
	IPv6                   netip.Addr
	RequiresApproval       bool
	Connected              bool
	ExtraDNSLabels         []string
	Meta                   PeerSystemMeta
	ProxyMeta              ProxyMeta
	Location               PeerLocation
}

// ProxyMeta is the slim twin of peer.ProxyMeta.
type ProxyMeta struct {
	Embedded bool
	Cluster  string
}

// ProxyDomain is the slim twin of a registered reverse-proxy domain, carrying
// what private-service zone resolution needs: the apex a service domain can sit
// under, and the cluster it is registered against.
type ProxyDomain struct {
	Domain        string
	TargetCluster string
}

// PeerSystemMeta is the slim twin of peer.PeerSystemMeta.
type PeerSystemMeta struct {
	WtVersion          string
	GoOS               string
	OSVersion          string
	KernelVersion      string
	NetworkAddresses   []NetworkAddress
	Files              []File
	Capabilities       []int32
	Flags              Flags
	SyncMessageVersion int
}

// Flags is the slim twin of peer.Flags.
type Flags struct {
	ServerSSHAllowed bool
	DisableIPv6      bool
}

// NetworkAddress is the slim twin of peer.NetworkAddress.
type NetworkAddress struct {
	NetIP netip.Prefix
}

// File is the slim twin of peer.File.
type File struct {
	Path             string
	ProcessIsRunning bool
}

// PeerLocation is the slim twin of peer.Location.
type PeerLocation struct {
	CountryCode  string
	CityName     string
	ConnectionIP net.IP
}

func (p *Peer) HasCapability(capability int32) bool {
	return slices.Contains(p.Meta.Capabilities, capability)
}

func (p *Peer) SupportsIPv6() bool {
	return !p.Meta.Flags.DisableIPv6 && p.HasCapability(PeerCapabilityIPv6Overlay)
}

func (p *Peer) SupportsSourcePrefixes() bool {
	return p.HasCapability(PeerCapabilitySourcePrefixes)
}

func (p *Peer) AddedWithSSOLogin() bool {
	return p.UserID != ""
}

func (p *Peer) FQDN(dnsDomain string) string {
	if dnsDomain == "" {
		return ""
	}
	return p.DNSLabel + "." + dnsDomain
}

func (p *Peer) GetLastLogin() time.Time {
	if p.LastLogin != nil {
		return *p.LastLogin
	}
	return time.Time{}
}

// SessionExpiresAt mirrors peer.Peer.SessionExpiresAt.
func (p *Peer) SessionExpiresAt(accountExpirationEnabled bool, expiresIn time.Duration) time.Time {
	if !accountExpirationEnabled || !p.AddedWithSSOLogin() || !p.LoginExpirationEnabled {
		return time.Time{}
	}
	last := p.GetLastLogin()
	if last.IsZero() {
		return time.Time{}
	}
	return last.Add(expiresIn).UTC()
}

func (p *Peer) LoginExpired(expiresIn time.Duration) (bool, time.Duration) {
	if !p.AddedWithSSOLogin() || !p.LoginExpirationEnabled {
		return false, 0
	}
	expiresAt := p.GetLastLogin().Add(expiresIn)
	now := time.Now()
	timeLeft := expiresAt.Sub(now)
	return timeLeft <= 0, timeLeft
}
