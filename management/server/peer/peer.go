package peer

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/util"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

// Peer capability constants mirror the proto enum values.
const (
	PeerCapabilitySourcePrefixes int32 = 1
	PeerCapabilityIPv6Overlay    int32 = 2
)

// Peer represents a machine connected to the network.
// The Peer is a WireGuard peer identified by a public key
type Peer struct {
	// ID is an internal ID of the peer
	ID string `gorm:"primaryKey"`
	// AccountID is a reference to Account that this object belongs
	AccountID string `json:"-" gorm:"index"`
	// WireGuard public key
	Key string `gorm:"size:255;uniqueIndex"`
	// IP address of the Peer
	IP netip.Addr `gorm:"serializer:json"` // uniqueness index per accountID (check migrations)
	// IPv6 overlay address of the Peer, zero value if IPv6 is not enabled for the account.
	IPv6 netip.Addr `gorm:"serializer:json"`
	// Meta is a Peer system meta data
	Meta PeerSystemMeta `gorm:"embedded;embeddedPrefix:meta_"`
	// ProxyMeta is metadata related to proxy peers
	ProxyMeta ProxyMeta `gorm:"embedded;embeddedPrefix:proxy_meta_"`
	// Name is peer's name (machine name)
	Name string `gorm:"index"`
	// DNSLabel is the parsed peer name for domain resolution. It is used to form an FQDN by appending the account's
	// domain to the peer label. e.g. peer-dns-label.netbird.cloud
	DNSLabel string // uniqueness index per accountID (check migrations)
	// Status peer's management connection status
	Status *PeerStatus `gorm:"embedded;embeddedPrefix:peer_status_"`
	// The user ID that registered the peer
	UserID string
	// SSHKey is a public SSH key of the peer
	SSHKey string
	// SSHEnabled indicates whether SSH server is enabled on the peer
	SSHEnabled bool
	// LoginExpirationEnabled indicates whether peer's login expiration is enabled and once expired the peer has to re-login.
	// Works with LastLogin
	LoginExpirationEnabled bool

	InactivityExpirationEnabled bool
	// LastLogin the time when peer performed last login operation
	LastLogin *time.Time
	// CreatedAt records the time the peer was created
	CreatedAt time.Time
	// Indicate ephemeral peer attribute
	Ephemeral bool `gorm:"index"`

	// Geo location based on connection IP
	Location Location `gorm:"embedded;embeddedPrefix:location_"`

	// ExtraDNSLabels is a list of additional DNS labels that can be used to resolve the peer
	ExtraDNSLabels []string `gorm:"serializer:json"`
	// AllowExtraDNSLabels indicates whether the peer allows extra DNS labels to be used for resolving the peer
	AllowExtraDNSLabels bool
}

type ProxyMeta struct {
	Embedded bool   `gorm:"index"`
	Cluster  string `gorm:"index"`
}

type PeerStatus struct { //nolint:revive
	// LastSeen is the last time the peer status was updated (i.e. the last
	// time we observed the peer being alive on a sync stream). Written by
	// the database (CURRENT_TIMESTAMP) — callers do not supply it.
	LastSeen time.Time
	// SessionStartedAt records when the currently-active sync stream began,
	// stored as Unix nanoseconds. It acts as the optimistic-locking token
	// for status updates: a stream is only allowed to mutate the peer's
	// status when its own token strictly exceeds the stored token (when connecting)
	// or matches it exactly (for disconnects). Zero means "no
	// active session". Integer nanoseconds are used so equality is
	// precision-safe across drivers, and so the predicates compose to a
	// single bigint comparison.
	SessionStartedAt int64 `gorm:"not null;default:0"`
	// Connected indicates whether peer is connected to the management service or not
	Connected bool
	// LoginExpired
	LoginExpired bool
	// RequiresApproval indicates whether peer requires approval or not
	RequiresApproval bool
}

// Location is a geo location information of a Peer based on public connection IP
type Location struct {
	ConnectionIP net.IP `gorm:"serializer:json"` // from grpc peer or reverse proxy headers depends on setup
	CountryCode  string
	CityName     string
	GeoNameID    uint // city level geoname id
}

// equal reports whether two locations match. ConnectionIP is a net.IP slice, so it uses
// IP.Equal, not ==.
func (l Location) equal(other Location) bool {
	return l.CountryCode == other.CountryCode &&
		l.CityName == other.CityName &&
		l.GeoNameID == other.GeoNameID &&
		l.ConnectionIP.Equal(other.ConnectionIP)
}

// NetworkAddress is the IP address with network and MAC address of a network interface
type NetworkAddress struct {
	NetIP netip.Prefix `gorm:"serializer:json"`
	Mac   string
}

// Environment is a system environment information
type Environment struct {
	Cloud    string
	Platform string
}

// File is a file on the system.
type File struct {
	Path             string
	Exist            bool
	ProcessIsRunning bool
}

// Flags defines a set of options to control feature behavior
type Flags struct {
	RosenpassEnabled    bool
	RosenpassPermissive bool
	ServerSSHAllowed    bool

	DisableClientRoutes bool
	DisableServerRoutes bool
	DisableDNS          bool
	DisableFirewall     bool
	BlockLANAccess      bool
	BlockInbound        bool
	DisableIPv6         bool

	LazyConnectionEnabled bool
}

// PeerSystemMeta is a metadata of a Peer machine system
type PeerSystemMeta struct { //nolint:revive
	Hostname           string
	GoOS               string
	Kernel             string
	Core               string
	Platform           string
	OS                 string
	OSVersion          string
	WtVersion          string
	UIVersion          string
	KernelVersion      string
	NetworkAddresses   []NetworkAddress `gorm:"serializer:json"`
	SystemSerialNumber string
	SystemProductName  string
	SystemManufacturer string
	Environment        Environment `gorm:"serializer:json"`
	Flags              Flags       `gorm:"serializer:json"`
	Files              []File      `gorm:"serializer:json"`
	Capabilities       []int32     `gorm:"serializer:json"`
}

func (p PeerSystemMeta) isEqual(other PeerSystemMeta) bool {
	return len(metaDiff(p, other)) == 0
}

func (p PeerSystemMeta) isEmpty() bool {
	return p.Hostname == "" &&
		p.GoOS == "" &&
		p.Kernel == "" &&
		p.Core == "" &&
		p.Platform == "" &&
		p.OS == "" &&
		p.OSVersion == "" &&
		p.WtVersion == "" &&
		p.UIVersion == "" &&
		p.KernelVersion == "" &&
		len(p.NetworkAddresses) == 0 &&
		p.SystemSerialNumber == "" &&
		p.SystemProductName == "" &&
		p.SystemManufacturer == "" &&
		p.Environment.Cloud == "" &&
		p.Environment.Platform == "" &&
		len(p.Files) == 0
}

// AddedWithSSOLogin indicates whether this peer has been added with an SSO login by a user.
func (p *Peer) AddedWithSSOLogin() bool {
	return p.UserID != ""
}

// HasCapability reports whether the peer has the given capability.
func (p *Peer) HasCapability(capability int32) bool {
	return slices.Contains(p.Meta.Capabilities, capability)
}

// SupportsIPv6 reports whether the peer supports IPv6 overlay.
func (p *Peer) SupportsIPv6() bool {
	return !p.Meta.Flags.DisableIPv6 && p.HasCapability(PeerCapabilityIPv6Overlay)
}

// SupportsSourcePrefixes reports whether the peer reads SourcePrefixes.
func (p *Peer) SupportsSourcePrefixes() bool {
	return p.HasCapability(PeerCapabilitySourcePrefixes)
}

func capabilitiesEqual(a, b []int32) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[int32]struct{}, len(a))
	for _, c := range a {
		set[c] = struct{}{}
	}
	for _, c := range b {
		if _, ok := set[c]; !ok {
			return false
		}
	}
	return true
}

// Copy copies Peer object
func (p *Peer) Copy() *Peer {
	peerStatus := p.Status
	if peerStatus != nil {
		peerStatus = p.Status.Copy()
	}
	return &Peer{
		ID:                          p.ID,
		AccountID:                   p.AccountID,
		Key:                         p.Key,
		IP:                          p.IP,
		IPv6:                        p.IPv6,
		Meta:                        p.Meta,
		Name:                        p.Name,
		DNSLabel:                    p.DNSLabel,
		Status:                      peerStatus,
		UserID:                      p.UserID,
		SSHKey:                      p.SSHKey,
		SSHEnabled:                  p.SSHEnabled,
		LoginExpirationEnabled:      p.LoginExpirationEnabled,
		LastLogin:                   p.LastLogin,
		CreatedAt:                   p.CreatedAt,
		Ephemeral:                   p.Ephemeral,
		ProxyMeta:                   p.ProxyMeta,
		Location:                    p.Location,
		InactivityExpirationEnabled: p.InactivityExpirationEnabled,
		ExtraDNSLabels:              slices.Clone(p.ExtraDNSLabels),
		AllowExtraDNSLabels:         p.AllowExtraDNSLabels,
	}
}

// UpdateMetaIfNew updates peer's system metadata and connection geo location if
// new information is provided. newLocation is the geo location resolved from the
// peer's current connection IP, or nil when there is nothing to apply (geo
// disabled, no real IP, or the IP is unchanged); the caller owns the expensive
// lookup and the same-IP guard. It returns a MetaDiff describing what changed;
// diff.Updated() reports whether the peer needs to be persisted.
func (p *Peer) UpdateMetaIfNew(ctx context.Context, meta PeerSystemMeta, newLocation *Location) MetaDiff {
	if meta.isEmpty() {
		return MetaDiff{}
	}

	// Avoid overwriting UIVersion if the update was triggered sole by the CLI client
	if meta.UIVersion == "" {
		meta.UIVersion = p.Meta.UIVersion
	}

	effectiveLocation := p.Location
	if newLocation != nil {
		effectiveLocation = *newLocation
	}

	diff := diffMeta(p.Meta, meta, p.Location, effectiveLocation)
	if diff.Updated() {
		p.Meta = meta
	}
	p.Location = effectiveLocation

	if diff.Updated() {
		log.WithContext(ctx).Debug(diff.LogSummary())
	}

	return diff
}

// MetaDiff holds a peer's full before/after state across a sync: both metas and both
// connection locations (the location lives on Peer, not PeerSystemMeta, but posture
// checks read it). Changed lists what moved, for logging and the persistence decision;
// the snapshots let a posture check be replayed against old and new. Everything is derived
// from these fields, so there are no parallel per-field flags to keep in sync.
type MetaDiff struct {
	OldMeta     PeerSystemMeta
	NewMeta     PeerSystemMeta
	OldLocation Location
	NewLocation Location

	Changed []string
}

// Updated reports whether anything changed and the peer must be persisted. diffMeta fills
// Changed in the pass that builds the diff, so this is a length check, not a re-comparison.
// Pointer receiver: MetaDiff embeds two metas, so copying it per call is wasteful.
func (d *MetaDiff) Updated() bool {
	return len(d.Changed) != 0
}

// VersionChanged reports whether the WireGuard client version changed (a client upgrade).
func (d *MetaDiff) VersionChanged() bool {
	return d.OldMeta.WtVersion != d.NewMeta.WtVersion
}

// HostnameChanged reports whether the peer's hostname changed.
func (d *MetaDiff) HostnameChanged() bool {
	return d.OldMeta.Hostname != d.NewMeta.Hostname
}

// LogSummary renders the changed fields as a single human-readable line.
func (d *MetaDiff) LogSummary() string {
	return fmt.Sprintf("peer meta updated, %d field(s) changed: %s",
		len(d.Changed), strings.Join(d.Changed, ", "))
}

func metaDiff(oldMeta, newMeta PeerSystemMeta) []string {
	return diffMeta(oldMeta, newMeta, Location{}, Location{}).Changed
}

// diffMeta snapshots a peer's old and new state and records a Changed entry per field that
// moved. It is the single source of truth for the comparison: isEqual is an empty Changed
// list, so the log line and the persistence decision can never disagree.
func diffMeta(oldMeta, newMeta PeerSystemMeta, oldLocation, newLocation Location) MetaDiff {
	d := MetaDiff{OldMeta: oldMeta, NewMeta: newMeta, OldLocation: oldLocation, NewLocation: newLocation}
	add := func(field string, oldVal, newVal any) {
		d.Changed = append(d.Changed, fmt.Sprintf("%s: %v -> %v", field, oldVal, newVal))
	}

	if oldMeta.Hostname != newMeta.Hostname {
		add("hostname", oldMeta.Hostname, newMeta.Hostname)
	}
	if oldMeta.GoOS != newMeta.GoOS {
		add("goos", oldMeta.GoOS, newMeta.GoOS)
	}
	if oldMeta.Kernel != newMeta.Kernel {
		add("kernel", oldMeta.Kernel, newMeta.Kernel)
	}
	if oldMeta.KernelVersion != newMeta.KernelVersion {
		add("kernel_version", oldMeta.KernelVersion, newMeta.KernelVersion)
	}
	if oldMeta.Core != newMeta.Core {
		add("core", oldMeta.Core, newMeta.Core)
	}
	if oldMeta.Platform != newMeta.Platform {
		add("platform", oldMeta.Platform, newMeta.Platform)
	}
	if oldMeta.OS != newMeta.OS {
		add("os", oldMeta.OS, newMeta.OS)
	}
	if oldMeta.OSVersion != newMeta.OSVersion {
		add("os_version", oldMeta.OSVersion, newMeta.OSVersion)
	}
	if oldMeta.WtVersion != newMeta.WtVersion {
		add("wt_version", oldMeta.WtVersion, newMeta.WtVersion)
	}
	if oldMeta.UIVersion != newMeta.UIVersion {
		add("ui_version", oldMeta.UIVersion, newMeta.UIVersion)
	}
	if oldMeta.SystemSerialNumber != newMeta.SystemSerialNumber {
		add("system_serial_number", oldMeta.SystemSerialNumber, newMeta.SystemSerialNumber)
	}
	if oldMeta.SystemProductName != newMeta.SystemProductName {
		add("system_product_name", oldMeta.SystemProductName, newMeta.SystemProductName)
	}
	if oldMeta.SystemManufacturer != newMeta.SystemManufacturer {
		add("system_manufacturer", oldMeta.SystemManufacturer, newMeta.SystemManufacturer)
	}
	if oldMeta.Environment.Cloud != newMeta.Environment.Cloud {
		add("environment_cloud", oldMeta.Environment.Cloud, newMeta.Environment.Cloud)
	}
	if oldMeta.Environment.Platform != newMeta.Environment.Platform {
		add("environment_platform", oldMeta.Environment.Platform, newMeta.Environment.Platform)
	}
	if !oldMeta.Flags.isEqual(newMeta.Flags) {
		add("flags", fmt.Sprintf("%+v", oldMeta.Flags), fmt.Sprintf("%+v", newMeta.Flags))
	}
	if !capabilitiesEqual(oldMeta.Capabilities, newMeta.Capabilities) {
		add("capabilities", oldMeta.Capabilities, newMeta.Capabilities)
	}
	if !sameMultiset(oldMeta.NetworkAddresses, newMeta.NetworkAddresses) {
		add("network_addresses", fmt.Sprintf("%v", oldMeta.NetworkAddresses), fmt.Sprintf("%v", newMeta.NetworkAddresses))
	}
	if !sameMultiset(oldMeta.Files, newMeta.Files) {
		add("files", fmt.Sprintf("%v", oldMeta.Files), fmt.Sprintf("%v", newMeta.Files))
	}

	if !oldLocation.equal(newLocation) {
		add("connection_ip", oldLocation.ConnectionIP, newLocation.ConnectionIP)
	}

	return d
}

// sameMultiset reports whether two slices contain the same elements with the
// same multiplicity, ignoring order. The element type is the comparison key, so
// every field participates in equality.
func sameMultiset[T comparable](a, b []T) bool {
	if len(a) != len(b) {
		return false
	}
	counts := make(map[T]int, len(a))
	for _, v := range a {
		counts[v]++
	}
	for _, v := range b {
		counts[v]--
		if counts[v] == 0 {
			delete(counts, v)
		}
	}
	return len(counts) == 0
}

// GetLastLogin returns the last login time of the peer.
func (p *Peer) GetLastLogin() time.Time {
	if p.LastLogin != nil {
		return *p.LastLogin
	}
	return time.Time{}

}

// MarkLoginExpired marks peer's status expired or not
func (p *Peer) MarkLoginExpired(expired bool) {
	newStatus := p.Status.Copy()
	newStatus.LoginExpired = expired
	if expired {
		newStatus.Connected = false
	}
	p.Status = newStatus
}

// SessionExpired indicates whether the peer's session has expired or not.
// If Peer.LastLogin plus the expiresIn duration has happened already; then session has expired.
// Return true if a session has expired, false otherwise, and time left to expiration (negative when expired).
// Session expiration can be disabled/enabled on a Peer level via Peer.LoginExpirationEnabled property.
// Session expiration can also be disabled/enabled globally on the Account level via Settings.PeerLoginExpirationEnabled.
// Only peers added by interactive SSO login can be expired.
func (p *Peer) SessionExpired(expiresIn time.Duration) (bool, time.Duration) {
	if !p.AddedWithSSOLogin() || !p.InactivityExpirationEnabled || p.Status.Connected {
		return false, 0
	}
	expiresAt := p.Status.LastSeen.Add(expiresIn)
	now := time.Now()
	timeLeft := expiresAt.Sub(now)
	return timeLeft <= 0, timeLeft
}

// LoginExpired indicates whether the peer's login has expired or not.
// If Peer.LastLogin plus the expiresIn duration has happened already; then login has expired.
// Return true if a login has expired, false otherwise, and time left to expiration (negative when expired).
// Login expiration can be disabled/enabled on a Peer level via Peer.LoginExpirationEnabled property.
// Login expiration can also be disabled/enabled globally on the Account level via Settings.PeerLoginExpirationEnabled.
// Only peers added by interactive SSO login can be expired.
func (p *Peer) LoginExpired(expiresIn time.Duration) (bool, time.Duration) {
	if !p.AddedWithSSOLogin() || !p.LoginExpirationEnabled {
		return false, 0
	}
	expiresAt := p.GetLastLogin().Add(expiresIn)
	now := time.Now()
	timeLeft := expiresAt.Sub(now)
	return timeLeft <= 0, timeLeft
}

// SessionExpiresAt returns the absolute UTC instant at which the peer's SSO
// session expires, derived from LastLogin and the account-level
// PeerLoginExpiration setting. Returns the zero value when login expiration
// does not apply (peer not SSO-registered, peer-level toggle off, or account
// expiry disabled). Callers should treat the zero value as "no deadline".
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

// FQDN returns peers FQDN combined of the peer's DNS label and the system's DNS domain
func (p *Peer) FQDN(dnsDomain string) string {
	if dnsDomain == "" {
		return ""
	}
	return p.DNSLabel + "." + dnsDomain
}

// EventMeta returns activity event meta related to the peer
func (p *Peer) EventMeta(dnsDomain string) map[string]any {
	meta := map[string]any{"name": p.Name, "fqdn": p.FQDN(dnsDomain), "ip": p.IP, "created_at": p.CreatedAt,
		"location_city_name": p.Location.CityName, "location_country_code": p.Location.CountryCode,
		"location_geo_name_id": p.Location.GeoNameID, "location_connection_ip": p.Location.ConnectionIP}
	if p.IPv6.IsValid() {
		meta["ipv6"] = p.IPv6.String()
	}
	return meta
}

// Copy PeerStatus. SessionStartedAt must be propagated so clone-based
// callers (Peer.Copy, MarkLoginExpired, UpdateLastLogin) don't silently
// reset the fencing token to zero — that would let any subsequent
// SavePeerStatus write reopen the optimistic-lock window.
func (p *PeerStatus) Copy() *PeerStatus {
	return &PeerStatus{
		LastSeen:         p.LastSeen,
		SessionStartedAt: p.SessionStartedAt,
		Connected:        p.Connected,
		LoginExpired:     p.LoginExpired,
		RequiresApproval: p.RequiresApproval,
	}
}

// UpdateLastLogin and set login expired false
func (p *Peer) UpdateLastLogin() *Peer {
	p.LastLogin = util.ToPtr(time.Now().UTC())
	newStatus := p.Status.Copy()
	newStatus.LoginExpired = false
	p.Status = newStatus
	return p
}

func (p *Peer) FromAPITemporaryAccessRequest(a *api.PeerTemporaryAccessRequest) {
	p.Ephemeral = true
	p.Name = a.Name
	p.Key = a.WgPubKey
	p.Meta = PeerSystemMeta{
		Hostname:      a.Name,
		GoOS:          "js",
		OS:            "js",
		KernelVersion: "wasm",
	}
}

func (f Flags) isEqual(other Flags) bool {
	return f.RosenpassEnabled == other.RosenpassEnabled &&
		f.RosenpassPermissive == other.RosenpassPermissive &&
		f.ServerSSHAllowed == other.ServerSSHAllowed &&
		f.DisableClientRoutes == other.DisableClientRoutes &&
		f.DisableServerRoutes == other.DisableServerRoutes &&
		f.DisableDNS == other.DisableDNS &&
		f.DisableFirewall == other.DisableFirewall &&
		f.BlockLANAccess == other.BlockLANAccess &&
		f.BlockInbound == other.BlockInbound &&
		f.LazyConnectionEnabled == other.LazyConnectionEnabled &&
		f.DisableIPv6 == other.DisableIPv6
}
