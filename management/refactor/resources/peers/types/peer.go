package types

import (
	"fmt"
	"net"
	"time"
)

type Peer interface {
	GetID() string
	SetID(string)
	GetAccountID() string
	SetAccountID(string)
	GetKey() string
	SetKey(string)
	GetSetupKey() string
	SetSetupKey(string)
	GetIP() net.IP
	SetIP(net.IP)
	GetName() string
	SetName(string)
	GetDNSLabel() string
	SetDNSLabel(string)
	GetUserID() string
	SetUserID(string)
	GetSSHKey() string
	SetSSHKey(string)
	GetSSHEnabled() bool
	SetSSHEnabled(bool)
	AddedWithSSOLogin() bool
	UpdateMetaIfNew(meta PeerSystemMeta) bool
	MarkLoginExpired(expired bool)
	FQDN(dnsDomain string) string
	EventMeta(dnsDomain string) map[string]any
	LoginExpired(expiresIn time.Duration) (bool, time.Duration)
	Copy() Peer
}

// Peer represents a machine connected to the network.
// The Peer is a WireGuard peer identified by a public key
type DefaultPeer struct {
	// ID is an internal ID of the peer
	ID string `gorm:"primaryKey"`
	// AccountID is a reference to Account that this object belongs
	AccountID string `json:"-" gorm:"index;uniqueIndex:idx_peers_account_id_ip"`
	// WireGuard public key
	Key string `gorm:"index"`
	// A setup key this peer was registered with
	SetupKey string
	// IP address of the Peer
	IP net.IP `gorm:"uniqueIndex:idx_peers_account_id_ip"`
	// Meta is a Peer system meta data
	Meta PeerSystemMeta `gorm:"embedded;embeddedPrefix:meta_"`
	// Name is peer's name (machine name)
	Name string
	// DNSLabel is the parsed peer name for domain resolution. It is used to form an FQDN by appending the account's
	// domain to the peer label. e.g. peer-dns-label.netbird.cloud
	DNSLabel string
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
	// LastLogin the time when peer performed last login operation
	LastLogin time.Time
	// CreatedAt records the time the peer was created
	CreatedAt time.Time
	// Indicate ephemeral peer attribute
	Ephemeral bool
	// Geo location based on connection IP
	Location Location `gorm:"embedded;embeddedPrefix:location_"`
}

// Location is a geo location information of a Peer based on public connection IP
type Location struct {
	ConnectionIP net.IP // from grpc peer or reverse proxy headers depends on setup
	CountryCode  string
	CityName     string
	GeoNameID    uint // city level geoname id
}

// PeerLogin used as a data object between the gRPC API and AccountManager on Login request.
type PeerLogin struct {
	// WireGuardPubKey is a peers WireGuard public key
	WireGuardPubKey string
	// SSHKey is a peer's ssh key. Can be empty (e.g., old version do not provide it, or this feature is disabled)
	SSHKey string
	// Meta is the system information passed by peer, must be always present.
	Meta PeerSystemMeta
	// UserID indicates that JWT was used to log in, and it was valid. Can be empty when SetupKey is used or auth is not required.
	UserID string
	// AccountID indicates that JWT was used to log in, and it was valid. Can be empty when SetupKey is used or auth is not required.
	AccountID string
	// SetupKey references to a server.SetupKey to log in. Can be empty when UserID is used or auth is not required.
	SetupKey string
}

// AddedWithSSOLogin indicates whether this peer has been added with an SSO login by a user.
func (p *DefaultPeer) AddedWithSSOLogin() bool {
	return p.UserID != ""
}

// UpdateMetaIfNew updates peer's system metadata if new information is provided
// returns true if meta was updated, false otherwise
func (p *DefaultPeer) UpdateMetaIfNew(meta PeerSystemMeta) bool {
	// Avoid overwriting UIVersion if the update was triggered sole by the CLI client
	if meta.UIVersion == "" {
		meta.UIVersion = p.Meta.UIVersion
	}

	if p.Meta.isEqual(meta) {
		return false
	}
	p.Meta = meta
	return true
}

// MarkLoginExpired marks peer's status expired or not
func (p *DefaultPeer) MarkLoginExpired(expired bool) {
	newStatus := p.Status.Copy()
	newStatus.LoginExpired = expired
	if expired {
		newStatus.Connected = false
	}
	p.Status = newStatus
}

// LoginExpired indicates whether the peer's login has expired or not.
// If Peer.LastLogin plus the expiresIn duration has happened already; then login has expired.
// Return true if a login has expired, false otherwise, and time left to expiration (negative when expired).
// Login expiration can be disabled/enabled on a Peer level via Peer.LoginExpirationEnabled property.
// Login expiration can also be disabled/enabled globally on the Account level via Settings.PeerLoginExpirationEnabled.
// Only peers added by interactive SSO login can be expired.
func (p *DefaultPeer) LoginExpired(expiresIn time.Duration) (bool, time.Duration) {
	if !p.AddedWithSSOLogin() || !p.LoginExpirationEnabled {
		return false, 0
	}
	expiresAt := p.LastLogin.Add(expiresIn)
	now := time.Now()
	timeLeft := expiresAt.Sub(now)
	return timeLeft <= 0, timeLeft
}

// FQDN returns peers FQDN combined of the peer's DNS label and the system's DNS domain
func (p *DefaultPeer) FQDN(dnsDomain string) string {
	if dnsDomain == "" {
		return ""
	}
	return fmt.Sprintf("%s.%s", p.DNSLabel, dnsDomain)
}

// EventMeta returns activity event meta related to the peer
func (p *DefaultPeer) EventMeta(dnsDomain string) map[string]any {
	return map[string]any{"name": p.Name, "fqdn": p.FQDN(dnsDomain), "ip": p.IP, "created_at": p.CreatedAt}
}

func (p *DefaultPeer) GetID() string {
	// TODO implement me
	panic("implement me")
}

func (p *DefaultPeer) SetID(s string) {
	// TODO implement me
	panic("implement me")
}

func (p *DefaultPeer) GetAccountID() string {
	// TODO implement me
	panic("implement me")
}

func (p *DefaultPeer) SetAccountID(s string) {
	// TODO implement me
	panic("implement me")
}

func (p *DefaultPeer) GetKey() string {
	// TODO implement me
	panic("implement me")
}

func (p *DefaultPeer) SetKey(s string) {
	// TODO implement me
	panic("implement me")
}

func (p *DefaultPeer) GetSetupKey() string {
	// TODO implement me
	panic("implement me")
}

func (p *DefaultPeer) SetSetupKey(s string) {
	// TODO implement me
	panic("implement me")
}

func (p *DefaultPeer) GetIP() net.IP {
	// TODO implement me
	panic("implement me")
}

func (p *DefaultPeer) SetIP(ip net.IP) {
	// TODO implement me
	panic("implement me")
}

func (p *DefaultPeer) GetName() string {
	// TODO implement me
	panic("implement me")
}

func (p *DefaultPeer) SetName(s string) {
	// TODO implement me
	panic("implement me")
}

func (p *DefaultPeer) GetDNSLabel() string {
	// TODO implement me
	panic("implement me")
}

func (p *DefaultPeer) SetDNSLabel(s string) {
	// TODO implement me
	panic("implement me")
}

func (p *DefaultPeer) GetUserID() string {
	// TODO implement me
	panic("implement me")
}

func (p *DefaultPeer) SetUserID(s string) {
	// TODO implement me
	panic("implement me")
}

func (p *DefaultPeer) GetSSHKey() string {
	// TODO implement me
	panic("implement me")
}

func (p *DefaultPeer) SetSSHKey(s string) {
	// TODO implement me
	panic("implement me")
}

func (p *DefaultPeer) GetSSHEnabled() bool {
	// TODO implement me
	panic("implement me")
}

func (p *DefaultPeer) SetSSHEnabled(b bool) {
	// TODO implement me
	panic("implement me")
}
