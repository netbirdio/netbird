package accounts

import (
	"time"

	nbdns "github.com/netbirdio/netbird/dns"
)

// Settings represents Account settings structure that can be modified via API and Dashboard
type Settings struct {
	// PeerLoginExpirationEnabled globally enables or disables peer login expiration
	PeerLoginExpirationEnabled bool

	// PeerLoginExpiration is a setting that indicates when peer login expires.
	// Applies to all peers that have Peer.LoginExpirationEnabled set to true.
	PeerLoginExpiration time.Duration

	// GroupsPropagationEnabled allows to propagate auto groups from the user to the peer
	GroupsPropagationEnabled bool

	// JWTGroupsEnabled allows extract groups from JWT claim, which name defined in the JWTGroupsClaimName
	// and add it to account groups.
	JWTGroupsEnabled bool

	// JWTGroupsClaimName from which we extract groups name to add it to account groups
	JWTGroupsClaimName string
}

// Copy copies the Settings struct
func (s *Settings) Copy() *Settings {
	return &Settings{
		PeerLoginExpirationEnabled: s.PeerLoginExpirationEnabled,
		PeerLoginExpiration:        s.PeerLoginExpiration,
		JWTGroupsEnabled:           s.JWTGroupsEnabled,
		JWTGroupsClaimName:         s.JWTGroupsClaimName,
		GroupsPropagationEnabled:   s.GroupsPropagationEnabled,
	}
}

// Account represents a unique account of the system
type Account struct {
	// we have to name column to aid as it collides with Network.Id when work with associations
	Id string `gorm:"primaryKey"`

	// User.Id it was created by
	CreatedBy              string
	Domain                 string `gorm:"index"`
	DomainCategory         string
	IsDomainPrimaryAccount bool
	SetupKeys              map[string]*SetupKey              `gorm:"-"`
	SetupKeysG             []SetupKey                        `json:"-" gorm:"foreignKey:AccountID;references:id"`
	Network                *Network                          `gorm:"embedded;embeddedPrefix:network_"`
	Peers                  map[string]*Peer                  `gorm:"-"`
	PeersG                 []Peer                            `json:"-" gorm:"foreignKey:AccountID;references:id"`
	Users                  map[string]*User                  `gorm:"-"`
	UsersG                 []User                            `json:"-" gorm:"foreignKey:AccountID;references:id"`
	Groups                 map[string]*Group                 `gorm:"-"`
	GroupsG                []Group                           `json:"-" gorm:"foreignKey:AccountID;references:id"`
	Rules                  map[string]*Rule                  `gorm:"-"`
	RulesG                 []Rule                            `json:"-" gorm:"foreignKey:AccountID;references:id"`
	Policies               []*Policy                         `gorm:"foreignKey:AccountID;references:id"`
	Routes                 map[string]*route.Route           `gorm:"-"`
	RoutesG                []route.Route                     `json:"-" gorm:"foreignKey:AccountID;references:id"`
	NameServerGroups       map[string]*nbdns.NameServerGroup `gorm:"-"`
	NameServerGroupsG      []nbdns.NameServerGroup           `json:"-" gorm:"foreignKey:AccountID;references:id"`
	DNSSettings            DNSSettings                       `gorm:"embedded;embeddedPrefix:dns_settings_"`
	// Settings is a dictionary of Account settings
	Settings *Settings `gorm:"embedded;embeddedPrefix:settings_"`
}
