package store

import (
	"time"

	dnsTypes "github.com/netbirdio/netbird/management/refactor/resources/dns/types"
	groupTypes "github.com/netbirdio/netbird/management/refactor/resources/groups/types"
	networkTypes "github.com/netbirdio/netbird/management/refactor/resources/network/types"
	peerTypes "github.com/netbirdio/netbird/management/refactor/resources/peers/types"
	policyTypes "github.com/netbirdio/netbird/management/refactor/resources/policies/types"
	routeTypes "github.com/netbirdio/netbird/management/refactor/resources/routes/types"
	settingsTypes "github.com/netbirdio/netbird/management/refactor/resources/settings/types"
	setupKeyTypes "github.com/netbirdio/netbird/management/refactor/resources/setup_keys/types"
	userTypes "github.com/netbirdio/netbird/management/refactor/resources/users/types"
	"github.com/netbirdio/netbird/management/server/posture"
)

// Account represents a unique account of the system
type DefaultAccount struct {
	// we have to name column to aid as it collides with Network.Id when work with associations
	Id string `gorm:"primaryKey"`

	// User.Id it was created by
	CreatedBy              string
	CreatedAt              time.Time
	Domain                 string `gorm:"index"`
	DomainCategory         string
	IsDomainPrimaryAccount bool
	SetupKeys              map[string]*setupKeyTypes.DefaultSetupKey   `gorm:"-"`
	SetupKeysG             []setupKeyTypes.DefaultSetupKey             `json:"-" gorm:"foreignKey:AccountID;references:id"`
	Network                *networkTypes.Network                       `gorm:"embedded;embeddedPrefix:network_"`
	Peers                  map[string]*peerTypes.DefaultPeer           `gorm:"-"`
	PeersG                 []peerTypes.DefaultPeer                     `json:"-" gorm:"foreignKey:AccountID;references:id"`
	Users                  map[string]*userTypes.DefaultUser           `gorm:"-"`
	UsersG                 []userTypes.DefaultUser                     `json:"-" gorm:"foreignKey:AccountID;references:id"`
	Groups                 map[string]*groupTypes.DefaultGroup         `gorm:"-"`
	GroupsG                []groupTypes.DefaultGroup                   `json:"-" gorm:"foreignKey:AccountID;references:id"`
	Policies               []*policyTypes.DefaultPolicy                `gorm:"foreignKey:AccountID;references:id"`
	Routes                 map[string]*routeTypes.DefaultRoute         `gorm:"-"`
	RoutesG                []routeTypes.DefaultRoute                   `json:"-" gorm:"foreignKey:AccountID;references:id"`
	NameServerGroups       map[string]*dnsTypes.DefaultNameServerGroup `gorm:"-"`
	NameServerGroupsG      []dnsTypes.DefaultNameServerGroup           `json:"-" gorm:"foreignKey:AccountID;references:id"`
	DNSSettings            dnsTypes.DefaultSettings                    `gorm:"embedded;embeddedPrefix:dns_settings_"`
	PostureChecks          []*posture.Checks                           `gorm:"foreignKey:AccountID;references:id"`
	// Settings is a dictionary of Account settings
	Settings *settingsTypes.DefaultSettings `gorm:"embedded;embeddedPrefix:settings_"`
	// deprecated on store and api level
	Rules  map[string]*Rule `json:"-" gorm:"-"`
	RulesG []Rule           `json:"-" gorm:"-"`
}
