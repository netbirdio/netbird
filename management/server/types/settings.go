package types

import (
	"time"

	"github.com/netbirdio/netbird/management/server/account"
)

// Settings represents Account settings structure that can be modified via API and Dashboard
type Settings struct {
	// PeerLoginExpirationEnabled globally enables or disables peer login expiration
	PeerLoginExpirationEnabled bool

	// PeerLoginExpiration is a setting that indicates when peer login expires.
	// Applies to all peers that have Peer.LoginExpirationEnabled set to true.
	PeerLoginExpiration time.Duration

	// PeerInactivityExpirationEnabled globally enables or disables peer inactivity expiration
	PeerInactivityExpirationEnabled bool

	// PeerInactivityExpiration is a setting that indicates when peer inactivity expires.
	// Applies to all peers that have Peer.PeerInactivityExpirationEnabled set to true.
	PeerInactivityExpiration time.Duration

	// RegularUsersViewBlocked allows to block regular users from viewing even their own peers and some UI elements
	RegularUsersViewBlocked bool

	// GroupsPropagationEnabled allows to propagate auto groups from the user to the peer
	GroupsPropagationEnabled bool

	// JWTGroupsEnabled allows extract groups from JWT claim, which name defined in the JWTGroupsClaimName
	// and add it to account groups.
	JWTGroupsEnabled bool

	// JWTGroupsClaimName from which we extract groups name to add it to account groups
	JWTGroupsClaimName string

	// JWTAllowGroups list of groups to which users are allowed access
	JWTAllowGroups []string `gorm:"serializer:json"`

	// RoutingPeerDNSResolutionEnabled enabled the DNS resolution on the routing peers
	RoutingPeerDNSResolutionEnabled bool

	// Extra is a dictionary of Account settings
	Extra *account.ExtraSettings `gorm:"embedded;embeddedPrefix:extra_"`
}

// Copy copies the Settings struct
func (s *Settings) Copy() *Settings {
	settings := &Settings{
		PeerLoginExpirationEnabled: s.PeerLoginExpirationEnabled,
		PeerLoginExpiration:        s.PeerLoginExpiration,
		JWTGroupsEnabled:           s.JWTGroupsEnabled,
		JWTGroupsClaimName:         s.JWTGroupsClaimName,
		GroupsPropagationEnabled:   s.GroupsPropagationEnabled,
		JWTAllowGroups:             s.JWTAllowGroups,
		RegularUsersViewBlocked:    s.RegularUsersViewBlocked,

		PeerInactivityExpirationEnabled: s.PeerInactivityExpirationEnabled,
		PeerInactivityExpiration:        s.PeerInactivityExpiration,

		RoutingPeerDNSResolutionEnabled: s.RoutingPeerDNSResolutionEnabled,
	}
	if s.Extra != nil {
		settings.Extra = s.Extra.Copy()
	}
	return settings
}
