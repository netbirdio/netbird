package types

import (
	"net/netip"
	"slices"
	"time"
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

	// DNSDomain is the custom domain for that account
	DNSDomain string

	// NetworkRange is the custom network range for that account
	NetworkRange netip.Prefix `gorm:"serializer:json"`

	// Extra is a dictionary of Account settings
	Extra *ExtraSettings `gorm:"embedded;embeddedPrefix:extra_"`

	// LazyConnectionEnabled indicates if the experimental feature is enabled or disabled
	LazyConnectionEnabled bool `gorm:"default:false"`

	// AutoUpdateVersion client auto-update version
	AutoUpdateVersion string `gorm:"default:'disabled'"`

	// EmbeddedIdpEnabled indicates if the embedded identity provider is enabled.
	// This is a runtime-only field, not stored in the database.
	EmbeddedIdpEnabled bool `gorm:"-"`

	// LocalAuthDisabled indicates if local (email/password) authentication is disabled.
	// This is a runtime-only field, not stored in the database.
	LocalAuthDisabled bool `gorm:"-"`
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
		LazyConnectionEnabled:           s.LazyConnectionEnabled,
		DNSDomain:                       s.DNSDomain,
		NetworkRange:                    s.NetworkRange,
		AutoUpdateVersion:               s.AutoUpdateVersion,
		EmbeddedIdpEnabled:              s.EmbeddedIdpEnabled,
		LocalAuthDisabled:               s.LocalAuthDisabled,
	}
	if s.Extra != nil {
		settings.Extra = s.Extra.Copy()
	}
	return settings
}

type ExtraSettings struct {
	// PeerApprovalEnabled enables or disables the need for peers bo be approved by an administrator
	PeerApprovalEnabled bool

	// UserApprovalRequired enables or disables the need for users joining via domain matching to be approved by an administrator
	UserApprovalRequired bool

	// IntegratedValidator is the string enum for the integrated validator type
	IntegratedValidator string
	// IntegratedValidatorGroups list of group IDs to be used with integrated approval configurations
	IntegratedValidatorGroups []string `gorm:"serializer:json"`

	FlowEnabled              bool     `gorm:"-"`
	FlowGroups               []string `gorm:"-"`
	FlowPacketCounterEnabled bool     `gorm:"-"`
	FlowENCollectionEnabled  bool     `gorm:"-"`
	FlowDnsCollectionEnabled bool     `gorm:"-"`
}

// Copy copies the ExtraSettings struct
func (e *ExtraSettings) Copy() *ExtraSettings {
	return &ExtraSettings{
		PeerApprovalEnabled:       e.PeerApprovalEnabled,
		UserApprovalRequired:      e.UserApprovalRequired,
		IntegratedValidatorGroups: slices.Clone(e.IntegratedValidatorGroups),
		IntegratedValidator:       e.IntegratedValidator,
		FlowEnabled:               e.FlowEnabled,
		FlowGroups:                slices.Clone(e.FlowGroups),
		FlowPacketCounterEnabled:  e.FlowPacketCounterEnabled,
		FlowENCollectionEnabled:   e.FlowENCollectionEnabled,
		FlowDnsCollectionEnabled:  e.FlowDnsCollectionEnabled,
	}
}
