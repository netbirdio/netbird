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

	// PeerExposeEnabled enables or disables peer-initiated service expose
	PeerExposeEnabled bool
	// PeerExposeGroups list of peer group IDs allowed to expose services
	PeerExposeGroups []string `gorm:"serializer:json"`

	// Extra is a dictionary of Account settings
	Extra *ExtraSettings `gorm:"embedded;embeddedPrefix:extra_"`

	// LazyConnectionEnabled indicates if the experimental feature is enabled or disabled
	LazyConnectionEnabled bool `gorm:"default:false"`

	// ConnectionMode is the account-wide default connection mode (Phase 1
	// of issue #5989). Nullable: NULL means "fall back to LazyConnectionEnabled".
	// Stored as the canonical lower-kebab-case string (e.g. "p2p-lazy").
	ConnectionMode *string `gorm:"type:varchar(32);default:null"`

	// RelayTimeoutSeconds, when non-NULL, overrides the built-in default
	// (5 min). 0 = "never tear down". Nullable to distinguish "use default"
	// from "explicit 0".
	RelayTimeoutSeconds *uint32 `gorm:"default:null"`

	// P2pTimeoutSeconds is reserved for Phase 2; same nullable semantics.
	// Built-in default in Phase 1: 180 min, but not yet effective.
	P2pTimeoutSeconds *uint32 `gorm:"default:null"`

	// P2pRetryMaxSeconds is reserved for Phase 3 (#5989). Caps the ICE-
	// failure backoff sequence in p2p-dynamic mode. NULL = use daemon's
	// built-in default (900s = 15 min). 0 = disable backoff (treated
	// internally as "user-explicit-disable" via uint32-max sentinel on
	// the wire).
	P2pRetryMaxSeconds *uint32 `gorm:"default:null"`

	// LegacyLazyFallbackEnabled (Phase 3.7i, #5989) controls whether the
	// management server downgrades clients that do NOT advertise the
	// "p2p_dynamic" capability to p2p-lazy when the account is in
	// p2p-dynamic mode. Defaults to true so that pre-3.7i clients keep
	// behaving sanely after an admin flips ConnectionMode to p2p-dynamic.
	// Set to false to send the raw p2p-dynamic config to all clients
	// (advanced; only useful when you know the entire fleet is upgraded).
	// No effect outside p2p-dynamic mode.
	//
	// Use ApplyLegacyLazyFallbackDefaults to seed the field correctly
	// in places that build a fresh Settings from scratch (PUT handler,
	// account creation, in-memory FileStore migration). The GORM
	// `default:true` only fires for SQL inserts.
	LegacyLazyFallbackEnabled bool `gorm:"default:true"`

	// LegacyLazyFallbackTimeoutSeconds (Phase 3.7i, #5989) is the relay
	// inactivity timeout sent to legacy clients via the lazy-fallback
	// branch. Default 3600s (60 min) - long enough to not hammer
	// connection setup on flaky LTE links, short enough to actually
	// release idle peers. Must be in [60, 86400]; validated by the
	// HTTP API handler.
	LegacyLazyFallbackTimeoutSeconds uint32 `gorm:"default:3600"`

	// AutoUpdateVersion client auto-update version
	AutoUpdateVersion string `gorm:"default:'disabled'"`

	// AutoUpdateAlways when true, updates are installed automatically in the background;
	// when false, updates require user interaction from the UI
	AutoUpdateAlways bool `gorm:"default:false"`

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
		PeerExposeEnabled:               s.PeerExposeEnabled,
		PeerExposeGroups:                slices.Clone(s.PeerExposeGroups),
		LazyConnectionEnabled:            s.LazyConnectionEnabled,
		ConnectionMode:                   cloneStringPtr(s.ConnectionMode),
		RelayTimeoutSeconds:              cloneUint32Ptr(s.RelayTimeoutSeconds),
		P2pTimeoutSeconds:                cloneUint32Ptr(s.P2pTimeoutSeconds),
		P2pRetryMaxSeconds:               cloneUint32Ptr(s.P2pRetryMaxSeconds),
		LegacyLazyFallbackEnabled:        s.LegacyLazyFallbackEnabled,
		LegacyLazyFallbackTimeoutSeconds: s.LegacyLazyFallbackTimeoutSeconds,
		DNSDomain:                       s.DNSDomain,
		NetworkRange:                    s.NetworkRange,
		AutoUpdateVersion:               s.AutoUpdateVersion,
		AutoUpdateAlways:                s.AutoUpdateAlways,
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

// cloneStringPtr returns a deep copy of a *string (nil-safe). Used by
// Settings.Copy for the new nullable ConnectionMode field.
func cloneStringPtr(p *string) *string {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

// cloneUint32Ptr returns a deep copy of a *uint32 (nil-safe). Used by
// Settings.Copy for the new nullable timeout fields.
func cloneUint32Ptr(p *uint32) *uint32 {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

// StringPtrEqual nil-safe equality for *string. Used to detect changes
// in nullable settings fields when deciding whether to push updated
// PeerConfig to live clients (account.updateAccountPeers).
func StringPtrEqual(a, b *string) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

// Uint32PtrEqual nil-safe equality for *uint32. Same purpose as
// StringPtrEqual for the new timeout fields.
func Uint32PtrEqual(a, b *uint32) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

// Phase 3.7i (#5989): canonical defaults for the LegacyLazyFallback*
// fields. Centralised so every code path that builds a Settings from
// scratch lands on the same numbers. The GORM `default:` tags only
// apply at INSERT time, so callers that mutate Settings in memory
// (PUT handler, account creation, FileStore migration) must call
// ApplyLegacyLazyFallbackDefaults explicitly.
const (
	DefaultLegacyLazyFallbackEnabled        = true
	DefaultLegacyLazyFallbackTimeoutSeconds = uint32(3600)
)

// ApplyLegacyLazyFallbackDefaults seeds the two LegacyLazyFallback*
// fields if they are at the Go zero value. Idempotent — calling it on
// an already-populated Settings is a no-op. The "is at zero value"
// detection is intentionally simple: there is no semantic difference
// between "user explicitly turned the toggle off / set timeout to 0"
// and "field uninitialised", because we forbid 0 timeouts at the API
// layer (range [60, 86400]) and the false toggle case is preserved
// only when the field was already true and got copied verbatim. New
// codepaths that need to remember "user opted out" should use the API
// handler's path (which only ever sees the wire field).
func (s *Settings) ApplyLegacyLazyFallbackDefaults() {
	if s == nil {
		return
	}
	// timeout==0 is never valid, so we always rewrite. Toggle: only
	// reset to default true when the timeout was also zero (= field
	// freshly built, never touched), otherwise honour the explicit
	// false the caller put there.
	if s.LegacyLazyFallbackTimeoutSeconds == 0 {
		s.LegacyLazyFallbackEnabled = DefaultLegacyLazyFallbackEnabled
		s.LegacyLazyFallbackTimeoutSeconds = DefaultLegacyLazyFallbackTimeoutSeconds
	}
}
