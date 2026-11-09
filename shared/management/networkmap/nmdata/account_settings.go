package nmdata

import "time"

// AccountSettingsInfo is the slim twin of types.AccountSettingsInfo.
type AccountSettingsInfo struct {
	PeerLoginExpirationEnabled      bool
	PeerLoginExpiration             time.Duration
	PeerInactivityExpirationEnabled bool
	PeerInactivityExpiration        time.Duration
	DNSDomain                       string
	IPv6EnabledGroups               []string
	RoutingPeerDNSResolutionEnabled bool
	LazyConnectionEnabled           bool
	AutoUpdateVersion               string
	AutoUpdateAlways                bool
	MetricsPushEnabled              bool
}
