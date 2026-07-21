//go:build windows || darwin

package mdm

import "strings"

// allKeys is the set of recognised MDM keys. Unknown keys in a managed
// configuration are ignored but logged. Lives in this build-tagged file
// (windows || darwin) because only desktop loaders need the
// canonicalisation table that consumes it; including it unconditionally
// would trigger the `unused` golangci-lint check on platforms that
// don't import canonical_loaders.go.
var allKeys = []string{
	KeyManagementURL,
	KeyDisableUpdateSettings,
	KeyDisableProfiles,
	KeyDisableNetworks,
	KeyDisableAdvancedView,
	KeyDisableClientRoutes,
	KeyDisableServerRoutes,
	KeyBlockInbound,
	KeyDisableMetricsCollection,
	KeyAllowServerSSH,
	KeyAllowServerVNC,
	KeyDisableVNCApproval,
	KeyDisableAutoConnect,
	KeyDisableAutostart,
	KeyPreSharedKey,
	KeyRosenpassEnabled,
	KeyRosenpassPermissive,
	KeyWireguardPort,
	KeySplitTunnelMode,
	KeySplitTunnelApps,
	KeyLazyConnection,
}

// canonicalKey maps the lowercase form of a managed-config value name to
// its canonical mdm.Key* form. Admins commonly write PascalCase value
// names in ADMX / Group Policy ("ManagementURL"); the iOS/AppConfig and
// macOS plist conventions are camelCase ("managementURL"); both must
// resolve to the same Policy lookup.
//
// Lives in a desktop-loader-only file (build tag `windows || darwin`)
// because no other build path consumes it. Linux / FreeBSD / mobile
// builds don't ship a platform loader that reads arbitrary-case key
// names, so they don't need the canonicalisation table — and including
// the var unconditionally would trigger the `unused` golangci-lint
// check on those platforms.
var canonicalKey = func() map[string]string {
	m := make(map[string]string, len(allKeys))
	for _, k := range allKeys {
		m[strings.ToLower(k)] = k
	}
	return m
}()
