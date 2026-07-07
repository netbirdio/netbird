// Package mdm reads MDM-managed configuration from platform-native sources
// (plist on macOS, registry on Windows, UserDefaults on iOS,
// RestrictionsManager on Android). The returned Policy is consumed by
// profilemanager.Config.apply() as the highest-priority override layer.
//
// An empty Policy (no source present, or source present with zero keys)
// means no MDM enforcement is active and the client behaves as if the
// feature did not exist.
package mdm

import (
	"sort"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

// Well-known policy keys. Names mirror the corresponding ConfigInput Go field
// names (lowerCamelCase) so the daemon can map a Policy key directly to a
// configuration field.
const (
	KeyManagementURL         = "managementURL"
	KeyDisableUpdateSettings = "disableUpdateSettings"
	KeyDisableProfiles       = "disableProfiles"
	KeyDisableNetworks       = "disableNetworks"
	// KeyDisableAdvancedView gates the advanced-view section in the
	// upcoming UI revision. UI-only: NOT stored on Config, not
	// applied by applyMDMPolicy, not rejectable via SetConfig. The
	// daemon surfaces it through GetFeatures (tristate: present
	// true / present false / absent) and the same key appears in
	// GetConfigResponse.mDMManagedFields when set.
	KeyDisableAdvancedView      = "disableAdvancedView"
	KeyDisableClientRoutes      = "disableClientRoutes"
	KeyDisableServerRoutes      = "disableServerRoutes"
	KeyBlockInbound             = "blockInbound"
	KeyDisableMetricsCollection = "disableMetricsCollection"
	KeyAllowServerSSH           = "allowServerSSH"
	KeyDisableAutoConnect       = "disableAutoConnect"
	// KeyDisableAutostart suppresses the GUI's fresh-install
	// launch-on-login default and marks the Settings toggle as
	// MDM-managed. UI-only: NOT stored on Config and not applied by
	// applyMDMPolicy; the GUI reads it directly and it appears in
	// GetConfigResponse.mDMManagedFields when set.
	KeyDisableAutostart    = "disableAutostart"
	KeyPreSharedKey        = "preSharedKey"
	KeyRosenpassEnabled    = "rosenpassEnabled"
	KeyRosenpassPermissive = "rosenpassPermissive"
	KeyWireguardPort       = "wireguardPort"
	KeyEnableLocalMetrics  = "enableLocalMetrics"
	KeyLocalMetricsAddress = "localMetricsAddress"

	// Split tunnel is modeled as a single conceptual policy with two
	// registry/plist values. KeySplitTunnelMode is the discriminator
	// ("allow" or "disallow"); KeySplitTunnelApps is a comma-separated
	// list of package names. The values are mutually exclusive by
	// construction — only one mode can be set at a time.
	KeySplitTunnelMode = "splitTunnelMode"
	KeySplitTunnelApps = "splitTunnelApps"

	// KeyLazyConnection forces the lazy-connection feature on or off, overriding
	// the management feature flag. Read as a bool (native bool, or on/off,
	// true/false, 1/0, yes/no); absent = defer to management.
	KeyLazyConnection = "lazyConnection"
)

// Split-tunnel mode literals (KeySplitTunnelMode values).
const (
	SplitTunnelModeAllow    = "allow"
	SplitTunnelModeDisallow = "disallow"
)

// SecretKeys lists keys whose values must be redacted in logs.
var SecretKeys = map[string]struct{}{
	KeyPreSharedKey: {},
}

// boolStringLiterals enumerates the textual boolean encodings the
// platform loaders may produce (Windows REG_SZ "true", iOS / Android
// managed-config booleans-as-strings, etc.). Lookup keeps GetBool flat
// (no nested switch on the string case).
var boolStringLiterals = map[string]bool{
	"true":  true,
	"1":     true,
	"yes":   true,
	"on":    true,
	"false": false,
	"0":     false,
	"no":    false,
	"off":   false,
}

// Policy holds MDM-managed settings read from the platform source. A nil or
// empty Policy means no enforcement is active.
type Policy struct {
	values map[string]any
}

// NewPolicy constructs a Policy from a key→value map. Pass nil or an
// empty map to construct an empty (no-enforcement) Policy. The returned
// *Policy is always non-nil.
func NewPolicy(values map[string]any) *Policy {
	if values == nil {
		values = map[string]any{}
	}
	return &Policy{values: values}
}

// LoadPolicy reads the platform-native MDM configuration. Returns an
// empty (but non-nil) Policy when no source is present, the source is
// empty, or the platform is unsupported.
//
// Diagnostic logging differentiates the three states:
//   - source absent / unsupported platform: trace log only
//   - source present, zero keys:             info "MDM enrolled (no managed keys)"
//   - source present, N keys:                info "MDM enrolled with N managed keys: [...]"
func LoadPolicy() *Policy {
	values, err := loadPlatformPolicy()
	if err != nil {
		log.Tracef("MDM policy load: %v", err)
		return &Policy{values: map[string]any{}}
	}
	if values == nil {
		return &Policy{values: map[string]any{}}
	}
	if len(values) == 0 {
		log.Info("MDM enrolled (no managed keys)")
	} else {
		log.Infof("MDM enrolled with %d managed key(s): %v", len(values), sortedKeys(values))
	}
	return &Policy{values: values}
}

// IsEmpty reports whether the Policy has no managed keys.
func (p *Policy) IsEmpty() bool {
	return p == nil || len(p.values) == 0
}

// HasKey reports whether the given key is MDM-managed.
func (p *Policy) HasKey(key string) bool {
	if p == nil {
		return false
	}
	_, ok := p.values[key]
	return ok
}

// ManagedKeys returns the sorted list of managed key names. Returns an empty
// slice (not nil) on an empty Policy.
func (p *Policy) ManagedKeys() []string {
	if p == nil {
		return []string{}
	}
	return sortedKeys(p.values)
}

// GetString returns the managed value for key coerced to string, and whether
// the key was set. A non-string value returns ("", false).
func (p *Policy) GetString(key string) (string, bool) {
	if p == nil {
		return "", false
	}
	v, ok := p.values[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return "", false
	}
	return s, true
}

// GetBool returns the managed value for key coerced to bool, and whether the
// key was set. Accepts native bool and string literals (true/false, 1/0,
// yes/no, on/off), case-insensitively and trimmed of surrounding whitespace.
func (p *Policy) GetBool(key string) (bool, bool) {
	if p == nil {
		return false, false
	}
	v, ok := p.values[key]
	if !ok {
		return false, false
	}
	switch t := v.(type) {
	case bool:
		return t, true
	case string:
		b, known := boolStringLiterals[strings.ToLower(strings.TrimSpace(t))]
		return b, known
	case int:
		return t != 0, true
	case int64:
		return t != 0, true
	}
	return false, false
}

// GetInt returns the managed value for key as int64, and whether the key
// was set. Accepts native int / int64 (as produced by the Windows registry
// loader for REG_DWORD/REG_QWORD) and numeric strings (decimal).
func (p *Policy) GetInt(key string) (int64, bool) {
	if p == nil {
		return 0, false
	}
	v, ok := p.values[key]
	if !ok {
		return 0, false
	}
	switch t := v.(type) {
	case int64:
		return t, true
	case int:
		return int64(t), true
	case int32:
		return int64(t), true
	case uint64:
		return int64(t), true
	case float64:
		return int64(t), true
	case string:
		if n, err := strconv.ParseInt(t, 10, 64); err == nil {
			return n, true
		}
	}
	return 0, false
}

// GetStringSlice returns the managed value for key as []string, and whether
// the key was set. Accepts []string, []any (of strings), and a single string
// (treated as a one-element list).
func (p *Policy) GetStringSlice(key string) ([]string, bool) {
	if p == nil {
		return nil, false
	}
	v, ok := p.values[key]
	if !ok {
		return nil, false
	}
	switch t := v.(type) {
	case []string:
		return append([]string(nil), t...), true
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			s, ok := item.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	case string:
		return []string{t}, true
	}
	return nil, false
}

// sortedKeys returns the keys of m as a deterministic, lexicographically
// sorted slice. Used internally by Policy.ManagedKeys and LoadPolicy's
// diagnostic log line so callers see a stable key order across runs
// regardless of Go's randomised map iteration.
func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
