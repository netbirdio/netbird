package mdm

import "encoding/json"

// Fields carries the per-key MDM enforcement state for a UI: value-typed
// fields hold the enforced value, boolean fields report that the key is
// managed.
type Fields struct {
	ManagementURL            string `json:"managementURL"`
	PreSharedKey             bool   `json:"preSharedKey"`
	WireguardPort            bool   `json:"wireguardPort"`
	RosenpassEnabled         bool   `json:"rosenpassEnabled"`
	RosenpassPermissive      bool   `json:"rosenpassPermissive"`
	DisableClientRoutes      bool   `json:"disableClientRoutes"`
	DisableServerRoutes      bool   `json:"disableServerRoutes"`
	AllowServerSSH           *bool  `json:"allowServerSSH"`
	DisableAutoConnect       bool   `json:"disableAutoConnect"`
	DisableAutostart         bool   `json:"disableAutostart"`
	BlockInbound             bool   `json:"blockInbound"`
	DisableMetricsCollection bool   `json:"disableMetricsCollection"`
	SplitTunnelMode          bool   `json:"splitTunnelMode"`
	SplitTunnelApps          bool   `json:"splitTunnelApps"`
	DisableAdvancedView      bool   `json:"disableAdvancedView"`
}

// Features carries the feature gates a UI must honor.
type Features struct {
	DisableProfiles       bool `json:"disableProfiles"`
	DisableNetworks       bool `json:"disableNetworks"`
	DisableUpdateSettings bool `json:"disableUpdateSettings"`
}

// Restrictions is the UI-facing enforcement snapshot; the JSON shape is
// shared by the desktop frontend and the mobile bridges.
type Restrictions struct {
	MDM      Fields   `json:"mdm"`
	Features Features `json:"features"`
}

// BuildRestrictions derives the UI enforcement snapshot from the active
// policy.
func BuildRestrictions(policy *Policy) Restrictions {
	var r Restrictions
	if policy.IsEmpty() {
		return r
	}

	if v, ok := policy.GetString(KeyManagementURL); ok {
		r.MDM.ManagementURL = CanonicalURL(v)
	}
	r.MDM.PreSharedKey = policy.HasKey(KeyPreSharedKey)
	r.MDM.WireguardPort = policy.HasKey(KeyWireguardPort)
	r.MDM.RosenpassEnabled = policy.HasKey(KeyRosenpassEnabled)
	r.MDM.RosenpassPermissive = policy.HasKey(KeyRosenpassPermissive)
	r.MDM.DisableClientRoutes = policy.HasKey(KeyDisableClientRoutes)
	r.MDM.DisableServerRoutes = policy.HasKey(KeyDisableServerRoutes)
	r.MDM.DisableAutoConnect = policy.HasKey(KeyDisableAutoConnect)
	r.MDM.DisableAutostart = policy.HasKey(KeyDisableAutostart)
	r.MDM.BlockInbound = policy.HasKey(KeyBlockInbound)
	r.MDM.DisableMetricsCollection = policy.HasKey(KeyDisableMetricsCollection)
	r.MDM.SplitTunnelMode = policy.HasKey(KeySplitTunnelMode)
	r.MDM.SplitTunnelApps = policy.HasKey(KeySplitTunnelApps)
	if v, ok := policy.GetBool(KeyAllowServerSSH); ok {
		r.MDM.AllowServerSSH = &v
	}
	if v, ok := policy.GetBool(KeyDisableAdvancedView); ok {
		r.MDM.DisableAdvancedView = v
	}

	if v, ok := policy.GetBool(KeyDisableProfiles); ok {
		r.Features.DisableProfiles = v
	}
	if v, ok := policy.GetBool(KeyDisableNetworks); ok {
		r.Features.DisableNetworks = v
	}
	if v, ok := policy.GetBool(KeyDisableUpdateSettings); ok {
		r.Features.DisableUpdateSettings = v
	}
	return r
}

// JSON renders the snapshot in the shared UI JSON shape.
func (r Restrictions) JSON() (string, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
