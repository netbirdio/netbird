package profilemanager

import "time"

// EntraEnrollState is a compact copy of the client-side Entra device auth
// state, duplicated here (rather than imported from entradevice) to avoid an
// import cycle between profilemanager and the enroll package.
//
// It is persisted inside Config.EntraEnroll; see config.go for the hook.
type EntraEnrollState struct {
	EntraDeviceID      string    `json:"entra_device_id"`
	TenantID           string    `json:"tenant_id"`
	PeerID             string    `json:"peer_id"`
	EnrolledAt         time.Time `json:"enrolled_at"`
	EnrolledViaURL     string    `json:"enrolled_via_url,omitempty"`
	ResolutionMode     string    `json:"resolution_mode,omitempty"`
	ResolvedAutoGroups []string  `json:"resolved_auto_groups,omitempty"`
	MatchedMappingIDs  []string  `json:"matched_mapping_ids,omitempty"`
}
