package entradevice

import (
	"time"
)

// EntraEnrollState is persisted per NetBird profile after a successful
// /join/entra/enroll. Its presence causes subsequent `netbird up` calls on
// the same profile to skip enrolment and proceed directly to the normal
// gRPC Login cycle using the WG pubkey the server already knows about.
type EntraEnrollState struct {
	// EntraDeviceID is the device GUID captured from the cert Subject CN at
	// enrolment time. Useful for support diagnostics.
	EntraDeviceID string `json:"entra_device_id"`

	// TenantID captures the Entra tenant id used during enrolment.
	TenantID string `json:"tenant_id"`

	// PeerID is the NetBird peer id the server assigned. Lets operators
	// correlate client logs with server-side activity entries.
	PeerID string `json:"peer_id"`

	// EnrolledAt is the UTC time the profile was enrolled.
	EnrolledAt time.Time `json:"enrolled_at"`

	// EnrolledViaURL records the exact management URL (path included) that
	// was used. Kept for audit.
	EnrolledViaURL string `json:"enrolled_via_url,omitempty"`

	// ResolutionMode + ResolvedAutoGroups + MatchedMappingIDs are echoed
	// back by the server for transparency, so operators can see *why* the
	// peer was put in the NetBird groups it ended up in.
	ResolutionMode     string   `json:"resolution_mode,omitempty"`
	ResolvedAutoGroups []string `json:"resolved_auto_groups,omitempty"`
	MatchedMappingIDs  []string `json:"matched_mapping_ids,omitempty"`
}

// IsEnrolled is a small helper so callers don't litter nil checks.
func (s *EntraEnrollState) IsEnrolled() bool {
	return s != nil && s.PeerID != "" && !s.EnrolledAt.IsZero()
}
