package entra_device

import (
	"time"
)

// ChallengeResponse is returned by GET /join/entra/challenge.
type ChallengeResponse struct {
	Nonce     string    `json:"nonce"`      // base64 (URL) encoded random bytes
	ExpiresAt time.Time `json:"expires_at"` // RFC3339
}

// EnrollRequest is the body of POST /join/entra/enroll. All base64 fields use
// standard padded encoding unless otherwise noted.
type EnrollRequest struct {
	// TenantID lets the server disambiguate when the server hosts mappings
	// for several Entra tenants.
	TenantID string `json:"tenant_id"`

	// EntraDeviceID is the GUID the client reads from dsregcmd / Win32
	// NetGetAadJoinInformation. Optional; the authoritative source is the
	// cert Subject CN, but the server cross-checks.
	EntraDeviceID string `json:"entra_device_id,omitempty"`

	// CertChain is an ordered list of base64-DER certs: leaf first.
	CertChain []string `json:"cert_chain"`

	// Nonce is the one returned by /challenge.
	Nonce string `json:"nonce"`

	// NonceSignature is the cert's private key signing the nonce bytes
	// (RSA-PSS / SHA-256 for RSA, ECDSA-P256 / SHA-256 for EC).
	NonceSignature string `json:"nonce_signature"`

	// WGPubKey is the peer's base64-encoded WireGuard public key.
	WGPubKey string `json:"wg_pub_key"`

	// SSHPubKey is the peer's base64-encoded SSH public key (may be empty).
	SSHPubKey string `json:"ssh_pub_key,omitempty"`

	// Hostname, Meta and DNSLabels are forwarded to the existing AddPeer
	// plumbing; the shape matches the fields on types.PeerLogin.
	Hostname       string            `json:"hostname,omitempty"`
	DNSLabels      []string          `json:"dns_labels,omitempty"`
	Meta           map[string]string `json:"meta,omitempty"`
	ConnectionIP   string            `json:"connection_ip,omitempty"` // optional, server prefers real IP
	ExtraDNSLabels []string          `json:"extra_dns_labels,omitempty"`
}

// EnrollResponse is the JSON body returned on successful enrolment. The
// NetbirdConfig / PeerConfig fields are rendered as raw JSON so callers do not
// need to pull in the protobuf types.
type EnrollResponse struct {
	PeerID                   string          `json:"peer_id"`
	EnrollmentBootstrapToken string          `json:"enrollment_bootstrap_token"`
	ResolvedAutoGroups       []string        `json:"resolved_auto_groups"`
	MatchedMappingIDs        []string        `json:"matched_mapping_ids"`
	ResolutionMode           string          `json:"resolution_mode"`
	NetbirdConfig            map[string]any  `json:"netbird_config,omitempty"`
	PeerConfig               map[string]any  `json:"peer_config,omitempty"`
	Checks                   []map[string]any `json:"checks,omitempty"`
}

// DeviceIdentity is the validated device descriptor derived from the cert
// chain + Graph lookups.
type DeviceIdentity struct {
	EntraDeviceID  string
	TenantID       string
	CertThumbprint string
	AccountEnabled bool
	IsCompliant    bool
	GroupIDs       []string // Entra object IDs of all transitive groups the device belongs to.
}

// ResolvedMapping is the effective configuration applied to the new peer after
// evaluating all matched mappings against the chosen resolution mode.
type ResolvedMapping struct {
	AutoGroups          []string
	Ephemeral           bool
	AllowExtraDNSLabels bool
	ExpiresAt           *time.Time

	// MatchedMappingIDs is the ordered list of mapping IDs that contributed.
	MatchedMappingIDs []string
	// ResolutionMode echoes back which mode produced this result.
	ResolutionMode string
}
