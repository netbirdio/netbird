package types

// Device authentication mode constants — what combination of auth factors is required.
const (
	DeviceAuthModeDisabled   = "disabled"
	DeviceAuthModeOptional   = "optional"
	DeviceAuthModeCertOnly   = "cert-only"
	DeviceAuthModeCertAndSSO = "cert-and-sso"
)

// Device enrollment mode constants — how device certificates are issued.
const (
	DeviceAuthEnrollmentManual      = "manual"
	DeviceAuthEnrollmentAttestation = "attestation"
	DeviceAuthEnrollmentBoth        = "both"
)

// Certificate authority backend type constants.
const (
	DeviceAuthCATypeBuiltin   = "builtin"
	DeviceAuthCATypeVault     = "vault"
	DeviceAuthCATypeSmallstep = "smallstep"
	DeviceAuthCATypeSCEP      = "scep"
)

// DeviceAuthSettings controls device certificate enforcement for an account.
// It is embedded in Settings via: DeviceAuth *DeviceAuthSettings `gorm:"embedded;embeddedPrefix:device_auth_"`
type DeviceAuthSettings struct {
	// Mode determines what combination of auth factors is required.
	Mode string `gorm:"default:disabled"`

	// EnrollmentMode determines how device certificates are issued.
	EnrollmentMode string `gorm:"default:manual"`

	// CAType selects the certificate authority backend.
	CAType string `gorm:"default:builtin"`

	// CAConfig is a JSON-encoded CA-specific configuration blob.
	CAConfig string

	// CertValidityDays is the number of days issued device certificates remain valid.
	CertValidityDays int `gorm:"default:365"`

	// OCSPEnabled enables Online Certificate Status Protocol revocation checks.
	OCSPEnabled bool

	// FailOpenOnOCSPUnavailable controls behaviour when the OCSP endpoint is unreachable.
	// When false (default) the connection is rejected if revocation cannot be confirmed.
	FailOpenOnOCSPUnavailable bool

	// InventoryType selects the device inventory backend used for attestation enrollment.
	// Supported values: "" or "static" (allow-list), "intune", "jamf".
	InventoryType string

	// InventoryConfig is a JSON-encoded inventory-specific configuration blob
	// (e.g. Intune tenant/client IDs, Jamf URL, or static serial list).
	InventoryConfig string

	// RequireInventoryCheck gates manual enrollment: when true, a device must be
	// found in the configured inventory (InventoryConfig) before an enrollment
	// request is accepted. The client-supplied SystemSerialNumber is checked
	// against the inventory. Requests from unrecognised devices are rejected
	// immediately without creating a pending entry visible to admins.
	RequireInventoryCheck bool

	// InventoryRecheckIntervalHours controls how often the inventory is re-consulted
	// during auto-renewal. 0 means always re-check on every renewal (no caching).
	// Positive values skip the MDM call when LastInventoryCheckAt on the
	// DeviceCertificate falls within the interval. Default: 24 (hours).
	InventoryRecheckIntervalHours int `gorm:"default:24"`

	// InventoryRecheckFailBehavior determines what happens when the MDM API is
	// unreachable during a re-check at auto-renewal time.
	// "deny" (default): abort renewal — peer stays on old cert until expiry, then
	//   must re-enroll manually after MDM recovers.
	// "allow": log a warning and proceed — fail-open for operational resilience.
	InventoryRecheckFailBehavior string `gorm:"default:deny"`
}

// Copy returns a deep copy of the DeviceAuthSettings.
func (d *DeviceAuthSettings) Copy() *DeviceAuthSettings {
	if d == nil {
		return nil
	}
	return &DeviceAuthSettings{
		Mode:                          d.Mode,
		EnrollmentMode:                d.EnrollmentMode,
		CAType:                        d.CAType,
		CAConfig:                      d.CAConfig,
		CertValidityDays:              d.CertValidityDays,
		OCSPEnabled:                   d.OCSPEnabled,
		FailOpenOnOCSPUnavailable:     d.FailOpenOnOCSPUnavailable,
		InventoryType:                 d.InventoryType,
		InventoryConfig:               d.InventoryConfig,
		RequireInventoryCheck:         d.RequireInventoryCheck,
		InventoryRecheckIntervalHours: d.InventoryRecheckIntervalHours,
		InventoryRecheckFailBehavior:  d.InventoryRecheckFailBehavior,
	}
}
