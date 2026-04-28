package domain

type Type string

const (
	TypeFree   Type = "free"
	TypeCustom Type = "custom"
)

type Domain struct {
	ID            string `gorm:"unique;primaryKey;autoIncrement"`
	Domain        string `gorm:"unique"` // Domain records must be unique, this avoids domain reuse across accounts.
	AccountID     string `gorm:"index"`
	TargetCluster string // The proxy cluster this domain should be validated against
	Type          Type   `gorm:"-"`
	Validated     bool
	// AutoConfigured is true when NetBird wrote the wildcard CNAME via the
	// auto-configure flow (using a stored DNS provider credential) rather
	// than the user creating it manually in their DNS UI.
	AutoConfigured bool `gorm:"default:false"`
	// AutoConfiguredCredentialID references the credential that was used
	// to write the CNAME. Stored so a future "remove the CNAME on domain
	// delete" feature can authenticate against the same provider.
	AutoConfiguredCredentialID string `gorm:"index;default:null"`
	// AutoConfiguredProvider is the provider type ("cloudflare", etc.)
	// denormalized from the credential at write time. Stored separately
	// so the dashboard's "Auto via Cloudflare" pill renders without a
	// second-fetch and survives the user later deleting the credential.
	AutoConfiguredProvider string `gorm:"default:null"`
	// SupportsCustomPorts is populated at query time for free domains from the
	// proxy cluster capabilities. Not persisted.
	SupportsCustomPorts *bool `gorm:"-"`
	// RequireSubdomain is populated at query time. When true, the domain
	// cannot be used bare and a subdomain label must be prepended. Not persisted.
	RequireSubdomain *bool `gorm:"-"`
	// SupportsCrowdSec is populated at query time from proxy cluster capabilities.
	// Not persisted.
	SupportsCrowdSec *bool `gorm:"-"`
}

// AutoConfigureRecord captures the metadata persisted when a custom
// domain is created via the auto-configure flow (NetBird wrote the
// CNAME on the user's behalf using a stored DNS provider credential).
// Passed to store.CreateCustomDomain as an optional pointer — nil
// means the manual flow.
type AutoConfigureRecord struct {
	CredentialID string
	Provider     string
}

// EventMeta returns activity event metadata for a domain
func (d *Domain) EventMeta() map[string]any {
	meta := map[string]any{
		"domain":         d.Domain,
		"target_cluster": d.TargetCluster,
		"validated":      d.Validated,
	}
	if d.AutoConfigured {
		meta["auto_configured"] = true
		meta["auto_configured_provider"] = d.AutoConfiguredProvider
	}
	return meta
}

func (d *Domain) Copy() *Domain {
	dCopy := *d
	return &dCopy
}
