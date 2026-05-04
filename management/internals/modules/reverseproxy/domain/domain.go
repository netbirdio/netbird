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

// EventMeta returns activity event metadata for a domain
func (d *Domain) EventMeta() map[string]any {
	return map[string]any{
		"domain":         d.Domain,
		"target_cluster": d.TargetCluster,
		"validated":      d.Validated,
	}
}

func (d *Domain) Copy() *Domain {
	dCopy := *d
	return &dCopy
}
