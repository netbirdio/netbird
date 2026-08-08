package domain

import "time"

type Type string

const (
	TypeFree   Type = "free"
	TypeCustom Type = "custom"
)

type Domain struct {
	ID string `gorm:"unique;primaryKey;autoIncrement"`
	// A claim is unique per account only. Global uniqueness applies once a row
	// is validated and is enforced by the manager, because proving control of
	// the DNS zone is what decides which account may serve the hostname.
	Domain        string `gorm:"uniqueIndex:idx_domains_account_id_domain,priority:2"`
	AccountID     string `gorm:"index;uniqueIndex:idx_domains_account_id_domain,priority:1"`
	TargetCluster string // The proxy cluster this domain should be validated against
	Type          Type   `gorm:"-"`
	Validated     bool
	// ClaimedAt is when the account last staked its claim on the domain. It
	// bounds how long an unvalidated row may hold the name.
	ClaimedAt time.Time
	// SupportsCustomPorts is populated at query time for free domains from the
	// proxy cluster capabilities. Not persisted.
	SupportsCustomPorts *bool `gorm:"-"`
	// RequireSubdomain is populated at query time. When true, the domain
	// cannot be used bare and a subdomain label must be prepended. Not persisted.
	RequireSubdomain *bool `gorm:"-"`
	// SupportsCrowdSec is populated at query time from proxy cluster capabilities.
	// Not persisted.
	SupportsCrowdSec *bool `gorm:"-"`
	// SupportsPrivate is populated at query time from proxy cluster capabilities. Not persisted.
	SupportsPrivate *bool `gorm:"-"`
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
