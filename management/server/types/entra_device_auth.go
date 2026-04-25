// Package types - entra_device_auth.go defines the domain model for the
// Entra/Intune device authentication integration.
//
// See management/server/integrations/entra_device/README.md for the overall
// design. This file mirrors the structure of types.SetupKey intentionally so
// admin UX feels identical.
package types

import (
	"strings"
	"time"

	"github.com/rs/xid"
)

// MappingResolution controls how the server resolves an enrolment when a
// device is a member of multiple Entra groups that each have a mapping row.
type MappingResolution string

const (
	// MappingResolutionStrictPriority applies only the single mapping with the
	// lowest Priority value. Ties broken by mapping ID ascending.
	MappingResolutionStrictPriority MappingResolution = "strict_priority"

	// MappingResolutionUnion applies all matched mappings merged together:
	//   AutoGroups            -> set-union
	//   Ephemeral             -> OR   (most restrictive: any true -> true)
	//   AllowExtraDNSLabels   -> AND  (most restrictive: any false -> false)
	//   ExpiresAt             -> min of non-nil values
	MappingResolutionUnion MappingResolution = "union"
)

// EntraGroupWildcard is a sentinel value that can be used in
// EntraDeviceAuthMapping.EntraGroupID to match any authenticated device in the
// configured tenant ("catch-all").
const EntraGroupWildcard = "*"

// EntraDeviceAuth is the per-account configuration for Entra/Intune device
// authentication. One row per account.
type EntraDeviceAuth struct {
	ID        string `gorm:"primaryKey"`
	AccountID string `gorm:"uniqueIndex"`

	// Entra configuration
	TenantID     string
	ClientID     string
	ClientSecret string `gorm:"column:client_secret"` // encrypt at rest via existing secret storage
	Issuer       string
	Audience     string

	// Behaviour flags
	Enabled                 bool
	RequireIntuneCompliant  bool
	AllowTenantOnlyFallback bool
	FallbackAutoGroups      []string `gorm:"serializer:json"`
	MappingResolution       MappingResolution

	// Optional continuous revalidation interval. 0 = join-only validation.
	RevalidationInterval time.Duration

	CreatedAt time.Time
	UpdatedAt time.Time `gorm:"autoUpdateTime:false"`
}

// TableName returns the gorm table name.
func (*EntraDeviceAuth) TableName() string { return "entra_device_auth" }

// ResolutionOrDefault returns MappingResolution, falling back to strict_priority
// when unset / unknown.
func (e *EntraDeviceAuth) ResolutionOrDefault() MappingResolution {
	switch e.MappingResolution {
	case MappingResolutionUnion:
		return MappingResolutionUnion
	default:
		return MappingResolutionStrictPriority
	}
}

// EventMeta returns activity-event metadata for this integration.
func (e *EntraDeviceAuth) EventMeta() map[string]any {
	return map[string]any{
		"tenant_id":          e.TenantID,
		"client_id":          e.ClientID,
		"enabled":            e.Enabled,
		"resolution_mode":    string(e.ResolutionOrDefault()),
		"require_compliance": e.RequireIntuneCompliant,
	}
}

// EntraDeviceAuthMapping is one admin-configured rule that associates an Entra
// security group (or wildcard) with a set of NetBird auto-groups plus the
// setup-key-like flags.
type EntraDeviceAuthMapping struct {
	ID            string `gorm:"primaryKey"`
	AccountID     string `gorm:"index"`
	IntegrationID string `gorm:"index"`

	Name         string
	EntraGroupID string `gorm:"index"` // Entra object ID or EntraGroupWildcard.

	AutoGroups          []string `gorm:"serializer:json"`
	Ephemeral           bool
	AllowExtraDNSLabels bool

	ExpiresAt *time.Time
	Revoked   bool
	Priority  int

	CreatedAt time.Time
	UpdatedAt time.Time `gorm:"autoUpdateTime:false"`
}

// TableName returns the gorm table name.
func (*EntraDeviceAuthMapping) TableName() string { return "entra_device_auth_mappings" }

// Copy returns a deep copy of the mapping.
func (m *EntraDeviceAuthMapping) Copy() *EntraDeviceAuthMapping {
	autoGroups := make([]string, len(m.AutoGroups))
	copy(autoGroups, m.AutoGroups)
	out := *m
	out.AutoGroups = autoGroups
	if m.ExpiresAt != nil {
		t := *m.ExpiresAt
		out.ExpiresAt = &t
	}
	return &out
}

// IsWildcard reports whether this mapping matches any device in the tenant.
func (m *EntraDeviceAuthMapping) IsWildcard() bool {
	g := strings.TrimSpace(m.EntraGroupID)
	return g == "" || g == EntraGroupWildcard
}

// IsExpired reports whether the mapping's expiry has passed.
func (m *EntraDeviceAuthMapping) IsExpired() bool {
	if m.ExpiresAt == nil || m.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().UTC().After(*m.ExpiresAt)
}

// IsEligible returns true if the mapping may participate in resolution. It is
// deliberately strict: revoked or expired mappings never "win" on priority.
func (m *EntraDeviceAuthMapping) IsEligible() bool {
	return !m.Revoked && !m.IsExpired()
}

// EventMeta returns activity-event metadata for this mapping.
func (m *EntraDeviceAuthMapping) EventMeta() map[string]any {
	return map[string]any{
		"mapping_id":     m.ID,
		"mapping_name":   m.Name,
		"entra_group_id": m.EntraGroupID,
		"priority":       m.Priority,
	}
}

// NewEntraDeviceAuth constructs a new integration with sane defaults.
func NewEntraDeviceAuth(accountID string) *EntraDeviceAuth {
	now := time.Now().UTC()
	return &EntraDeviceAuth{
		ID:                id(),
		AccountID:         accountID,
		Enabled:           true,
		MappingResolution: MappingResolutionStrictPriority,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
}

// NewEntraDeviceAuthMapping constructs a new mapping with a fresh ID.
func NewEntraDeviceAuthMapping(accountID, integrationID, name, entraGroupID string, autoGroups []string) *EntraDeviceAuthMapping {
	now := time.Now().UTC()
	copied := make([]string, len(autoGroups))
	copy(copied, autoGroups)
	return &EntraDeviceAuthMapping{
		ID:            id(),
		AccountID:     accountID,
		IntegrationID: integrationID,
		Name:          name,
		EntraGroupID:  entraGroupID,
		AutoGroups:    copied,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
}

func id() string { return xid.New().String() }
