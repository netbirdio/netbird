package posture

import (
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

const (
	NBVersionCheckName   = "NBVersionCheck"
	OSVersionCheckName   = "OSVersionCheck"
	GeoLocationCheckName = "GeoLocationCheck"
)

// Check represents an interface for performing a check on a peer.
type Check interface {
	Check(peer nbpeer.Peer) (bool, error)
	Name() string
}

type Checks struct {
	// ID of the posture checks
	ID string `gorm:"primaryKey"`

	// Name of the posture checks
	Name string

	// Description of the posture checks visible in the UI
	Description string

	// AccountID is a reference to the Account that this object belongs
	AccountID string `json:"-" gorm:"index"`

	// Checks is a set of objects that perform the actual checks
	Checks ChecksDefinition `gorm:"serializer:json"`
}

type ChecksDefinition struct {
	NBVersionCheck   *NBVersionCheck   `json:",omitempty"`
	OSVersionCheck   *OSVersionCheck   `json:",omitempty"`
	GeoLocationCheck *GeoLocationCheck `json:",omitempty"`
}

// TableName returns the name of the table for the Checks model in the database.
func (*Checks) TableName() string {
	return "posture_checks"
}

// Copy returns a copy of a policy rule.
func (pc *Checks) Copy() *Checks {
	checks := &Checks{
		ID:          pc.ID,
		Name:        pc.Name,
		Description: pc.Description,
		AccountID:   pc.AccountID,
		Checks:      pc.Checks, // TODO: copy by value
	}
	return checks
}

// EventMeta returns activity event meta-related to this posture checks.
func (pc *Checks) EventMeta() map[string]any {
	return map[string]any{"name": pc.Name}
}

// GetChecks returns list of all initialized checks definitions
func (pc *Checks) GetChecks() []Check {
	var checks []Check
	if pc.Checks.NBVersionCheck != nil {
		checks = append(checks, pc.Checks.NBVersionCheck)
	}
	if pc.Checks.OSVersionCheck != nil {
		checks = append(checks, pc.Checks.OSVersionCheck)
	}
	if pc.Checks.GeoLocationCheck != nil {
		checks = append(checks, pc.Checks.GeoLocationCheck)
	}
	return checks
}
