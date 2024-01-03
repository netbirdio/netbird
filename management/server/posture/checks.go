package posture

import (
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

// Check represents an interface for performing a check on a peer.
type Check interface {
	Check(peer nbpeer.Peer) error
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

	// Checks is a list of objects that perform the actual checks
	Checks []Check `gorm:"serializer:json"`
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
		Checks:      make([]Check, len(pc.Checks)),
	}
	copy(checks.Checks, pc.Checks)
	return checks
}
