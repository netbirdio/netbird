package posture

import (
	"encoding/json"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

const (
	NBVersionCheckName = "NBVersionCheck"
)

// Check represents an interface for performing a check on a peer.
type Check interface {
	Check(peer nbpeer.Peer) error
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

// EventMeta returns activity event meta-related to this posture checks.
func (pc *Checks) EventMeta() map[string]any {
	return map[string]any{"name": pc.Name}
}

// MarshalJSON returns the JSON encoding of the Checks object.
// The Checks object is marshaled as a map[string]json.RawMessage,
// where the key is the name of the check and the value is the JSON
// representation of the Check object.
func (pc *Checks) MarshalJSON() ([]byte, error) {
	type Alias Checks
	return json.Marshal(&struct {
		Checks map[string]json.RawMessage
		*Alias
	}{
		Checks: pc.marshalChecks(),
		Alias:  (*Alias)(pc),
	})
}

// UnmarshalJSON unmarshal the JSON data into the Checks object.
func (pc *Checks) UnmarshalJSON(data []byte) error {
	type Alias Checks
	aux := &struct {
		Checks map[string]json.RawMessage
		*Alias
	}{
		Alias: (*Alias)(pc),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	return pc.unmarshalChecks(aux.Checks)
}

func (pc *Checks) marshalChecks() map[string]json.RawMessage {
	result := make(map[string]json.RawMessage)
	for _, check := range pc.Checks {
		data, err := json.Marshal(check)
		if err != nil {
			return result
		}
		result[check.Name()] = data
	}
	return result
}

func (pc *Checks) unmarshalChecks(rawChecks map[string]json.RawMessage) error {
	pc.Checks = make([]Check, 0, len(rawChecks))

	for name, rawCheck := range rawChecks {
		switch name {
		case NBVersionCheckName:
			check := &NBVersionCheck{}
			if err := json.Unmarshal(rawCheck, check); err != nil {
				return err
			}
			pc.Checks = append(pc.Checks, check)
		}
	}
	return nil
}
