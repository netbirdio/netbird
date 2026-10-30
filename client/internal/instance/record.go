package instance

import "errors"

// recordsKey holds one subkey per named installation, written by the installer
// and readable by every user. The daemon never needs it to connect.
const recordsKey = `SOFTWARE\NetBird\Installations`

// ErrNoRecord is returned when an installation has no record.
var ErrNoRecord = errors.New("no installation record")

// Record is what the installer wrote about a named installation. Its values are
// untrusted input: Label goes through Instance.WithLabel, Role through
// ParseRole, and the UI validates Color before drawing it.
type Record struct {
	Name       Name
	Label      string
	Color      string
	Role       string
	InstallDir string
	Version    string
}

// Apply returns inst with the record's label and role. An invalid role falls
// back to secondary and is reported, so the caller can log it.
func (r Record) Apply(inst Instance) (Instance, error) {
	role, err := ParseRole(r.Role)
	return inst.WithLabel(r.Label).WithRole(role), err
}
