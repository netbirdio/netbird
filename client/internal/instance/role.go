package instance

import "fmt"

// Role decides which installation wins when two want the same machine-wide
// resource: the default route, catch-all DNS, an identical route.
type Role string

const (
	// RolePrimary behaves as a lone installation always has.
	RolePrimary Role = "primary"
	// RoleSecondary never takes the default route or system DNS and loses
	// identical routes.
	RoleSecondary Role = "secondary"
)

// secondaryInterfaceMetric is above any automatic metric Windows assigns, so
// the primary wins every route both installations have.
const secondaryInterfaceMetric = 1000

// IsSecondary reports whether the installation yields to the primary: no
// default route, no system DNS takeover, the losing interface metric.
func (i Instance) IsSecondary() bool {
	return i.role == RoleSecondary
}

// InterfaceMetric returns the metric to set on the overlay adapter, and false
// when the metric stays automatic, as it always has for a primary.
func (i Instance) InterfaceMetric() (uint32, bool) {
	if !i.IsSecondary() {
		return 0, false
	}
	return secondaryInterfaceMetric, true
}

// ParseRole parses a role given on the command line. Empty input is secondary.
// Anything unknown is secondary too, the more restrictive role, and is reported
// as an error so the caller can log it.
func ParseRole(s string) (Role, error) {
	switch Role(asciiLower(s)) {
	case RolePrimary:
		return RolePrimary, nil
	case RoleSecondary, "":
		return RoleSecondary, nil
	default:
		return RoleSecondary, fmt.Errorf("unknown installation role %q, using %s", s, RoleSecondary)
	}
}
