package posture

import (
	"fmt"
	"net/netip"

	"github.com/hashicorp/go-version"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

const (
	NBVersionCheckName        = "NBVersionCheck"
	OSVersionCheckName        = "OSVersionCheck"
	GeoLocationCheckName      = "GeoLocationCheck"
	PeerNetworkRangeCheckName = "PeerNetworkRangeCheck"

	CheckActionAllow string = "allow"
	CheckActionDeny  string = "deny"
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

// ChecksDefinition contains definition of actual check
type ChecksDefinition struct {
	NBVersionCheck        *NBVersionCheck        `json:",omitempty"`
	OSVersionCheck        *OSVersionCheck        `json:",omitempty"`
	GeoLocationCheck      *GeoLocationCheck      `json:",omitempty"`
	PeerNetworkRangeCheck *PeerNetworkRangeCheck `json:",omitempty"`
}

// Copy returns a copy of a checks definition.
func (cd ChecksDefinition) Copy() ChecksDefinition {
	var cdCopy ChecksDefinition
	if cd.NBVersionCheck != nil {
		cdCopy.NBVersionCheck = &NBVersionCheck{
			MinVersion: cd.NBVersionCheck.MinVersion,
		}
	}
	if cd.OSVersionCheck != nil {
		cdCopy.OSVersionCheck = &OSVersionCheck{}
		osCheck := cd.OSVersionCheck
		if osCheck.Android != nil {
			cdCopy.OSVersionCheck.Android = &MinVersionCheck{MinVersion: osCheck.Android.MinVersion}
		}
		if osCheck.Darwin != nil {
			cdCopy.OSVersionCheck.Darwin = &MinVersionCheck{MinVersion: osCheck.Darwin.MinVersion}
		}
		if osCheck.Ios != nil {
			cdCopy.OSVersionCheck.Ios = &MinVersionCheck{MinVersion: osCheck.Ios.MinVersion}
		}
		if osCheck.Linux != nil {
			cdCopy.OSVersionCheck.Linux = &MinKernelVersionCheck{MinKernelVersion: osCheck.Linux.MinKernelVersion}
		}
		if osCheck.Windows != nil {
			cdCopy.OSVersionCheck.Windows = &MinKernelVersionCheck{MinKernelVersion: osCheck.Windows.MinKernelVersion}
		}
	}
	if cd.GeoLocationCheck != nil {
		geoCheck := cd.GeoLocationCheck
		cdCopy.GeoLocationCheck = &GeoLocationCheck{
			Action:    geoCheck.Action,
			Locations: make([]Location, len(geoCheck.Locations)),
		}
		copy(cdCopy.GeoLocationCheck.Locations, geoCheck.Locations)
	}
	if cd.PeerNetworkRangeCheck != nil {
		peerNetRangeCheck := cd.PeerNetworkRangeCheck
		cdCopy.PeerNetworkRangeCheck = &PeerNetworkRangeCheck{
			Action: peerNetRangeCheck.Action,
			Ranges: make([]netip.Prefix, len(peerNetRangeCheck.Ranges)),
		}
		copy(cdCopy.PeerNetworkRangeCheck.Ranges, peerNetRangeCheck.Ranges)
	}
	return cdCopy
}

// TableName returns the name of the table for the Checks model in the database.
func (*Checks) TableName() string {
	return "posture_checks"
}

// Copy returns a copy of a posture checks.
func (pc *Checks) Copy() *Checks {
	checks := &Checks{
		ID:          pc.ID,
		Name:        pc.Name,
		Description: pc.Description,
		AccountID:   pc.AccountID,
		Checks:      pc.Checks.Copy(),
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
	if pc.Checks.PeerNetworkRangeCheck != nil {
		checks = append(checks, pc.Checks.PeerNetworkRangeCheck)
	}
	return checks
}

func (pc *Checks) Validate() error {
	if check := pc.Checks.NBVersionCheck; check != nil {
		if !isVersionValid(check.MinVersion) {
			return fmt.Errorf("%s version: %s is not valid", check.Name(), check.MinVersion)
		}
	}

	if osCheck := pc.Checks.OSVersionCheck; osCheck != nil {
		if osCheck.Android != nil {
			if !isVersionValid(osCheck.Android.MinVersion) {
				return fmt.Errorf("%s android version: %s is not valid", osCheck.Name(), osCheck.Android.MinVersion)
			}
		}

		if osCheck.Ios != nil {
			if !isVersionValid(osCheck.Ios.MinVersion) {
				return fmt.Errorf("%s ios version: %s is not valid", osCheck.Name(), osCheck.Ios.MinVersion)
			}
		}

		if osCheck.Darwin != nil {
			if !isVersionValid(osCheck.Darwin.MinVersion) {
				return fmt.Errorf("%s  darwin version: %s is not valid", osCheck.Name(), osCheck.Darwin.MinVersion)
			}
		}

		if osCheck.Linux != nil {
			if !isVersionValid(osCheck.Linux.MinKernelVersion) {
				return fmt.Errorf("%s  linux kernel version: %s is not valid", osCheck.Name(),
					osCheck.Linux.MinKernelVersion)
			}
		}

		if osCheck.Windows != nil {
			if !isVersionValid(osCheck.Windows.MinKernelVersion) {
				return fmt.Errorf("%s  windows kernel version: %s is not valid", osCheck.Name(),
					osCheck.Windows.MinKernelVersion)
			}
		}
	}

	return nil
}

func isVersionValid(ver string) bool {
	newVersion, err := version.NewVersion(ver)
	if err != nil {
		return false
	}

	if newVersion != nil {
		return true
	}

	return false
}
