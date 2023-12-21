package checks

import (
	"fmt"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

type PostureCheck struct {
	// ID of the policy rule
	ID string `gorm:"primaryKey"`

	// PolicyID is a reference to Policy that this object belongs
	PolicyID string `json:"-" gorm:"index"`

	NBVersionCheck NBVersionPostureCheck `gorm:"embedded;embeddedPrefix:nb_version_check_"`
	OSVersionCheck OSVersionPostureCheck `gorm:"embedded;embeddedPrefix:os_version_check_"`
}

type NBVersionPostureCheck struct {
	Enabled               bool
	MinimumVersionAllowed string
}

func (n *NBVersionPostureCheck) Check(peer nbpeer.Peer) error {
	if peer.Meta.WtVersion >= n.MinimumVersionAllowed {
		return nil
	}
	return fmt.Errorf("peer nb version is not supported")
}

type OSVersionPostureCheck struct {
	Enabled               bool
	MinimumVersionAllowed string
}

func (o *OSVersionPostureCheck) Check(peer nbpeer.Peer) error {
	if peer.Meta.WtVersion >= o.MinimumVersionAllowed {
		return nil
	}
	return fmt.Errorf("peer OS version is not supported")
}
