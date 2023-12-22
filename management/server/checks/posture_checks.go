package checks

import (
	"fmt"

	"github.com/hashicorp/go-version"

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
	peerNBVersion, err := version.NewVersion(peer.Meta.UIVersion)
	if err != nil {
		return err
	}

	constraints, err := version.NewConstraint(">= " + n.MinimumVersionAllowed)
	if err != nil {
		return err
	}

	if constraints.Check(peerNBVersion) {
		return nil
	}

	return fmt.Errorf("peer nb version is older than minimum allowed version %s", n.MinimumVersionAllowed)
}

type OSVersionPostureCheck struct {
	Enabled               bool
	MinimumVersionAllowed string

	// TODO: add OS context to prevent using the same version on different OS types
}

func (o *OSVersionPostureCheck) Check(peer nbpeer.Peer) error {
	peerNBVersion, err := version.NewVersion(peer.Meta.UIVersion)
	if err != nil {
		return err
	}

	constraints, err := version.NewConstraint(">= " + o.MinimumVersionAllowed)
	if err != nil {
		return err
	}

	if constraints.Check(peerNBVersion) {
		return nil
	}

	return fmt.Errorf("peer OS version is not supported")
}
