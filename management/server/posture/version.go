package posture

import (
	"fmt"

	"github.com/hashicorp/go-version"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

type NBVersionCheck struct {
	Enabled    bool
	MinVersion string
	MaxVersion string
}

var _ Check = (*NBVersionCheck)(nil)

func (n *NBVersionCheck) Check(peer nbpeer.Peer) error {
	peerNBVersion, err := version.NewVersion(peer.Meta.UIVersion)
	if err != nil {
		return err
	}

	minMaxVersionRange := ">= " + n.MinVersion + "," + "<= " + n.MaxVersion
	constraints, err := version.NewConstraint(minMaxVersionRange)
	if err != nil {
		return err
	}

	if constraints.Check(peerNBVersion) {
		return nil
	}

	return fmt.Errorf("peer NB version %s is not within the allowed version range %s to %s",
		peer.Meta.UIVersion,
		n.MinVersion,
		n.MaxVersion,
	)
}
