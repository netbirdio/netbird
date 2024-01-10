package posture

import (
	"fmt"

	"github.com/hashicorp/go-version"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

type NBVersionCheck struct {
	Enabled    bool
	MinVersion string
}

var _ Check = (*NBVersionCheck)(nil)

func (n *NBVersionCheck) Check(peer nbpeer.Peer) error {
	if !n.Enabled {
		return nil
	}

	peerNBVersion, err := version.NewVersion(peer.Meta.WtVersion)
	if err != nil {
		return err
	}

	constraints, err := version.NewConstraint(">= " + n.MinVersion)
	if err != nil {
		return err
	}

	if constraints.Check(peerNBVersion) {
		return nil
	}

	return fmt.Errorf("peer NB version %s is older than minimum allowed version %s",
		peer.Meta.UIVersion,
		n.MinVersion,
	)
}

func (n *NBVersionCheck) Name() string {
	return NBVersionCheckName
}
