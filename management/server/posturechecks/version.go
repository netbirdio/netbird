package posturechecks

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

var _ PostureChecker = (*NBVersionCheck)(nil)

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

	return fmt.Errorf("peer nb version is older than minimum allowed version %s", n.MinVersion)
}
