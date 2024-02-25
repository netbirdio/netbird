package posture

import (
	"github.com/hashicorp/go-version"
	log "github.com/sirupsen/logrus"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

type NBVersionCheck struct {
	MinVersion string
}

var _ Check = (*NBVersionCheck)(nil)

func (n *NBVersionCheck) Check(peer nbpeer.Peer) (bool, error) {
	peerNBVersion, err := version.NewVersion(peer.Meta.WtVersion)
	if err != nil {
		return false, err
	}

	constraints, err := version.NewConstraint(">= " + n.MinVersion)
	if err != nil {
		return false, err
	}

	if constraints.Check(peerNBVersion) {
		return true, nil
	}

	log.Debugf("peer %s NB version %s is older than minimum allowed version %s",
		peer.ID, peer.Meta.WtVersion, n.MinVersion)

	return false, nil
}

func (n *NBVersionCheck) Name() string {
	return NBVersionCheckName
}
