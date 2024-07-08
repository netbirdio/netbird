package posture

import (
	"context"
	"fmt"

	"github.com/hashicorp/go-version"
	log "github.com/sirupsen/logrus"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

type NBVersionCheck struct {
	MinVersion string
}

var _ Check = (*NBVersionCheck)(nil)

func (n *NBVersionCheck) Check(ctx context.Context, peer nbpeer.Peer) (bool, error) {
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

	log.WithContext(ctx).Debugf("peer %s NB version %s is older than minimum allowed version %s",
		peer.ID, peer.Meta.WtVersion, n.MinVersion)

	return false, nil
}

func (n *NBVersionCheck) Name() string {
	return NBVersionCheckName
}

func (n *NBVersionCheck) Validate() error {
	if n.MinVersion == "" {
		return fmt.Errorf("%s minimum version shouldn't be empty", n.Name())
	}
	if !isVersionValid(n.MinVersion) {
		return fmt.Errorf("%s version: %s is not valid", n.Name(), n.MinVersion)
	}
	return nil
}
