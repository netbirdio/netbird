package posture

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/go-version"
	log "github.com/sirupsen/logrus"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

type NBVersionCheck struct {
	MinVersion string
}

var _ Check = (*NBVersionCheck)(nil)

// sanitizeVersion removes anything after the pre-release tag (e.g., "-dev", "-alpha", etc.)
func sanitizeVersion(version string) string {
	parts := strings.Split(version, "-")
	return parts[0]
}

func (n *NBVersionCheck) Check(ctx context.Context, peer nbpeer.Peer) (bool, error) {
	peerVersion := sanitizeVersion(peer.Meta.WtVersion)
	minVersion := sanitizeVersion(n.MinVersion)

	peerNBVersion, err := version.NewVersion(peerVersion)
	if err != nil {
		return false, err
	}

	constraints, err := version.NewConstraint(">= " + minVersion)
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
