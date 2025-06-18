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
	meetsMin, err := MeetsMinVersion(n.MinVersion, peer.Meta.WtVersion)
	if err != nil {
		return false, err
	}

	if meetsMin {
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

// MeetsMinVersion checks if the peer's version meets or exceeds the minimum required version
func MeetsMinVersion(minVer, peerVer string) (bool, error) {
	peerVer = sanitizeVersion(peerVer)
	minVer = sanitizeVersion(minVer)

	peerNBVersion, err := version.NewVersion(peerVer)
	if err != nil {
		return false, err
	}

	constraints, err := version.NewConstraint(">= " + minVer)
	if err != nil {
		return false, err
	}

	return constraints.Check(peerNBVersion), nil
}
