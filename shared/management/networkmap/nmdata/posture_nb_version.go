package nmdata

import (
	"strings"

	"github.com/hashicorp/go-version"
)

// NBVersionCheck is the slim twin of posture.NBVersionCheck.
type NBVersionCheck struct {
	MinVersion string
}

func (n *NBVersionCheck) check(peer *Peer) (bool, error) {
	return meetsMinVersion(n.MinVersion, peer.Meta.WtVersion)
}

func meetsMinVersion(minVer, peerVer string) (bool, error) {
	peerVer = sanitizeVersion(peerVer)
	minVer = sanitizeVersion(minVer)

	peerNBVer, err := version.NewVersion(peerVer)
	if err != nil {
		return false, err
	}

	constraints, err := version.NewConstraint(">= " + minVer)
	if err != nil {
		return false, err
	}

	return constraints.Check(peerNBVer), nil
}

func sanitizeVersion(v string) string {
	parts := strings.Split(v, "-")
	return parts[0]
}
